import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn, spawnSync } from "child_process";
import { resolve, normalize, join } from "path";
import { existsSync } from "fs";

const server = new McpServer({
  name: "mcp-cmd",
  version: "1.1.0",
});

const DEFAULT_CWD = resolve(process.cwd());
const COMMON_CHILD_ENV = {
  GIT_TERMINAL_PROMPT: "0",
  GIT_EDITOR: "true",
  GIT_SSH_COMMAND: "ssh -o BatchMode=yes",
};
const POWERSHELL_BASE_ARGS = [
  "-NonInteractive",
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-OutputFormat",
  "Text",
];

// ─── Security Configuration ────────────────────────────────────────────────────
// Inspired by MladenSU/cli-mcp-server security features
const SECURITY_CONFIG = {
  maxCommandLength: 8192,         // Max command string length (bytes)
  commandTimeout: 15000,          // Default timeout (ms) - 15s balanced for most tasks
  maxTimeout: 30000,              // Max allowed timeout (ms) - 30s for chained commands
  maxOutputSize: 10 * 1024 * 1024, // 10MB output cap
  maxBatchSize: 20,               // Max commands per batch
  rateLimit: 60,                  // Max calls/min for process management tools
  rateLimitWindow: 60000,         // Rate limit window (ms)
  // File-destructive ops are scoped to the detected project root (via .git, package.json, etc.)
};

// System-level commands: ALWAYS blocked (cannot be scoped to a directory)
const ALWAYS_BLOCKED_COMMANDS = [
  /^format\s/i, /^diskpart/i, /^reg\s+(delete|add)/i,
  /^net\s+(user|localgroup)\s/i,
  /^(sc|net)\s+(stop|delete|config)\s/i,
  /^shutdown\s/i, /^sfc\s/i, /^bcdedit/i,
  /^powershell.*-enc/i,
];

// File-destructive commands: allowed ONLY within cwd that is a project under allowedBaseDir
const FILE_DESTRUCTIVE_COMMANDS = [
  /^(rd|rmdir)\s/i, /^del\s/i, /Remove-Item/i,
];

// Combined list for general detection
const DANGEROUS_COMMANDS = [...ALWAYS_BLOCKED_COMMANDS, ...FILE_DESTRUCTIVE_COMMANDS];

// Shell operators that could indicate injection attempts
const SHELL_OPERATORS = ['&&', '||', '|', '>', '>>', '<', '<<', ';', '`'];

/**
 * Detect potentially dangerous patterns in a command string.
 * Returns { dangerous: bool, operators: string[], warnings: string[] }
 */
function analyzeCommand(command) {
  const warnings = [];
  const detectedOps = [];

  // Check command length
  if (command.length > SECURITY_CONFIG.maxCommandLength) {
    warnings.push(`[SECURITY] Command exceeds max length (${command.length}/${SECURITY_CONFIG.maxCommandLength})`);
  }

  // Detect shell operators
  for (const op of SHELL_OPERATORS) {
    if (command.includes(op)) detectedOps.push(op);
  }
  if (detectedOps.length > 0) {
    warnings.push(`[SECURITY] Shell operators detected: ${detectedOps.join(', ')}`);
  }

  // Check for dangerous commands (split into categories)
  const isAlwaysBlocked = ALWAYS_BLOCKED_COMMANDS.some(p => p.test(command));
  const isFileDestructive = FILE_DESTRUCTIVE_COMMANDS.some(p => p.test(command));
  const isDangerous = isAlwaysBlocked || isFileDestructive;
  if (isAlwaysBlocked) {
    warnings.push(`[SECURITY] System-level destructive command BLOCKED`);
  } else if (isFileDestructive) {
    warnings.push(`[SECURITY] File-destructive command detected (cwd-restricted)`);
  }

  // Detect null bytes (path traversal indicator)
  if (command.includes('\0')) {
    warnings.push(`[SECURITY] Null byte detected in command`);
  }

  return { dangerous: isDangerous, alwaysBlocked: isAlwaysBlocked, fileDestructive: isFileDestructive, operators: detectedOps, warnings };
}

// ─── Active child process tracking ─────────────────────────────────────────────
// Tracks all spawned child PIDs so we can force-kill on exit
const _activeChildren = new Set();

/**
 * Safely destroy all stdio streams of a child process.
 * This is critical to unblock the "close" event which waits for ALL streams to close.
 * On Windows, grandchild processes can inherit pipes, keeping them open indefinitely.
 */
function destroyStreams(child) {
  if (!child) return;
  try { child.stdin && !child.stdin.destroyed && child.stdin.destroy(); } catch (_) { }
  try { child.stdout && !child.stdout.destroyed && child.stdout.destroy(); } catch (_) { }
  try { child.stderr && !child.stderr.destroyed && child.stderr.destroy(); } catch (_) { }
}

// ─── Concurrency limiter (FIFO queue) ───────────────────────────────────────────
// Max 3 simultaneous child processes. Extra work waits in a FIFO queue.
const MAX_CONCURRENT = 3;
const IDLE_TIMEOUT_MS = 20000; // 20s no-output → auto-kill (balanced for slow tasks like git, PS)
const ABSOLUTE_MAX_LIFETIME_MS = 60000; // 60s absolute max → kill regardless of output
const PROCESS_CLOSE_GRACE_MS = 3000;
const PROCESS_DEADLINE_GRACE_MS = 10000;

// Track running processes with metadata for idle cleanup.
// Each entry: { pid, startedAt, lastOutputAt, kill: () => void }
const _runningProcs = new Map();
const _spawnQueue = [];
let _activeSlots = 0;

function registerProc(pid, killFn, childRef) {
  const now = Date.now();
  _runningProcs.set(pid, { pid, startedAt: now, lastOutputAt: now, kill: killFn, child: childRef });
}

function touchProc(pid) {
  const entry = _runningProcs.get(pid);
  if (entry) entry.lastOutputAt = Date.now();
}

function unregisterProc(pid) {
  _runningProcs.delete(pid);
}

function drainSpawnQueue() {
  while (_activeSlots < MAX_CONCURRENT && _spawnQueue.length > 0) {
    const next = _spawnQueue.shift();
    next?.grant();
  }
}

function acquireProcessSlot(timeoutMs) {
  return new Promise((resolve) => {
    let finished = false;
    let waitTimer;

    const grant = () => {
      if (finished) return;
      finished = true;
      clearTimeout(waitTimer);
      _activeSlots += 1;
      let released = false;

      resolve(() => {
        if (released) return;
        released = true;
        _activeSlots = Math.max(0, _activeSlots - 1);
        drainSpawnQueue();
      });
    };

    if (_activeSlots < MAX_CONCURRENT) {
      grant();
      return;
    }

    const entry = { grant };
    _spawnQueue.push(entry);

    waitTimer = setTimeout(() => {
      if (finished) return;
      finished = true;
      const index = _spawnQueue.indexOf(entry);
      if (index >= 0) _spawnQueue.splice(index, 1);
      resolve(null);
    }, timeoutMs);
    waitTimer.unref && waitTimer.unref();
  });
}

// ─── Idle + Lifetime watchdog ───────────────────────────────────────────────────
// Every 3s, check for:
//   1. Idle processes (no output for IDLE_TIMEOUT_MS) → kill
//   2. Long-running processes (alive > ABSOLUTE_MAX_LIFETIME_MS) → kill regardless
const _idleWatchdog = setInterval(() => {
  const now = Date.now();
  for (const [pid, entry] of _runningProcs) {
    const idleMs = now - entry.lastOutputAt;
    const lifetimeMs = now - entry.startedAt;
    if (idleMs > IDLE_TIMEOUT_MS || lifetimeMs > ABSOLUTE_MAX_LIFETIME_MS) {
      const reason = lifetimeMs > ABSOLUTE_MAX_LIFETIME_MS ? 'lifetime exceeded' : 'idle timeout';
      process.stderr.write(`[MCP_CMD] Watchdog: killing PID ${pid} (${reason}, idle=${Math.round(idleMs / 1000)}s, lifetime=${Math.round(lifetimeMs / 1000)}s)\n`);
      try { entry.kill(); } catch (_) { /* best effort */ }
      // Destroy streams to unblock "close" event after kill
      if (entry.child) destroyStreams(entry.child);
      _runningProcs.delete(pid);
    }
  }
}, 3000); // Check every 3s for faster response
_idleWatchdog.unref(); // Don't prevent process exit

/**
 * Force-kill an entire process tree on Windows.
 * Uses taskkill /T /F (tree kill) first, then fallback individual kill.
 * Verifies the process is actually dead after killing.
 */
function forceKillTree(pid) {
  if (!pid) return;
  try {
    spawnSync("taskkill", ["/T", "/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 3000 });
  } catch (_) {
    try { spawnSync("taskkill", ["/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 2000 }); }
    catch (_2) { /* process already gone */ }
  }
  _activeChildren.delete(pid);
}

function buildPowerShellScript(script) {
  return `$ProgressPreference = 'SilentlyContinue'; ${script}`;
}

function encodePowerShellScript(script) {
  return Buffer.from(buildPowerShellScript(script), "utf16le").toString("base64");
}

async function runSpawnedProcess(options) {
  const {
    fileName,
    args,
    cwd = DEFAULT_CWD,
    timeoutMs = SECURITY_CONFIG.commandTimeout,
    maxOutput = SECURITY_CONFIG.maxOutputSize,
    env = {},
  } = options;

  const startedAt = Date.now();
  const releaseSlot = await acquireProcessSlot(timeoutMs);
  const queueWaitMs = Date.now() - startedAt;

  if (!releaseSlot) {
    return {
      stdout: "",
      stderr: "",
      timedOut: true,
      queueTimedOut: true,
      queueWaitMs,
      runtimeTimeoutMs: 0,
      exitCode: 1,
      spawnError: null,
    };
  }

  const runtimeTimeoutMs = Math.max(100, timeoutMs - queueWaitMs);

  return new Promise((resolve) => {
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let finished = false;
    let timedOut = false;
    let child;
    let timer;
    let deadlineTimer;

    function done(exitCode, spawnError = null) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      clearTimeout(deadlineTimer);

      if (child?.pid) {
        _activeChildren.delete(child.pid);
        unregisterProc(child.pid);
      }

      destroyStreams(child);
      releaseSlot();

      resolve({
        stdout: Buffer.concat(stdoutChunks).toString().trim(),
        stderr: Buffer.concat(stderrChunks).toString().trim(),
        timedOut,
        queueTimedOut: false,
        queueWaitMs,
        runtimeTimeoutMs,
        exitCode: exitCode ?? 1,
        spawnError,
      });
    }

    try {
      child = spawn(fileName, args, {
        cwd,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          ...COMMON_CHILD_ENV,
          ...env,
        },
      });
    } catch (spawnErr) {
      done(1, spawnErr);
      return;
    }

    if (child.pid) {
      _activeChildren.add(child.pid);
      registerProc(child.pid, () => forceKillTree(child.pid), child);
    }

    child.stdin.end();

    child.stdin.on("error", () => { });
    child.stdout.on("error", () => { });
    child.stderr.on("error", () => { });

    child.stdout.on("data", (chunk) => {
      if (stdoutLen < maxOutput) {
        stdoutChunks.push(chunk);
        stdoutLen += chunk.length;
      }
      if (child.pid) touchProc(child.pid);
    });

    child.stderr.on("data", (chunk) => {
      if (stderrLen < maxOutput) {
        stderrChunks.push(chunk);
        stderrLen += chunk.length;
      }
      if (child.pid) touchProc(child.pid);
    });

    timer = setTimeout(() => {
      if (finished) return;
      timedOut = true;
      forceKillTree(child.pid);
      destroyStreams(child);
      const closeTimer = setTimeout(() => done(null), PROCESS_CLOSE_GRACE_MS);
      closeTimer.unref && closeTimer.unref();
    }, runtimeTimeoutMs);

    deadlineTimer = setTimeout(() => {
      if (finished) return;
      timedOut = true;
      forceKillTree(child.pid);
      destroyStreams(child);
      done(null);
    }, runtimeTimeoutMs + PROCESS_DEADLINE_GRACE_MS);
    deadlineTimer.unref && deadlineTimer.unref();

    child.on("exit", (code) => {
      const exitTimer = setTimeout(() => {
        if (!finished) {
          destroyStreams(child);
          done(code);
        }
      }, 2000);
      exitTimer.unref && exitTimer.unref();
    });

    child.on("close", (code) => done(code));
    child.on("error", (err) => {
      stderrChunks.push(Buffer.from(err.message));
      stderrLen += Buffer.byteLength(err.message);
      done(1, err);
    });
  });
}

function buildToolResultText(result, options = {}) {
  const { timeoutMs, securityPrefix = "" } = options;
  const parts = [];

  if (securityPrefix) parts.push(securityPrefix.trim());
  if (result.stdout) parts.push(result.stdout);
  if (result.stderr) parts.push(`[STDERR] ${result.stderr}`);
  if (result.queueTimedOut) {
    parts.push(`[TIMEOUT] Queue wait exceeded ${timeoutMs}ms before process start`);
  } else if (result.timedOut && result.queueWaitMs >= 100) {
    parts.push(`[TIMEOUT] Killed after ${timeoutMs}ms total (${result.runtimeTimeoutMs}ms runtime after ${result.queueWaitMs}ms queue wait)`);
  } else if (result.timedOut) {
    parts.push(`[TIMEOUT] Killed after ${timeoutMs}ms`);
  }
  else if (result.exitCode !== 0 && !result.stdout && !result.stderr) {
    parts.push(`[ERROR] Process exited with code ${result.exitCode}`);
  }
  parts.push(`[EXIT ${result.exitCode}]`);

  return parts.join("\n") || "[NO OUTPUT]";
}

function decodePowerShellClixml(text) {
  if (!text || !text.includes("CLIXML")) return text;

  const decodedSegments = [...text.matchAll(/<S S="[^"]+">(.*?)<\/S>/g)]
    .map(([, segment]) => segment
      .replace(/_x000D__x000A_/g, "\n")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&"))
    .join("")
    .trim();

  return decodedSegments.replace(/\n{3,}/g, "\n\n");
}

/**
 * Anti-hang CMD execution using spawn (not exec) for full control.
 * - Spawns cmd.exe /c <command> directly via spawn for proper PID tracking
 * - Closes stdin immediately to prevent interactive prompts from blocking
 * - Kills the entire process tree on timeout (taskkill /T /F /PID)
 * - Caps output to prevent memory issues
 * - Uses spawn instead of exec to avoid exec's unreliable timeout on Windows
 */
async function execCmd(command, options = {}) {
  const cwd = options.cwd || DEFAULT_CWD;
  const timeoutMs = Math.max(100, Math.min(options.timeout || SECURITY_CONFIG.commandTimeout, SECURITY_CONFIG.maxTimeout));

  const analysis = analyzeCommand(command);
  const securityPrefix = analysis.warnings.length > 0 ? analysis.warnings.join('\n') + '\n' : '';

  if (analysis.alwaysBlocked) {
    return { content: [{ type: "text", text: `${securityPrefix}[BLOCKED] System-level destructive command rejected.\n[EXIT 1]` }] };
  }

  if (analysis.fileDestructive && !isFileOpSafe(command, cwd)) {
    return { content: [{ type: "text", text: `${securityPrefix}[BLOCKED] File operation targets outside project boundary (${cwd}).\nFile deletion is only allowed within a recognized project directory (detected via .git, package.json, etc.).\n[EXIT 1]` }] };
  }

  if (command.length > SECURITY_CONFIG.maxCommandLength) {
    return { content: [{ type: "text", text: `[SECURITY] Command rejected: exceeds max length (${command.length}/${SECURITY_CONFIG.maxCommandLength})\n[EXIT 1]` }] };
  }

  const result = await runSpawnedProcess({
    fileName: "cmd.exe",
    args: ["/c", command],
    cwd,
    timeoutMs,
    maxOutput: SECURITY_CONFIG.maxOutputSize,
  });

  return {
    content: [{ type: "text", text: buildToolResultText(result, { timeoutMs, securityPrefix }) }],
  };
}

// Helper: run PowerShell with GUARANTEED timeout (async, anti-hang)
// Uses the same process lifecycle manager as the main tools to avoid deadlocks.
async function psSafe(script, timeoutMs = 10000) {
  let encoded;
  try {
    encoded = encodePowerShellScript(script);
  } catch (_) {
    return "";
  }

  const result = await runSpawnedProcess({
    fileName: "powershell.exe",
    args: [...POWERSHELL_BASE_ARGS, "-EncodedCommand", encoded],
    timeoutMs,
    maxOutput: SECURITY_CONFIG.maxOutputSize / 2,
  });

  return result.stdout || "";
}

// Rate limiter: prevents abuse of process management tools (60 calls/min)
const _rateCalls = new Map();
function rateCheck(tool) {
  const now = Date.now();
  const calls = (_rateCalls.get(tool) || []).filter(t => now - t < SECURITY_CONFIG.rateLimitWindow);
  if (calls.length >= SECURITY_CONFIG.rateLimit) return `[RATE LIMITED] Max ${SECURITY_CONFIG.rateLimit} calls/min. Try again later.`;
  calls.push(now);
  _rateCalls.set(tool, calls);
  return null;
}

// Validate working directory to prevent path traversal
// Enhanced with symlink resolution and traversal prevention (inspired by cli-mcp-server)
function validateCwd(cwd) {
  if (!cwd) return DEFAULT_CWD;
  // Block null bytes
  if (cwd.includes('\0')) return DEFAULT_CWD;
  try {
    // Normalize and resolve to absolute path to prevent traversal via ../ or ./ 
    const resolved = resolve(normalize(cwd));
    // Block UNC paths that could access network resources
    if (resolved.startsWith('\\\\')) return DEFAULT_CWD;
    // Block paths with suspicious double-dot sequences post-resolution
    if (resolved.includes('..')) return DEFAULT_CWD;
    return resolved;
  } catch (_) {
    return DEFAULT_CWD;
  }
}

// Project root markers: if any of these exist in a directory, it's a project root
const PROJECT_MARKERS = [
  '.git', 'package.json', 'Cargo.toml', 'go.mod', 'pyproject.toml',
  'setup.py', 'pom.xml', 'build.gradle', '.sln', '.csproj',
  'Makefile', 'CMakeLists.txt', 'composer.json', 'Gemfile',
];

/**
 * Walk up from `startDir` to find the nearest project root.
 * Returns the project root path, or null if no project marker is found.
 * Stops at the filesystem root to prevent infinite loop.
 */
function findProjectRoot(startDir) {
  let dir = resolve(normalize(startDir));
  const root = resolve(dir.split('\\')[0] + '\\'); // e.g. "C:\\"
  while (true) {
    for (const marker of PROJECT_MARKERS) {
      try {
        if (existsSync(join(dir, marker))) return dir;
      } catch (_) { /* permission denied etc. */ }
    }
    const parent = resolve(dir, '..');
    if (parent === dir || dir === root) break; // reached filesystem root
    dir = parent;
  }
  return null;
}

/**
 * Check if a file-destructive command is safe to run within the given cwd.
 * Rules:
 *   1. cwd must be inside a recognized project (detected via project markers)
 *   2. All target paths in the command must resolve within the project root
 */
function isFileOpSafe(command, cwd) {
  const resolvedCwd = resolve(normalize(cwd));

  // Find the project root from cwd
  const projectRoot = findProjectRoot(resolvedCwd);
  if (!projectRoot) return false; // Not inside any recognized project → block

  const projectRootLower = projectRoot.toLowerCase();
  const resolvedCwdLower = resolvedCwd.toLowerCase();

  // cwd must be within the project root
  if (!resolvedCwdLower.startsWith(projectRootLower + '\\') && resolvedCwdLower !== projectRootLower) return false;

  // Extract arguments after the command keyword (del, rd, rmdir, Remove-Item)
  const match = command.match(/^(?:del|rd|rmdir|Remove-Item)\s+(.*)$/i);
  if (!match) return true; // No args = no target

  const argsStr = match[1];
  // Tokenize: split by spaces but respect quotes
  const tokens = argsStr.match(/(?:[^\s"]+|"[^"]*")+/g) || [];

  for (const token of tokens) {
    // Skip CMD switches (/s, /q, /f) and PS switches (-Recurse, -Force)
    if (/^\/[a-zA-Z]/.test(token) || token.startsWith('-')) continue;
    // Skip wildcards without path component
    const cleaned = token.replace(/"/g, '');
    if (!cleaned || cleaned === '*' || cleaned === '.' || cleaned === '*.*') continue;

    // Resolve the path relative to cwd
    const resolvedTarget = resolve(resolvedCwdLower, cleaned).toLowerCase();

    // Target must stay within the project root (not escape to parent dirs)
    if (!resolvedTarget.startsWith(projectRootLower + '\\') && resolvedTarget !== projectRootLower) {
      return false;
    }
  }

  return true;
}

// ─── Tool 1: Run a single CMD command ──────────────────────────────────────────

server.tool(
  "cmd_run",
  "Run a Windows CMD command without hanging. Uses cmd.exe /c with stdin closed and process tree kill on timeout. Safe for any non-interactive command.",
  {
    command: z.string().describe("The CMD command to run"),
    cwd: z.string().optional().describe("Working directory. Defaults to the server start directory."),
    timeout: z
      .number()
      .optional()
      .describe("Timeout in ms. Defaults to 10000. Max 30000."),
  },
  async ({ command, cwd, timeout }) => {
    return execCmd(command, { cwd: validateCwd(cwd), timeout });
  }
);

// ─── Tool 2: Run multiple CMD commands sequentially ────────────────────────────

server.tool(
  "cmd_batch",
  "Run multiple CMD commands one by one. Each command runs in its own cmd.exe /c process (no hanging). Stops on first failure unless continueOnError is true.",
  {
    commands: z
      .array(
        z.object({
          command: z.string().describe("CMD command to run"),
          cwd: z.string().optional().describe("Working directory for this command"),
        })
      )
      .describe("Commands to run sequentially"),
    timeout: z
      .number()
      .optional()
      .describe("Timeout per command in ms. Defaults to 10000. Max 30000."),
    continueOnError: z
      .boolean()
      .optional()
      .describe("Continue running after a command fails. Defaults to false."),
  },
  async ({ commands, timeout, continueOnError }) => {
    // Cap batch size to prevent resource exhaustion
    if (commands.length > SECURITY_CONFIG.maxBatchSize) {
      return { content: [{ type: "text", text: `[ERROR] Max ${SECURITY_CONFIG.maxBatchSize} commands per batch. Got ${commands.length}.` }] };
    }

    const results = [];

    for (let i = 0; i < commands.length; i++) {
      const { command, cwd } = commands[i];
      const result = await execCmd(command, { cwd: validateCwd(cwd), timeout });
      const text = result.content[0].text;
      const failed = !text.includes("[EXIT 0]");

      results.push(`[${i + 1}/${commands.length}] ${command}\n${text}`);

      if (failed && !continueOnError) {
        results.push(`\n[STOPPED] at command ${i + 1}`);
        break;
      }
    }

    return {
      content: [{ type: "text", text: results.join("\n\n") }],
    };
  }
);

// ─── Tool 3: Run a PowerShell command ──────────────────────────────────────────

server.tool(
  "powershell_run",
  "Run a PowerShell command without hanging. Uses -NonInteractive -NoProfile flags to prevent prompts and speed up startup. Command is Base64-encoded to avoid escaping issues.",
  {
    command: z.string().describe("PowerShell command or script block to run"),
    cwd: z.string().optional().describe("Working directory. Defaults to the server start directory."),
    timeout: z
      .number()
      .optional()
      .describe("Timeout in ms. Defaults to 10000. Max 30000."),
  },
  async ({ command, cwd, timeout }) => {
    const workDir = validateCwd(cwd);
    const timeoutMs = Math.max(100, Math.min(timeout || SECURITY_CONFIG.commandTimeout, SECURITY_CONFIG.maxTimeout));

    let encoded;
    try {
      encoded = encodePowerShellScript(command);
    } catch (encErr) {
      return { content: [{ type: "text", text: `[ERROR] Failed to encode command: ${encErr.message}\n[EXIT 1]` }] };
    }

    const result = await runSpawnedProcess({
      fileName: "powershell.exe",
      args: [...POWERSHELL_BASE_ARGS, "-EncodedCommand", encoded],
      cwd: workDir,
      timeoutMs,
      maxOutput: SECURITY_CONFIG.maxOutputSize / 2,
    });

    result.stderr = decodePowerShellClixml(result.stderr);
    return { content: [{ type: "text", text: buildToolResultText(result, { timeoutMs }) }] };
  }
);

// ─── Tool 4: Quick system diagnostic ──────────────────────────────────────────

server.tool(
  "system_info",
  "Get basic Windows system info: OS, architecture, memory, username. Quick diagnostic.",
  {},
  async () => {
    // Use PowerShell for reliable system info (avoids FINDSTR quoting issues in cmd.exe /c)
    const output = await psSafe(
      `$os = Get-CimInstance Win32_OperatingSystem; ` +
      `"OS: $($os.Caption) $($os.Version)"; ` +
      `"ARCH: $env:PROCESSOR_ARCHITECTURE"; ` +
      `"USER: $env:USERNAME"; ` +
      `"SHELL: $env:COMSPEC"; ` +
      `"Total Memory: $([math]::Round($os.TotalVisibleMemorySize/1MB, 1)) GB"; ` +
      `"Free Memory: $([math]::Round($os.FreePhysicalMemory/1MB, 1)) GB"`,
      15000
    );
    return { content: [{ type: "text", text: output.trim() || "[ERROR] Could not retrieve system info" }] };
  }
);

// ─── Tool 5: List running processes (diagnostic) ───────────────────────────────

server.tool(
  "process_list",
  "List running cmd.exe, powershell.exe, node.exe, and conhost.exe processes. Useful for diagnosing hanging processes before cleanup.",
  {
    filter: z
      .string()
      .optional()
      .describe("Filter by process name (e.g. 'cmd', 'node'). Defaults to all relevant processes."),
  },
  async ({ filter }) => {
    const rl = rateCheck("process_list");
    if (rl) return { content: [{ type: "text", text: rl }] };

    // Sanitize filter to prevent injection (allow only alphanumeric, dot, underscore)
    const sanitized = filter ? filter.replace(/[^a-zA-Z0-9._]/g, "") : "";
    // Escape WMI LIKE wildcards (% and _) in user input, then wrap in LIKE pattern
    const escaped = sanitized.replace(/%/g, "[%]").replace(/_/g, "[_]");
    const filterExpr = escaped
      ? `Name LIKE '%${escaped}%'`
      : "Name='cmd.exe' OR Name='conhost.exe' OR Name='powershell.exe' OR Name='node.exe'";

    try {
      // PowerShell Get-CimInstance (replaces deprecated WMIC) - uses async psSafe to prevent hang
      const output = await psSafe(`Get-CimInstance Win32_Process -Filter \"(${filterExpr})\" | Select-Object ProcessId,Name,CreationDate,CommandLine | Format-List`, 15000);
      if (output.trim()) {
        return { content: [{ type: "text", text: output.trim() }] };
      }
      // Empty output = fallback to WMIC for older Windows versions
      return execCmd(`wmic process where "(${filterExpr})" get ProcessId,Name,CreationDate,CommandLine /format:list`, { timeout: 10000 });
    } catch (_) {
      return execCmd(`wmic process where "(${filterExpr})" get ProcessId,Name,CreationDate,CommandLine /format:list`, { timeout: 10000 });
    }
  }
);

// ─── Tool 6: Cleanup hanging/orphaned processes ────────────────────────────────

// Strategy: Kill ALL old cmd.exe EXCEPT MCP infrastructure processes
// MCP servers are long-running by design and must never be killed
const MCP_PATTERNS = [
  /npx\s.*mcp/i, /npx\s.*context7/i, /npx\s.*deepwiki/i,
  /npx\s.*playwright/i, /npx\s.*mem0/i, /npx\s.*sequential/i,
  /npx\s.*snyk/i, /npx\s.*pulumi/i, /npx\s.*filesystem/i,
  /npx\s.*markdown-rules/i, /npx\s.*mcp-remote/i,
  /npx\s.*@modelcontextprotocol/i, /npx\s.*duckduckgo/i,
  /mcp-server/i, /context7-mcp/i, /mcp-remote/i,
  /markdown-rules-mcp/i, /playwright-mcp/i, /mem0-mcp/i,
  /pulumi-mcp-server/i, /snyk\s+mcp/i,
  /next\s+dev/i, /vite\s+dev/i, // dev servers (long-running)
  /npm\s+run\s+dev/i, /npm-cli\.js.*\s+run\s+dev/i, // npm dev servers
  /run-driver/i, // playwright-go driver
  /MCP_CMD[\\\/]index\.js/i, // self-protection: don't kill MCP_CMD server
  /launcher\.(cs|exe)/i, /wrapper\.js/i, // MCP_CMD helpers
  /mcp_server_\w+/i, // Python-based MCP servers (time, fetch, duckduckgo, git, etc.)
  /uv\s+.*run\s+/i, // uv-launched Python MCP servers
  /mem0/i, // mem0 memory MCP server
];

function isMcpInfrastructure(cmdLine, name) {
  if (name?.toLowerCase() === "conhost.exe") return true; // system-managed
  if (!cmdLine || cmdLine.trim() === "") return true; // unknown = safe
  // Bare/interactive cmd.exe without /c or -c flag = VS Code terminal or user shell
  // cmd.exe with /c or -c is executing a command and may be a zombie if hung
  if (name?.toLowerCase() === "cmd.exe" && !/[\/-]c\s/i.test(cmdLine)) return true;
  return MCP_PATTERNS.some(p => p.test(cmdLine));
}

server.tool(
  "process_cleanup",
  "Find and kill hanging/orphaned cmd.exe and conhost.exe processes. Targets windowless CMD processes older than the specified age (default: 30 seconds). Use this to clean up stale processes left by Antigravity's run_command tool.",
  {
    maxAgeSeconds: z
      .number()
      .optional()
      .describe("Kill processes older than this many seconds. Defaults to 30."),
    dryRun: z
      .boolean()
      .optional()
      .describe("If true, only list processes without killing them. Defaults to false."),
    includeNode: z
      .boolean()
      .optional()
      .describe("Also clean up orphaned node.exe processes. Defaults to false."),
  },
  async ({ maxAgeSeconds, dryRun, includeNode }) => {
    const ageLimitSec = maxAgeSeconds ?? 30;
    const isDry = dryRun ?? false;

    const rl = rateCheck("process_cleanup");
    if (rl) return { content: [{ type: "text", text: rl }] };

    try {
      const targets = ["cmd.exe", "conhost.exe"];
      if (includeNode) targets.push("node.exe");
      const nameFilter = targets.map(n => `Name='${n}'`).join(" OR ");

      // PowerShell Get-CimInstance + JSON (uses async psSafe to prevent hang)
      let procs = [];
      try {
        const script = `@(Get-CimInstance Win32_Process -Filter \"(${nameFilter})\" -EA SilentlyContinue | Select-Object ProcessId, Name, @{N='Created';E={$_.CreationDate.ToString('o')}}, CommandLine) | ConvertTo-Json -Compress`;
        const raw = await psSafe(script, 15000);
        const parsed = JSON.parse(raw.trim() || "[]");
        procs = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
      } catch (_) {
        // Fallback to WMIC for older Windows (also with timeout via execCmd)
        try {
          const wmicResult = await execCmd(
            `wmic process where "(${nameFilter})" get ProcessId,Name,CreationDate,CommandLine /format:csv`,
            { timeout: 10000 }
          );
          const raw = wmicResult.content[0].text || "";
          const lines = raw.trim().split("\n").filter(l => l.trim() && !l.startsWith("Node") && !l.startsWith("["));
          for (const line of lines) {
            const m = line.trim().match(/^([^,]*),(.*),(\d{14}\.\d+\+\d+),([^,]+),(\d+)\s*$/);
            if (!m) continue;
            const [, , cmd, dateStr, n, p] = m;
            const dm = dateStr.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
            if (!dm) continue;
            procs.push({ ProcessId: parseInt(p), Name: n, Created: new Date(dm[1], dm[2] - 1, dm[3], dm[4], dm[5], dm[6]).toISOString(), CommandLine: cmd });
          }
        } catch (_2) { /* both PowerShell and WMIC failed */ }
      }

      const now = Date.now();
      const killed = [], skipped = [], safe = [];
      const myPid = process.pid;

      for (const proc of procs) {
        const pidNum = proc.ProcessId;
        const name = proc.Name || "";
        const cmdLine = proc.CommandLine || "";

        if (!pidNum || pidNum === myPid) continue;

        if (isMcpInfrastructure(cmdLine, name)) {
          safe.push(`🛡️ PID ${pidNum} (${name}) - MCP/SYSTEM`);
          continue;
        }

        const created = new Date(proc.Created);
        const ageMs = now - created.getTime();
        const ageSec = Math.round(ageMs / 1000);
        const ageLabel = ageSec >= 60 ? `${Math.round(ageSec / 60)}m${ageSec % 60}s` : `${ageSec}s`;
        const cmdShort = cmdLine ? cmdLine.substring(0, 60) : "(no cmdline)";

        if (ageSec < ageLimitSec) {
          skipped.push(`⏭ PID ${pidNum} (${name}) - ${ageLabel} old [${cmdShort}]`);
          continue;
        }

        if (isDry) {
          killed.push(`🔍 PID ${pidNum} (${name}) - ${ageLabel} old - WOULD KILL [${cmdShort}]`);
        } else {
          try {
            forceKillTree(pidNum);
            killed.push(`💀 PID ${pidNum} (${name}) - ${ageLabel} old - KILLED [${cmdShort}]`);
          } catch (_) {
            killed.push(`⚠️ PID ${pidNum} (${name}) - ${ageLabel} old - FAILED [${cmdShort}]`);
          }
        }
      }

      const parts = [];
      parts.push(`[${isDry ? "DRY RUN" : "CLEANUP"}] Age limit: ${ageLimitSec}s`);
      if (killed.length) parts.push(killed.join("\n"));
      else parts.push("✅ No hanging processes found.");
      if (safe.length) parts.push(`\n[SAFE ${safe.length} processes]`);
      if (skipped.length) parts.push(`[SKIPPED ${skipped.length} recent processes]`);

      return { content: [{ type: "text", text: parts.join("\n") }] };
    } catch (err) {
      return { content: [{ type: "text", text: `[ERROR] ${err.message}` }] };
    }
  }
);

// ─── Tool 7: Show security rules (inspired by cli-mcp-server) ─────────────────

server.tool(
  "show_security_rules",
  "Display current security configuration, restrictions, and runtime limits. Shows command length limits, timeout values, concurrency settings, dangerous command patterns, and MCP infrastructure protection rules.",
  {},
  async () => {
    const rules = [
      `Security Configuration`,
      `==================`,
      ``,
      `Runtime Limits:`,
      `  Max Command Length: ${SECURITY_CONFIG.maxCommandLength} bytes`,
      `  Default Timeout: ${SECURITY_CONFIG.commandTimeout}ms`,
      `  Max Timeout: ${SECURITY_CONFIG.maxTimeout}ms`,
      `  Max Output Size: ${(SECURITY_CONFIG.maxOutputSize / 1024 / 1024).toFixed(0)}MB`,
      `  Max Batch Size: ${SECURITY_CONFIG.maxBatchSize} commands`,
      `  Rate Limit: ${SECURITY_CONFIG.rateLimit} calls/min (process tools)`,
      ``,
      `Concurrency:`,
      `  Max Concurrent Processes: ${MAX_CONCURRENT}`,
      `  Idle Timeout: ${IDLE_TIMEOUT_MS}ms`,
      `  Absolute Max Lifetime: ${ABSOLUTE_MAX_LIFETIME_MS}ms`,
      `  Queue Depth: ${_spawnQueue.length}`,
      `  Active Slots: ${_activeSlots}`,
      `  Active Processes: ${_runningProcs.size}`,
      `  Tracked Children: ${_activeChildren.size}`,
      ``,
      `Zombie Reaper:`,
      `  Scan Interval: ${ZOMBIE_SCAN_INTERVAL_MS}ms`,
      `  Age Limit: ${ZOMBIE_AGE_LIMIT_SEC}s`,
      `  Status: ENABLED`,
      ``,
      `Security Features:`,
      `  ✅ Path traversal prevention (resolve + normalize + UNC block)`,
      `  ✅ Null byte injection detection`,
      `  ✅ Shell operator detection (${SHELL_OPERATORS.join(', ')})`,
      `  ✅ Dangerous command detection (${DANGEROUS_COMMANDS.length} patterns)`,
      `  ✅ Command length enforcement`,
      `  ✅ Process tree kill on timeout (taskkill /T /F)`,
      `  ✅ Stdin closed to prevent interactive prompts`,
      `  ✅ MCP infrastructure process protection (${MCP_PATTERNS.length} patterns)`,
      `  ✅ Rate limiting on process management tools`,
      `  ✅ Idle watchdog auto-kill`,
      `  ✅ Absolute lifetime enforcement (${ABSOLUTE_MAX_LIFETIME_MS}ms max)`,
      `  ✅ Background zombie reaper (every ${ZOMBIE_SCAN_INTERVAL_MS / 1000}s)`,
      `  ✅ FIFO concurrency queue`,
      `  ✅ Per-request timeout includes queue wait`,
      ``,
      `Shell Operators Monitored:`,
      `  ${SHELL_OPERATORS.join('  ')}`,
      `  (Operators are allowed but generate security warnings in output)`,
      ``,
      `Dangerous Command Enforcement:`,
      `  ALWAYS BLOCKED (system-level):`,
      `    format, diskpart, reg delete/add, net user/localgroup,`,
      `    sc/net stop/delete, shutdown, sfc, bcdedit, powershell -enc`,
      `  PROJECT-SCOPED (file operations - only within detected project root):`,
      `    rd/rmdir, del, Remove-Item`,
      `  Project markers: ${PROJECT_MARKERS.join(', ')}`,
      `  ✅ System commands are hard-blocked (cannot be bypassed)`,
      `  ✅ File ops require cwd inside a recognized project (auto-detected)`,
      `  ✅ File operation targets must resolve within project root (no escape)`,
    ];
    return { content: [{ type: "text", text: rules.join("\n") }] };
  }
);

// ─── Background Zombie Reaper ──────────────────────────────────────────────────
// Periodically scan for orphaned cmd.exe processes and kill them.
// Uses cmd.exe "wmic" (no PowerShell flash) to check for old hanging cmd.exe
// processes that are NOT MCP infrastructure.
const ZOMBIE_SCAN_INTERVAL_MS = 30000; // 30s scan interval
const ZOMBIE_AGE_LIMIT_SEC = 30; // Kill cmd.exe processes older than 30s

async function zombieReaper() {
  try {
    // Use wmic via cmd.exe (no window flash via spawn windowsHide:true)
    const child = spawn('cmd.exe', ['/c',
      'wmic process where "Name=\'cmd.exe\'" get ProcessId,CreationDate,CommandLine /format:csv'
    ], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.end();

    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk.toString(); });

    // Safety timeout for wmic itself
    const wmicTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { }
    }, 8000);
    wmicTimer.unref && wmicTimer.unref();

    await new Promise((resolve) => {
      child.on('close', resolve);
      child.on('error', resolve);
    });
    clearTimeout(wmicTimer);

    const now = Date.now();
    const myPid = process.pid;
    const lines = output.split('\n').filter(l => l.trim() && !l.startsWith('Node'));
    let killedCount = 0;

    // Phase 1: Parse all cmd.exe processes
    const allProcs = [];
    for (const line of lines) {
      // CSV format: Node,CommandLine,CreationDate,ProcessId
      const parts = line.trim().split(',');
      if (parts.length < 4) continue;

      // Reconstruct CommandLine (may contain commas)
      const pidStr = parts[parts.length - 1].trim();
      const dateStr = parts[parts.length - 2].trim();
      const cmdLine = parts.slice(1, parts.length - 2).join(',').trim();

      const pidNum = parseInt(pidStr);
      if (!pidNum || isNaN(pidNum) || pidNum === myPid) continue;

      // Parse WMI date (yyyymmddHHMMSS.ffffff+UUU)
      const dm = dateStr.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
      if (!dm) continue;
      const created = new Date(dm[1], dm[2] - 1, dm[3], dm[4], dm[5], dm[6]);
      const ageSec = Math.round((now - created.getTime()) / 1000);

      allProcs.push({ pidNum, cmdLine, created, ageSec });
    }

    // Phase 2: Kill non-MCP zombie processes (older than age limit)
    for (const proc of allProcs) {
      if (proc.ageSec < ZOMBIE_AGE_LIMIT_SEC) continue;
      if (isMcpInfrastructure(proc.cmdLine, 'cmd.exe')) continue;

      process.stderr.write(`[MCP_CMD] Zombie reaper: killing PID ${proc.pidNum} (age=${proc.ageSec}s, cmd=${proc.cmdLine.substring(0, 60)})\n`);
      forceKillTree(proc.pidNum);
      proc._killed = true;
      killedCount++;
    }

    // Phase 3: Kill DUPLICATE MCP instances (zombie MCP processes from old Antigravity sessions)
    // When Antigravity restarts, old MCP server processes become zombies but are protected
    // by isMcpInfrastructure(). Detect duplicates: same CommandLine → keep only newest.
    const cmdGroups = new Map();
    for (const proc of allProcs) {
      if (proc._killed) continue;
      const key = proc.cmdLine.toLowerCase().trim();
      if (!key) continue;
      if (!cmdGroups.has(key)) cmdGroups.set(key, []);
      cmdGroups.get(key).push(proc);
    }

    for (const [, group] of cmdGroups) {
      if (group.length <= 1) continue; // No duplicates
      // Sort by creation time descending (newest first)
      group.sort((a, b) => b.created.getTime() - a.created.getTime());
      // Kill all but the newest
      for (let i = 1; i < group.length; i++) {
        const old = group[i];
        process.stderr.write(`[MCP_CMD] Zombie reaper: killing DUPLICATE PID ${old.pidNum} (age=${old.ageSec}s, kept PID ${group[0].pidNum}, cmd=${old.cmdLine.substring(0, 60)})\n`);
        forceKillTree(old.pidNum);
        killedCount++;
      }
    }

    if (killedCount > 0) {
      process.stderr.write(`[MCP_CMD] Zombie reaper: killed ${killedCount} orphaned process(es)\n`);
    }
  } catch (_) {
    // Silently ignore reaper errors - it's a best-effort cleanup
  }
}

// Start zombie reaper with initial delay of 15s, then every 30s
const _zombieReaperDelay = setTimeout(() => {
  zombieReaper(); // Initial scan
  const _zombieReaperInterval = setInterval(zombieReaper, ZOMBIE_SCAN_INTERVAL_MS);
  _zombieReaperInterval.unref();
}, 15000);
_zombieReaperDelay.unref();

// ─── Process Exit Cleanup ──────────────────────────────────────────────────────
// When MCP server exits, kill ALL tracked active children to prevent orphans
function cleanupOnExit() {
  for (const pid of _activeChildren) {
    try { spawnSync("taskkill", ["/T", "/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 3000 }); }
    catch (_) { /* best effort */ }
  }
  _activeChildren.clear();
}
process.on("exit", cleanupOnExit);
process.on("SIGINT", () => { cleanupOnExit(); process.exit(0); });
process.on("SIGTERM", () => { cleanupOnExit(); process.exit(0); });

// Graceful error handling - prevent MCP server crashes
process.on("unhandledRejection", (err) => {
  process.stderr.write(`[MCP_CMD] Unhandled rejection: ${err?.message || err}\n`);
});
process.on("uncaughtException", (err) => {
  process.stderr.write(`[MCP_CMD] Uncaught exception: ${err?.message || err}\n`);
});

// Start server
try {
  const transport = new StdioServerTransport();
  await server.connect(transport);
} catch (err) {
  process.stderr.write(`[MCP_CMD] Failed to start: ${err.message}\n`);
  process.exit(1);
}
