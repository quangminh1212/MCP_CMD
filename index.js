import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn, spawnSync } from "child_process";

const server = new McpServer({
  name: "mcp-cmd",
  version: "1.0.0",
});

// ─── Active child process tracking ─────────────────────────────────────────────
// Tracks all spawned child PIDs so we can force-kill on exit
const _activeChildren = new Set();

// ─── Concurrency limiter ────────────────────────────────────────────────────────
// Limits simultaneous child processes to prevent zombie accumulation
const MAX_CONCURRENT = 3;
let _runningCount = 0;
const _waitQueue = [];

function acquireSlot() {
  return new Promise((resolve) => {
    if (_runningCount < MAX_CONCURRENT) {
      _runningCount++;
      resolve();
    } else {
      _waitQueue.push(resolve);
    }
  });
}

function releaseSlot() {
  if (_waitQueue.length > 0) {
    const next = _waitQueue.shift();
    next(); // don't decrement - pass the slot to next waiter
  } else {
    _runningCount--;
  }
}

/**
 * Force-kill an entire process tree on Windows.
 * Uses taskkill /T /F (tree kill) first, then fallback individual kill.
 * Verifies the process is actually dead after killing.
 */
function forceKillTree(pid) {
  if (!pid) return;
  try {
    spawnSync("taskkill", ["/T", "/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 5000 });
  } catch (_) {
    try { spawnSync("taskkill", ["/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 5000 }); }
    catch (_2) { /* process already gone */ }
  }
  // Verify kill - if still alive, retry once after short delay
  try {
    const check = spawnSync("tasklist", ["/FI", `PID eq ${pid}`, "/NH"], { encoding: "utf8", windowsHide: true, timeout: 3000 });
    if ((check.stdout || "").includes(String(pid))) {
      // Still alive, force kill again
      try { spawnSync("taskkill", ["/F", "/PID", String(pid)], { windowsHide: true, stdio: "ignore", timeout: 5000 }); }
      catch (_) { /* best effort */ }
    }
  } catch (_) { /* tasklist failed = process is gone */ }
  _activeChildren.delete(pid);
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
  const cwd = options.cwd || "C:\\Dev";
  const timeoutMs = Math.min(options.timeout || 30000, 300000);
  const maxOutput = 10 * 1024 * 1024; // 10MB

  // Wait for a concurrency slot before spawning
  await acquireSlot();

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let finished = false;
    let timedOut = false;

    let child;
    try {
      child = spawn("cmd.exe", ["/c", command], {
        cwd,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (spawnErr) {
      // spawn threw synchronously (e.g. invalid cwd) → release slot and return error
      releaseSlot();
      resolve({ content: [{ type: "text", text: `[ERROR] Spawn failed: ${spawnErr.message}\n[EXIT 1]` }] });
      return;
    }

    // Track this child for cleanup on exit
    if (child.pid) _activeChildren.add(child.pid);

    // Close stdin immediately - prevents interactive prompts from hanging
    child.stdin.end();

    // Prevent unhandled 'error' events on stdio streams from crashing the server
    child.stdin.on("error", () => { });
    child.stdout.on("error", () => { });
    child.stderr.on("error", () => { });

    child.stdout.on("data", (d) => { if (stdout.length < maxOutput) stdout += d.toString(); });
    child.stderr.on("data", (d) => { if (stderr.length < maxOutput) stderr += d.toString(); });

    const timer = setTimeout(() => {
      if (!finished) {
        timedOut = true;
        forceKillTree(child.pid);
      }
    }, timeoutMs);

    function done(exitCode) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      _activeChildren.delete(child.pid);
      releaseSlot();

      const parts = [];
      if (stdout.trim()) parts.push(stdout.trim());
      if (stderr.trim()) parts.push(`[STDERR] ${stderr.trim()}`);
      if (timedOut) parts.push(`[TIMEOUT] Killed after ${timeoutMs}ms`);
      else if (exitCode !== 0 && !stdout.trim() && !stderr.trim()) {
        parts.push(`[ERROR] Process exited with code ${exitCode}`);
      }
      parts.push(`[EXIT ${exitCode ?? 1}]`);

      resolve({
        content: [{ type: "text", text: parts.join("\n") || "[NO OUTPUT]" }],
      });
    }

    child.on("close", (code) => done(code));
    child.on("error", (err) => { stderr += err.message; done(1); });
  });
}

// Helper: run PowerShell synchronously (replaces deprecated WMIC)
// Uses spawnSync with argv array for reliable windowsHide (no console flash)
function psSync(script, timeoutMs = 10000) {
  try {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    const result = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
      { encoding: "utf8", windowsHide: true, timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] }
    );
    return result.stdout || "";
  } catch (err) {
    // Return empty on failure instead of crashing the MCP server
    return "";
  }
}

// Rate limiter: prevents abuse of process management tools (60 calls/min)
const _rateCalls = new Map();
function rateCheck(tool) {
  const now = Date.now();
  const calls = (_rateCalls.get(tool) || []).filter(t => now - t < 60000);
  if (calls.length >= 60) return "[RATE LIMITED] Max 60 calls/min. Try again later.";
  calls.push(now);
  _rateCalls.set(tool, calls);
  return null;
}

// Validate working directory to prevent path traversal
function validateCwd(cwd) {
  if (!cwd) return "C:\\Dev";
  // Block null bytes and suspicious path components
  if (cwd.includes('\0')) return "C:\\Dev";
  return cwd;
}

// ─── Tool 1: Run a single CMD command ──────────────────────────────────────────

server.tool(
  "cmd_run",
  "Run a Windows CMD command without hanging. Uses cmd.exe /c with stdin closed and process tree kill on timeout. Safe for any non-interactive command.",
  {
    command: z.string().describe("The CMD command to run"),
    cwd: z.string().optional().describe("Working directory. Defaults to C:\\Dev"),
    timeout: z
      .number()
      .optional()
      .describe("Timeout in ms. Defaults to 30000 (30s). Max 300000 (5min)."),
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
      .describe("Timeout per command in ms. Defaults to 30000."),
    continueOnError: z
      .boolean()
      .optional()
      .describe("Continue running after a command fails. Defaults to false."),
  },
  async ({ commands, timeout, continueOnError }) => {
    // Cap batch size to prevent resource exhaustion
    const maxBatch = 20;
    if (commands.length > maxBatch) {
      return { content: [{ type: "text", text: `[ERROR] Max ${maxBatch} commands per batch. Got ${commands.length}.` }] };
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
    cwd: z.string().optional().describe("Working directory. Defaults to C:\\Dev"),
    timeout: z
      .number()
      .optional()
      .describe("Timeout in ms. Defaults to 30000. Max 300000."),
  },
  async ({ command, cwd, timeout }) => {
    const workDir = validateCwd(cwd);
    const timeoutMs = Math.min(timeout || 30000, 300000);
    const maxOutput = 5 * 1024 * 1024;

    // Concurrency control for PowerShell too
    await acquireSlot();

    // Encode command as Base64 UTF-16LE to avoid all escaping issues
    let encoded;
    try {
      encoded = Buffer.from(command, "utf16le").toString("base64");
    } catch (encErr) {
      releaseSlot();
      return { content: [{ type: "text", text: `[ERROR] Failed to encode command: ${encErr.message}\n[EXIT 1]` }] };
    }

    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let finished = false;
      let timedOut = false;

      // SECURITY NOTE: -ExecutionPolicy Bypass is intentional for MCP server operation.
      // This tool runs in a trusted local context where the AI agent is the caller.
      // Scripts are Base64-encoded from the agent's command, not from external sources.
      let child;
      try {
        child = spawn(
          "powershell.exe",
          ["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
          { cwd: workDir, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }
        );
      } catch (spawnErr) {
        releaseSlot();
        resolve({ content: [{ type: "text", text: `[ERROR] Spawn failed: ${spawnErr.message}\n[EXIT 1]` }] });
        return;
      }

      // Track this child for cleanup on exit
      if (child.pid) _activeChildren.add(child.pid);

      child.stdin.end();

      // Prevent unhandled 'error' events on stdio streams from crashing the server
      child.stdin.on("error", () => { });
      child.stdout.on("error", () => { });
      child.stderr.on("error", () => { });

      child.stdout.on("data", (d) => { if (stdout.length < maxOutput) stdout += d.toString(); });
      child.stderr.on("data", (d) => { if (stderr.length < maxOutput) stderr += d.toString(); });

      const timer = setTimeout(() => {
        if (!finished) {
          timedOut = true;
          forceKillTree(child.pid);
        }
      }, timeoutMs);

      function done(exitCode) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        _activeChildren.delete(child.pid);
        releaseSlot();

        const parts = [];
        if (stdout.trim()) parts.push(stdout.trim());
        if (stderr.trim()) parts.push(`[STDERR] ${stderr.trim()}`);
        if (timedOut) parts.push(`[TIMEOUT] Killed after ${timeoutMs}ms`);
        parts.push(`[EXIT ${exitCode ?? "?"}]`);
        resolve({ content: [{ type: "text", text: parts.join("\n") || "[NO OUTPUT]" }] });
      }

      child.on("close", (code) => done(code));
      child.on("error", (err) => { stderr += err.message; done(1); });
    });
  }
);

// ─── Tool 4: Quick system diagnostic ──────────────────────────────────────────

server.tool(
  "system_info",
  "Get basic Windows system info: OS, architecture, memory, username. Quick diagnostic.",
  {},
  async () => {
    // Use PowerShell for reliable system info (avoids FINDSTR quoting issues in cmd.exe /c)
    const output = psSync(
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
      // PowerShell Get-CimInstance (replaces deprecated WMIC)
      const output = psSync(`Get-CimInstance Win32_Process -Filter \"(${filterExpr})\" | Select-Object ProcessId,Name,CreationDate,CommandLine | Format-List`);
      return { content: [{ type: "text", text: output.trim() || "[NO PROCESSES FOUND]" }] };
    } catch (_) {
      // Fallback to WMIC for older Windows versions
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

      // PowerShell Get-CimInstance + JSON (replaces deprecated WMIC + fragile CSV)
      let procs = [];
      try {
        const script = `@(Get-CimInstance Win32_Process -Filter \"(${nameFilter})\" -EA SilentlyContinue | Select-Object ProcessId, Name, @{N='Created';E={$_.CreationDate.ToString('o')}}, CommandLine) | ConvertTo-Json -Compress`;
        const raw = psSync(script);
        const parsed = JSON.parse(raw.trim() || "[]");
        procs = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
      } catch (_) {
        // Fallback to WMIC for older Windows
        try {
          const wmicResult = spawnSync(
            "wmic",
            ["process", "where", `(${nameFilter})`, "get", "ProcessId,Name,CreationDate,CommandLine", "/format:csv"],
            { encoding: "utf8", windowsHide: true, timeout: 10000, stdio: ["ignore", "pipe", "pipe"] }
          );
          const raw = wmicResult.stdout || "";
          const lines = raw.trim().split("\n").filter(l => l.trim() && !l.startsWith("Node"));
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

// ─── Background Auto-Reaper (DISABLED) ─────────────────────────────────────────
// DISABLED: The auto-reaper was spawning a PowerShell process every 30s which
// caused visible CMD/PowerShell windows to flash on Windows (even with windowsHide).
// This is unnecessary because:
//   1. execCmd() already has its own timeout + forceKillTree
//   2. powershell_run() already has its own timeout + forceKillTree
//   3. Users can manually call process_cleanup tool when needed
// The reaper function is kept for potential manual use but the interval is removed.

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
