import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec, spawn, execSync } from "child_process";

const server = new McpServer({
  name: "mcp-cmd",
  version: "1.0.0",
});

/**
 * Anti-hang CMD execution.
 * - Uses child_process.exec with cmd.exe shell for correct quote handling
 * - Closes stdin immediately to prevent interactive prompts from blocking
 * - Kills the entire process tree on timeout (taskkill /T /F /PID)
 * - Caps output buffer to prevent memory issues
 */
function execCmd(command, options = {}) {
  const cwd = options.cwd || "C:\\Dev";
  const timeoutMs = Math.min(options.timeout || 30000, 300000);
  const maxBuffer = 10 * 1024 * 1024; // 10MB

  return new Promise((resolve) => {
    const child = exec(command, {
      cwd,
      timeout: timeoutMs,
      encoding: "utf8",
      shell: "cmd.exe",
      windowsHide: true,
      maxBuffer,
    }, (error, stdout, stderr) => {
      const parts = [];
      if (stdout && stdout.trim()) parts.push(stdout.trim());
      if (stderr && stderr.trim()) parts.push(`[STDERR] ${stderr.trim()}`);
      if (error && error.killed) parts.push(`[TIMEOUT] Killed after ${timeoutMs}ms`);
      if (error && !error.killed && !stdout && !stderr) parts.push(`[ERROR] ${error.message}`);

      const exitCode = error ? (error.code ?? 1) : 0;
      parts.push(`[EXIT ${exitCode}]`);

      resolve({
        content: [{ type: "text", text: parts.join("\n") || "[NO OUTPUT]" }],
      });
    });

    // Close stdin immediately - prevents interactive prompts from hanging
    child.stdin.end();

    // Extra safety: kill process tree on timeout (exec's built-in timeout
    // only kills the child, not grandchildren)
    const treeKillTimer = setTimeout(() => {
      try {
        execSync(`taskkill /T /F /PID ${child.pid}`, {
          windowsHide: true,
          stdio: "ignore",
        });
      } catch (_) { }
    }, timeoutMs + 500); // slightly after exec's own timeout

    child.on("close", () => clearTimeout(treeKillTimer));
  });
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
    return execCmd(command, { cwd, timeout });
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
    const results = [];

    for (let i = 0; i < commands.length; i++) {
      const { command, cwd } = commands[i];
      const result = await execCmd(command, { cwd, timeout });
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
    const workDir = cwd || "C:\\Dev";
    const timeoutMs = Math.min(timeout || 30000, 300000);
    const maxOutput = 5 * 1024 * 1024;

    // Encode command as Base64 UTF-16LE to avoid all escaping issues
    const encoded = Buffer.from(command, "utf16le").toString("base64");

    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let finished = false;
      let timedOut = false;

      const child = spawn(
        "powershell.exe",
        ["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        { cwd: workDir, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }
      );

      child.stdin.end();

      child.stdout.on("data", (d) => { if (stdout.length < maxOutput) stdout += d.toString(); });
      child.stderr.on("data", (d) => { if (stderr.length < maxOutput) stderr += d.toString(); });

      const timer = setTimeout(() => {
        if (!finished) {
          timedOut = true;
          try { execSync(`taskkill /T /F /PID ${child.pid}`, { windowsHide: true, stdio: "ignore" }); }
          catch (_) { child.kill("SIGKILL"); }
        }
      }, timeoutMs);

      function done(exitCode) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
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
    return execCmd(
      'echo OS: %OS% & echo ARCH: %PROCESSOR_ARCHITECTURE% & echo USER: %USERNAME% & echo SHELL: %COMSPEC% & systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Total Physical Memory" /C:"Available Physical Memory"',
      { timeout: 15000 }
    );
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
    // Sanitize filter to prevent WMIC injection (allow only alphanumeric, dot, underscore)
    const sanitized = filter ? filter.replace(/[^a-zA-Z0-9._]/g, "") : "";
    const names = sanitized
      ? `Name LIKE '%${sanitized}%'`
      : "Name='cmd.exe' OR Name='conhost.exe' OR Name='powershell.exe' OR Name='node.exe'";
    return execCmd(
      `wmic process where "(${names})" get ProcessId,Name,CreationDate,CommandLine /format:list`,
      { timeout: 10000 }
    );
  }
);

// ─── Tool 6: Cleanup hanging/orphaned processes ────────────────────────────────

// Only kill processes matching these HANGING patterns (inverted logic = safer)
// cmd.exe /c or /d are non-interactive and will exit on their own → NEVER kill
// Only target: bare cmd.exe (interactive shell) or Antigravity's broken -c format
function isHangingProcess(cmdLine, name) {
  if (name?.toLowerCase() === "conhost.exe") return false; // system-managed
  if (!cmdLine || cmdLine.trim() === "") return false; // no info, skip

  const cl = cmdLine.trim();

  // Bare interactive shell: "C:\WINDOWS\System32\cmd.exe" with no args
  if (/^("?[A-Z]:\\.*\\cmd\.exe"?\s*)$/i.test(cl)) return true;

  // Antigravity's run_command format: cmd.exe -c "..." (note: -c not /c)
  if (/cmd\.exe\s+-c\s/i.test(cl)) return true;

  return false;
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

    try {
      const targets = ["cmd.exe", "conhost.exe"];
      if (includeNode) targets.push("node.exe");

      const nameFilter = targets.map(n => `Name='${n}'`).join(" OR ");
      const raw = execSync(
        `wmic process where "(${nameFilter})" get ProcessId,Name,CreationDate,CommandLine /format:csv`,
        { encoding: "utf8", windowsHide: true, timeout: 10000 }
      );

      const lines = raw.trim().split("\n").filter(l => l.trim() && !l.startsWith("Node"));
      const now = Date.now();
      const killed = [];
      const skipped = [];
      const safe = [];
      const myPid = process.pid;

      for (const line of lines) {
        // CSV: Node,CommandLine,CreationDate,Name,ProcessId
        // CommandLine may contain commas, so parse fixed fields from the end
        const m = line.trim().match(/^([^,]*),(.*),(\d{14}\.\d+\+\d+),([^,]+),(\d+)\s*$/);
        if (!m) continue;

        const [, , cmdLine, creationDate, name, pid] = m;
        const pidNum = parseInt(pid);

        if (isNaN(pidNum) || pidNum === myPid) continue;

        // Only target processes matching HANGING patterns
        if (!isHangingProcess(cmdLine, name)) {
          safe.push(`🛡️ PID ${pidNum} (${name}) - SAFE`);
          continue;
        }

        // Parse WMIC date: 20260224220000.000000+420
        const match = creationDate.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
        if (!match) continue;

        const created = new Date(
          parseInt(match[1]), parseInt(match[2]) - 1, parseInt(match[3]),
          parseInt(match[4]), parseInt(match[5]), parseInt(match[6])
        );
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
            execSync(`taskkill /T /F /PID ${pidNum}`, { windowsHide: true, stdio: "ignore" });
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
      if (safe.length) parts.push(`\n[PROTECTED ${safe.length} MCP/system processes]`);
      if (skipped.length) parts.push(`[SKIPPED ${skipped.length} recent processes]`);

      return { content: [{ type: "text", text: parts.join("\n") }] };
    } catch (err) {
      return { content: [{ type: "text", text: `[ERROR] ${err.message}` }] };
    }
  }
);

// Graceful error handling
process.on("unhandledRejection", (err) => {
  process.stderr.write(`[MCP_CMD] Unhandled rejection: ${err?.message || err}\n`);
});

// Start server
try {
  const transport = new StdioServerTransport();
  await server.connect(transport);
} catch (err) {
  process.stderr.write(`[MCP_CMD] Failed to start: ${err.message}\n`);
  process.exit(1);
}
