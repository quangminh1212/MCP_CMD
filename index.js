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
    const names = filter
      ? `Name LIKE '%${filter}%'`
      : "Name='cmd.exe' OR Name='conhost.exe' OR Name='powershell.exe' OR Name='node.exe'";
    return execCmd(
      `wmic process where "(${names})" get ProcessId,Name,CreationDate,CommandLine /format:list`,
      { timeout: 10000 }
    );
  }
);

// ─── Tool 6: Cleanup hanging/orphaned processes ────────────────────────────────

server.tool(
  "process_cleanup",
  "Find and kill hanging/orphaned cmd.exe and conhost.exe processes. Targets windowless CMD processes older than the specified age. Use this to clean up stale processes left by Antigravity's run_command tool.",
  {
    maxAgeMinutes: z
      .number()
      .optional()
      .describe("Kill processes older than this many minutes. Defaults to 5."),
    dryRun: z
      .boolean()
      .optional()
      .describe("If true, only list processes without killing them. Defaults to false."),
    includeNode: z
      .boolean()
      .optional()
      .describe("Also clean up orphaned node.exe processes. Defaults to false."),
  },
  async ({ maxAgeMinutes, dryRun, includeNode }) => {
    const ageLimit = maxAgeMinutes ?? 5;
    const isDry = dryRun ?? false;

    try {
      // Get list of cmd.exe and conhost.exe processes with creation time
      const targets = ["cmd.exe", "conhost.exe"];
      if (includeNode) targets.push("node.exe");

      const nameFilter = targets.map(n => `Name='${n}'`).join(" OR ");
      const raw = execSync(
        `wmic process where "(${nameFilter})" get ProcessId,Name,CreationDate,ParentProcessId /format:csv`,
        { encoding: "utf8", windowsHide: true, timeout: 10000 }
      );

      const lines = raw.trim().split("\n").filter(l => l.trim() && !l.startsWith("Node"));
      const now = Date.now();
      const killed = [];
      const skipped = [];

      // Get our own PID and parent to avoid self-kill
      const myPid = process.pid;

      for (const line of lines) {
        const cols = line.trim().split(",");
        if (cols.length < 5) continue;

        const [, creationDate, name, parentPid, pid] = cols;
        const pidNum = parseInt(pid);
        const parentPidNum = parseInt(parentPid);

        if (isNaN(pidNum) || pidNum === myPid) continue;

        // Parse WMIC date: 20260224220000.000000+420
        const match = creationDate.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
        if (!match) continue;

        const created = new Date(
          parseInt(match[1]), parseInt(match[2]) - 1, parseInt(match[3]),
          parseInt(match[4]), parseInt(match[5]), parseInt(match[6])
        );
        const ageMs = now - created.getTime();
        const ageMins = Math.round(ageMs / 60000);

        if (ageMins < ageLimit) {
          skipped.push(`⏭ PID ${pidNum} (${name}) - ${ageMins}min old (under ${ageLimit}min limit)`);
          continue;
        }

        if (isDry) {
          killed.push(`🔍 PID ${pidNum} (${name}) - ${ageMins}min old - WOULD KILL`);
        } else {
          try {
            execSync(`taskkill /T /F /PID ${pidNum}`, { windowsHide: true, stdio: "ignore" });
            killed.push(`💀 PID ${pidNum} (${name}) - ${ageMins}min old - KILLED`);
          } catch (_) {
            killed.push(`⚠️ PID ${pidNum} (${name}) - ${ageMins}min old - KILL FAILED (already dead?)`);
          }
        }
      }

      const parts = [];
      parts.push(`[${isDry ? "DRY RUN" : "CLEANUP"}] Age limit: ${ageLimit}min`);
      if (killed.length) parts.push(killed.join("\n"));
      else parts.push("✅ No hanging processes found.");
      if (skipped.length) parts.push(`\n[SKIPPED ${skipped.length} recent processes]`);

      return { content: [{ type: "text", text: parts.join("\n") }] };
    } catch (err) {
      return { content: [{ type: "text", text: `[ERROR] ${err.message}` }] };
    }
  }
);

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
