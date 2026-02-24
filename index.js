import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn, execSync } from "child_process";

const server = new McpServer({
  name: "mcp-cmd",
  version: "1.0.0",
});

/**
 * Anti-hang CMD execution using spawn with process isolation.
 * - Spawns cmd.exe /c so the shell exits after command completes
 * - Closes stdin immediately to prevent interactive prompts from blocking
 * - Kills the entire process tree on timeout (taskkill /T /F /PID)
 * - Caps output buffer to prevent memory issues
 */
function execCmd(command, options = {}) {
  const cwd = options.cwd || "C:\\Dev";
  const timeoutMs = Math.min(options.timeout || 30000, 300000);
  const maxOutput = options.maxOutput || 5 * 1024 * 1024; // 5MB

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let finished = false;
    let timedOut = false;

    const child = spawn("cmd.exe", ["/S", "/C", `"${command}"`], {
      cwd,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });

    // Close stdin immediately - prevents interactive prompts from hanging
    child.stdin.end();

    child.stdout.on("data", (data) => {
      if (stdout.length < maxOutput) stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      if (stderr.length < maxOutput) stderr += data.toString();
    });

    const timer = setTimeout(() => {
      if (!finished) {
        timedOut = true;
        // Kill entire process tree to prevent orphans
        try {
          execSync(`taskkill /T /F /PID ${child.pid}`, {
            windowsHide: true,
            stdio: "ignore",
          });
        } catch (_) {
          child.kill("SIGKILL");
        }
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

      resolve({
        content: [{ type: "text", text: parts.join("\n") || "[NO OUTPUT]" }],
      });
    }

    child.on("close", (code) => done(code));
    child.on("error", (err) => {
      stderr += err.message;
      done(1);
    });
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
      const failed = text.includes("[EXIT 1]") || text.includes("[TIMEOUT]");

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
    const cmd = 'echo OS: %OS% & echo ARCH: %PROCESSOR_ARCHITECTURE% & echo USER: %USERNAME% & echo SHELL: %COMSPEC%';
    return execCmd(cmd, { timeout: 15000 });
  }
);

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
