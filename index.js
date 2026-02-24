import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec, execSync } from "child_process";

const server = new McpServer({
  name: "mcp-cmd",
  version: "1.0.0",
});

/**
 * Execute a CMD command with proper /c flag to prevent hanging.
 * Uses child_process.exec with cmd.exe /c to ensure the process exits after command completion.
 */
server.tool(
  "cmd_execute",
  "Execute a Windows CMD command reliably. The command runs via cmd.exe /c which ensures the process exits after completion (no hanging). Returns stdout, stderr, and exit code.",
  {
    command: z.string().describe("The CMD command to execute"),
    cwd: z.string().optional().describe("Working directory for the command. Defaults to C:\\Dev"),
    timeout: z.number().optional().describe("Timeout in milliseconds. Defaults to 30000 (30s). Max 300000 (5min)."),
    encoding: z.string().optional().describe("Output encoding. Defaults to 'utf8'. Use 'buffer' for binary output."),
  },
  async ({ command, cwd, timeout, encoding }) => {
    const workDir = cwd || "C:\\Dev";
    const timeoutMs = Math.min(timeout || 30000, 300000);
    const enc = encoding || "utf8";

    return new Promise((resolve) => {
      const child = exec(
        command,
        {
          cwd: workDir,
          timeout: timeoutMs,
          encoding: enc,
          shell: "cmd.exe",
          windowsHide: true,
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        },
        (error, stdout, stderr) => {
          const exitCode = error ? error.code || 1 : 0;
          const output = [];

          if (stdout && stdout.toString().trim()) {
            output.push(`[STDOUT]\n${stdout.toString().trim()}`);
          }
          if (stderr && stderr.toString().trim()) {
            output.push(`[STDERR]\n${stderr.toString().trim()}`);
          }
          if (error && error.killed) {
            output.push(`[TIMEOUT] Command killed after ${timeoutMs}ms`);
          }
          if (error && !error.killed && !stdout && !stderr) {
            output.push(`[ERROR] ${error.message}`);
          }

          output.push(`\n[EXIT CODE] ${exitCode}`);

          resolve({
            content: [
              {
                type: "text",
                text: output.join("\n") || "[NO OUTPUT]",
              },
            ],
          });
        }
      );
    });
  }
);

/**
 * Execute multiple CMD commands sequentially.
 * Each command runs independently via cmd.exe /c.
 */
server.tool(
  "cmd_execute_batch",
  "Execute multiple CMD commands sequentially. Each command runs via cmd.exe /c. Returns combined output of all commands.",
  {
    commands: z
      .array(
        z.object({
          command: z.string().describe("The CMD command to execute"),
          cwd: z.string().optional().describe("Working directory"),
        })
      )
      .describe("Array of commands to execute sequentially"),
    timeout: z.number().optional().describe("Timeout per command in ms. Defaults to 30000."),
  },
  async ({ commands, timeout }) => {
    const timeoutMs = Math.min(timeout || 30000, 300000);
    const results = [];

    for (let i = 0; i < commands.length; i++) {
      const { command, cwd } = commands[i];
      const workDir = cwd || "C:\\Dev";

      try {
        const stdout = execSync(command, {
          cwd: workDir,
          timeout: timeoutMs,
          encoding: "utf8",
          shell: "cmd.exe",
          windowsHide: true,
          maxBuffer: 10 * 1024 * 1024,
          stdio: ["pipe", "pipe", "pipe"],
        });

        results.push(`--- Command ${i + 1}: ${command} ---\n[OK] ${stdout.trim()}`);
      } catch (error) {
        const stderr = error.stderr ? error.stderr.toString().trim() : "";
        const stdout = error.stdout ? error.stdout.toString().trim() : "";
        const exitCode = error.status || 1;

        let output = `--- Command ${i + 1}: ${command} ---\n[FAILED] Exit code: ${exitCode}`;
        if (stdout) output += `\n[STDOUT] ${stdout}`;
        if (stderr) output += `\n[STDERR] ${stderr}`;

        results.push(output);

        // Stop on first failure
        results.push(`\n[STOPPED] Batch execution stopped at command ${i + 1}`);
        break;
      }
    }

    return {
      content: [
        {
          type: "text",
          text: results.join("\n\n") || "[NO OUTPUT]",
        },
      ],
    };
  }
);

/**
 * Check system info (quick diagnostic)
 */
server.tool(
  "cmd_system_info",
  "Get basic Windows system information (OS version, architecture, available memory, etc.)",
  {},
  async () => {
    try {
      const info = execSync(
        'echo OS: %OS% && echo ARCH: %PROCESSOR_ARCHITECTURE% && echo COMSPEC: %COMSPEC% && echo USER: %USERNAME% && systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Total Physical Memory" /C:"Available Physical Memory"',
        {
          encoding: "utf8",
          shell: "cmd.exe",
          timeout: 15000,
          windowsHide: true,
          maxBuffer: 1024 * 1024,
        }
      );
      return {
        content: [{ type: "text", text: info.trim() }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `[ERROR] ${error.message}`,
          },
        ],
      };
    }
  }
);

// Start the server
const transport = new StdioServerTransport();
await server.connect(transport);
