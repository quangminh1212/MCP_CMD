import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec, execSync } from "child_process";
import { readFileSync, writeFileSync, appendFileSync, existsSync, statSync } from "fs";
import { resolve, basename } from "path";

/** Helper: run a CMD command synchronously and return output */
function runCmd(command, options = {}) {
  const opts = {
    encoding: "utf8",
    shell: "cmd.exe",
    windowsHide: true,
    timeout: options.timeout || 30000,
    maxBuffer: 10 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
    ...options,
  };
  try {
    const stdout = execSync(command, opts);
    return { ok: true, output: stdout.toString().trim() };
  } catch (error) {
    const stderr = error.stderr ? error.stderr.toString().trim() : "";
    const stdout = error.stdout ? error.stdout.toString().trim() : "";
    return { ok: false, output: stdout, error: stderr || error.message, exitCode: error.status || 1 };
  }
}

/** Helper: format result as MCP content */
function textResult(text) {
  return { content: [{ type: "text", text }] };
}

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

// ==================== FILE OPERATIONS ====================

/**
 * Read file content using Node.js fs (reliable, no shell escaping issues)
 */
server.tool(
  "file_read",
  "Read the contents of a file. Supports optional line range (startLine/endLine). Returns file content as text.",
  {
    path: z.string().describe("Absolute or relative path to the file"),
    startLine: z.number().optional().describe("Start line (1-indexed). Omit to read from beginning."),
    endLine: z.number().optional().describe("End line (1-indexed, inclusive). Omit to read to end."),
  },
  async ({ path: filePath, startLine, endLine }) => {
    try {
      const absPath = resolve(filePath);
      if (!existsSync(absPath)) return textResult(`[ERROR] File not found: ${absPath}`);
      const content = readFileSync(absPath, "utf8");
      if (startLine || endLine) {
        const lines = content.split(/\r?\n/);
        const start = Math.max((startLine || 1) - 1, 0);
        const end = Math.min(endLine || lines.length, lines.length);
        const slice = lines.slice(start, end);
        return textResult(`[FILE] ${absPath} (lines ${start + 1}-${end} of ${lines.length})\n${slice.join("\n")}`);
      }
      return textResult(`[FILE] ${absPath}\n${content}`);
    } catch (error) {
      return textResult(`[ERROR] ${error.message}`);
    }
  }
);

/**
 * Write or append content to a file
 */
server.tool(
  "file_write",
  "Write or append content to a file. Creates the file if it doesn't exist. Supports 'write' (overwrite) or 'append' mode.",
  {
    path: z.string().describe("Absolute or relative path to the file"),
    content: z.string().describe("Content to write"),
    mode: z.enum(["write", "append"]).optional().describe("Write mode: 'write' (overwrite) or 'append'. Defaults to 'write'."),
  },
  async ({ path: filePath, content, mode }) => {
    try {
      const absPath = resolve(filePath);
      if (mode === "append") {
        appendFileSync(absPath, content, "utf8");
        return textResult(`[OK] Appended ${content.length} chars to ${absPath}`);
      } else {
        writeFileSync(absPath, content, "utf8");
        return textResult(`[OK] Written ${content.length} chars to ${absPath}`);
      }
    } catch (error) {
      return textResult(`[ERROR] ${error.message}`);
    }
  }
);

/**
 * Find files by name pattern (recursive)
 */
server.tool(
  "file_find",
  "Find files by name pattern recursively. Uses 'dir /s /b' for fast Windows-native search. Supports wildcards like *.js, *.txt, etc.",
  {
    pattern: z.string().describe("File name pattern with wildcards (e.g., '*.js', 'config*', '*.log')"),
    directory: z.string().optional().describe("Directory to search in. Defaults to C:\\Dev"),
    maxResults: z.number().optional().describe("Maximum results to return. Defaults to 50."),
  },
  async ({ pattern, directory, maxResults }) => {
    const dir = directory || "C:\\Dev";
    const max = maxResults || 50;
    const result = runCmd(`dir /s /b "${pattern}"`, { cwd: dir, timeout: 30000 });
    if (!result.ok && !result.output) return textResult(`[NO MATCH] No files found matching '${pattern}' in ${dir}`);
    const lines = (result.output || "").split(/\r?\n/).filter(Boolean);
    const limited = lines.slice(0, max);
    return textResult(`[FOUND] ${lines.length} file(s) matching '${pattern}' in ${dir}${lines.length > max ? ` (showing first ${max})` : ""}\n${limited.join("\n")}`);
  }
);

/**
 * Search text content inside files (grep-like)
 */
server.tool(
  "file_grep",
  "Search for text content inside files (like grep). Uses 'findstr' for Windows-native text search. Returns matching lines with file names and line numbers.",
  {
    query: z.string().describe("Text to search for"),
    path: z.string().optional().describe("File or directory to search in. Defaults to current directory."),
    recursive: z.boolean().optional().describe("Search recursively in subdirectories. Defaults to true."),
    caseInsensitive: z.boolean().optional().describe("Case-insensitive search. Defaults to true."),
    filePattern: z.string().optional().describe("Filter by file pattern (e.g., '*.js', '*.txt'). Defaults to '*.*'"),
  },
  async ({ query, path: searchPath, recursive, caseInsensitive, filePattern }) => {
    const dir = searchPath || ".";
    const flags = [];
    if (recursive !== false) flags.push("/S");
    if (caseInsensitive !== false) flags.push("/I");
    flags.push("/N"); // line numbers
    const pattern = filePattern || "*.*";
    const cmd = `findstr ${flags.join(" ")} /C:"${query}" "${dir}\\${pattern}"`;
    const result = runCmd(cmd, { timeout: 30000 });
    if (!result.ok && !result.output) return textResult(`[NO MATCH] No results for '${query}'`);
    const lines = (result.output || "").split(/\r?\n/).filter(Boolean);
    const limited = lines.slice(0, 100);
    return textResult(`[GREP] ${lines.length} match(es) for '${query}'\n${limited.join("\n")}${lines.length > 100 ? "\n... (truncated)" : ""}`);
  }
);

// ==================== DIRECTORY OPERATIONS ====================

/**
 * List directory contents with details
 */
server.tool(
  "dir_list",
  "List directory contents with details (name, size, date, type). Provides a formatted listing similar to 'dir' command.",
  {
    path: z.string().optional().describe("Directory path. Defaults to C:\\Dev"),
    showHidden: z.boolean().optional().describe("Show hidden/system files. Defaults to false."),
    sortBy: z.enum(["name", "size", "date", "extension"]).optional().describe("Sort by: name, size, date, or extension. Defaults to name."),
  },
  async ({ path: dirPath, showHidden, sortBy }) => {
    const dir = dirPath || "C:\\Dev";
    const sortFlag = { name: "/ON", size: "/OS", date: "/OD", extension: "/OE" }[sortBy || "name"];
    const hiddenFlag = showHidden ? "/A" : "/A-H-S";
    const result = runCmd(`dir ${hiddenFlag} ${sortFlag} "${dir}"`, { timeout: 15000 });
    if (!result.ok) return textResult(`[ERROR] ${result.error || "Cannot list directory"}`);
    return textResult(`[DIR] ${dir}\n${result.output}`);
  }
);

/**
 * Directory tree structure
 */
server.tool(
  "dir_tree",
  "Show directory tree structure. Displays folder hierarchy visually. Useful for understanding project structure.",
  {
    path: z.string().optional().describe("Root directory. Defaults to C:\\Dev"),
    depth: z.number().optional().describe("Max depth level. Omit for full tree."),
    filesOnly: z.boolean().optional().describe("If true, also show files (not just folders). Defaults to false (folders only)."),
  },
  async ({ path: dirPath, depth, filesOnly }) => {
    const dir = dirPath || "C:\\Dev";
    let cmd = `tree "${dir}"`;
    if (filesOnly) cmd += " /F";
    // tree command doesn't support depth, so we use it as-is and truncate output
    const result = runCmd(cmd, { timeout: 15000 });
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    const lines = result.output.split(/\r?\n/);
    if (depth && depth > 0) {
      // Approximate depth filtering by indentation
      const filtered = lines.filter((line) => {
        const indent = line.search(/\S/);
        return indent < 0 || indent <= depth * 4 + 4;
      });
      return textResult(`[TREE] ${dir} (depth ≤ ${depth})\n${filtered.join("\n")}`);
    }
    return textResult(`[TREE] ${dir}\n${result.output}`);
  }
);

// ==================== PROCESS MANAGEMENT ====================

/**
 * List running processes
 */
server.tool(
  "process_list",
  "List running Windows processes. Optionally filter by name. Shows PID, memory usage, and process name.",
  {
    filter: z.string().optional().describe("Filter by process name (e.g., 'node', 'chrome'). Omit for all processes."),
    format: z.enum(["table", "csv"]).optional().describe("Output format: 'table' or 'csv'. Defaults to 'table'."),
  },
  async ({ filter, format }) => {
    let cmd = "tasklist /NH";
    if (format === "csv") cmd = "tasklist /FO CSV";
    else cmd = "tasklist /FO TABLE";
    if (filter) cmd += ` /FI "IMAGENAME eq ${filter}*"`;
    const result = runCmd(cmd);
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    return textResult(`[PROCESSES]${filter ? ` (filter: ${filter})` : ""}\n${result.output}`);
  }
);

/**
 * Kill a process
 */
server.tool(
  "process_kill",
  "Kill a Windows process by name or PID. Use /F flag to force kill.",
  {
    target: z.string().describe("Process name (e.g., 'notepad.exe') or PID number"),
    force: z.boolean().optional().describe("Force kill. Defaults to true."),
    tree: z.boolean().optional().describe("Kill process tree (all child processes). Defaults to false."),
  },
  async ({ target, force, tree }) => {
    const flags = [];
    if (force !== false) flags.push("/F");
    if (tree) flags.push("/T");
    const isNumeric = /^\d+$/.test(target);
    const idFlag = isNumeric ? `/PID ${target}` : `/IM "${target}"`;
    const result = runCmd(`taskkill ${flags.join(" ")} ${idFlag}`);
    return textResult(result.ok ? `[OK] ${result.output}` : `[ERROR] ${result.error || result.output}`);
  }
);

// ==================== NETWORK ====================

/**
 * Ping a host
 */
server.tool(
  "network_ping",
  "Ping a host to check connectivity. Returns ping statistics (time, TTL, packet loss).",
  {
    host: z.string().describe("Host to ping (IP or domain name)"),
    count: z.number().optional().describe("Number of pings. Defaults to 4."),
  },
  async ({ host, count }) => {
    const n = count || 4;
    const result = runCmd(`ping -n ${n} ${host}`, { timeout: n * 5000 + 5000 });
    return textResult(result.ok ? `[PING] ${host}\n${result.output}` : `[ERROR] ${result.error || result.output}`);
  }
);

/**
 * Show listening network ports
 */
server.tool(
  "network_ports",
  "Show active network connections and listening ports. Optionally filter by port number or state.",
  {
    state: z.enum(["listening", "established", "all"]).optional().describe("Connection state filter. Defaults to 'listening'."),
    port: z.number().optional().describe("Filter by specific port number."),
  },
  async ({ state, port }) => {
    let cmd = "netstat -ano";
    if (state === "listening" || !state) cmd += ' | findstr "LISTENING"';
    else if (state === "established") cmd += ' | findstr "ESTABLISHED"';
    if (port) cmd += ` | findstr ":${port}"`;
    const result = runCmd(cmd);
    if (!result.ok && !result.output) return textResult("[INFO] No matching connections found.");
    return textResult(`[PORTS] ${state || "listening"}\n${result.output || result.error}`);
  }
);

/**
 * Show network/IP configuration
 */
server.tool(
  "network_ipconfig",
  "Show network adapter configuration (IP addresses, DNS, gateway, etc.).",
  {
    all: z.boolean().optional().describe("Show detailed config (/all). Defaults to false."),
  },
  async ({ all }) => {
    const cmd = all ? "ipconfig /all" : "ipconfig";
    const result = runCmd(cmd);
    return textResult(result.ok ? result.output : `[ERROR] ${result.error}`);
  }
);

// ==================== SYSTEM ====================

/**
 * Disk space info
 */
server.tool(
  "disk_info",
  "Show disk space usage for all drives or a specific drive. Shows total, used, and free space.",
  {
    drive: z.string().optional().describe("Drive letter (e.g., 'C'). Omit for all drives."),
  },
  async ({ drive }) => {
    let cmd = 'wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem,VolumeName /format:list';
    if (drive) cmd = `wmic logicaldisk where "DeviceID='${drive.replace(":", "")}:'" get DeviceID,Size,FreeSpace,FileSystem,VolumeName /format:list`;
    const result = runCmd(cmd, { timeout: 15000 });
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    // Parse and format nicely
    const raw = result.output;
    const blocks = raw.split(/\n\s*\n/).filter((b) => b.trim());
    const drives = blocks.map((block) => {
      const props = {};
      block.split(/\r?\n/).forEach((line) => {
        const [key, ...val] = line.split("=");
        if (key && val.length) props[key.trim()] = val.join("=").trim();
      });
      if (!props.DeviceID) return null;
      const total = parseInt(props.Size) || 0;
      const free = parseInt(props.FreeSpace) || 0;
      const used = total - free;
      const gb = (b) => (b / 1073741824).toFixed(2) + " GB";
      const pct = total > 0 ? ((used / total) * 100).toFixed(1) + "%" : "N/A";
      return `${props.DeviceID} [${props.FileSystem || "?"}] ${props.VolumeName || ""}\n  Total: ${gb(total)} | Used: ${gb(used)} (${pct}) | Free: ${gb(free)}`;
    }).filter(Boolean);
    return textResult(`[DISK INFO]\n${drives.join("\n\n")}`);
  }
);

/**
 * Get/list environment variables
 */
server.tool(
  "env_get",
  "Get environment variable value or list all environment variables. Useful for checking PATH, JAVA_HOME, etc.",
  {
    name: z.string().optional().describe("Variable name to get (e.g., 'PATH', 'JAVA_HOME'). Omit to list all."),
  },
  async ({ name }) => {
    if (name) {
      const val = process.env[name] || process.env[name.toUpperCase()];
      if (!val) return textResult(`[NOT SET] Environment variable '${name}' is not defined.`);
      // Special formatting for PATH
      if (name.toUpperCase() === "PATH") {
        const paths = val.split(";").filter(Boolean);
        return textResult(`[ENV] ${name} (${paths.length} entries)\n${paths.join("\n")}`);
      }
      return textResult(`[ENV] ${name}=${val}`);
    }
    const result = runCmd("set");
    return textResult(`[ENV] All variables\n${result.output}`);
  }
);

/**
 * Windows services management
 */
server.tool(
  "service_list",
  "List or query Windows services. Optionally filter by name or state.",
  {
    name: z.string().optional().describe("Service name to query (e.g., 'wuauserv'). Omit to list all running services."),
    state: z.enum(["running", "stopped", "all"]).optional().describe("Filter by state. Defaults to 'running'."),
  },
  async ({ name, state }) => {
    if (name) {
      const result = runCmd(`sc query "${name}"`);
      return textResult(result.ok ? `[SERVICE] ${name}\n${result.output}` : `[ERROR] ${result.error || result.output}`);
    }
    const stateFilter = state === "stopped" ? "state= inactive" : state === "all" ? "state= all" : "";
    const result = runCmd(`sc query ${stateFilter} type= service`);
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    // Summarize
    const matches = result.output.match(/SERVICE_NAME: .+/g) || [];
    return textResult(`[SERVICES] ${matches.length} service(s) (${state || "running"})\n${result.output}`);
  }
);

// ==================== CLIPBOARD ====================

/**
 * Read clipboard content
 */
server.tool(
  "clipboard_read",
  "Read the current text content from the Windows clipboard.",
  {},
  async () => {
    const result = runCmd('powershell -NoProfile -Command "Get-Clipboard"', { timeout: 5000 });
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    return textResult(`[CLIPBOARD]\n${result.output || "(empty)"}`);
  }
);

/**
 * Write to clipboard
 */
server.tool(
  "clipboard_write",
  "Write text content to the Windows clipboard.",
  {
    content: z.string().describe("Text to copy to clipboard"),
  },
  async ({ content }) => {
    // Use powershell to set clipboard, pipe content via echo
    const escaped = content.replace(/"/g, '`"').replace(/\n/g, '`n');
    const result = runCmd(`powershell -NoProfile -Command "Set-Clipboard -Value \\"${escaped}\\""`, { timeout: 5000 });
    if (!result.ok) return textResult(`[ERROR] ${result.error}`);
    return textResult(`[OK] Copied ${content.length} chars to clipboard.`);
  }
);

// ==================== UTILITIES ====================

/**
 * Check if path exists and get info
 */
server.tool(
  "path_info",
  "Check if a file/directory exists and get detailed info (size, dates, attributes).",
  {
    path: z.string().describe("Path to check"),
  },
  async ({ path: targetPath }) => {
    try {
      const absPath = resolve(targetPath);
      if (!existsSync(absPath)) return textResult(`[NOT FOUND] ${absPath}`);
      const stat = statSync(absPath);
      const type = stat.isDirectory() ? "Directory" : "File";
      const size = stat.isFile() ? `${(stat.size / 1024).toFixed(2)} KB (${stat.size} bytes)` : "N/A";
      const info = [
        `[PATH INFO] ${absPath}`,
        `Type: ${type}`,
        `Size: ${size}`,
        `Created: ${stat.birthtime.toISOString()}`,
        `Modified: ${stat.mtime.toISOString()}`,
        `Accessed: ${stat.atime.toISOString()}`,
      ];
      return textResult(info.join("\n"));
    } catch (error) {
      return textResult(`[ERROR] ${error.message}`);
    }
  }
);

/**
 * Open file/URL in default application
 */
server.tool(
  "open",
  "Open a file, folder, or URL in the default Windows application (e.g., open a folder in Explorer, a URL in browser, a file in its associated app).",
  {
    target: z.string().describe("File path, folder path, or URL to open"),
  },
  async ({ target }) => {
    const result = runCmd(`start "" "${target}"`, { timeout: 10000 });
    return textResult(result.ok ? `[OK] Opened: ${target}` : `[ERROR] ${result.error}`);
  }
);

// Start the server
const transport = new StdioServerTransport();
await server.connect(transport);
