#!/usr/bin/env node
/**
 * Headless MCP Server Wrapper for Windows
 * 
 * Wraps any command execution with windowsHide: true to prevent
 * CMD/console windows from flashing on Windows.
 * 
 * Usage in mcp_config.json:
 *   Instead of: { "command": "npx", "args": ["-y", "some-mcp-server"] }
 *   Use:        { "command": "node", "args": ["C:\\Dev\\MCP_CMD\\headless-wrapper.js", "npx", "-y", "some-mcp-server"] }
 * 
 * This wrapper:
 * 1. Resolves .cmd/.ps1 wrappers (npx, npm, etc.) to actual executables
 * 2. Spawns the target command with windowsHide: true
 * 3. Pipes STDIO transparently (required for MCP protocol)
 * 4. Forwards exit codes properly
 */

import { spawn, spawnSync } from "child_process";
import { existsSync } from "fs";
import { join, dirname, resolve as pathResolve } from "path";

// Parse arguments: first arg after script is the command, rest are args
const [command, ...args] = process.argv.slice(2);

if (!command) {
    process.stderr.write("[headless-wrapper] Error: No command specified.\n");
    process.stderr.write("Usage: node headless-wrapper.js <command> [args...]\n");
    process.exit(1);
}

/**
 * Resolve a command to its actual executable path on Windows.
 * npx/npm on Windows are .cmd or .ps1 scripts - we need to handle them
 * without using shell: true (which creates a visible CMD window).
 * 
 * For .cmd/.ps1 wrappers, we use cmd.exe /c but with windowsHide: true.
 * The key insight: windowsHide works on the PARENT spawn call, so even
 * if cmd.exe is involved, the window stays hidden.
 */
function resolveCommand(cmd) {
    // If it's an absolute path to an actual executable, use directly
    if (existsSync(cmd) && cmd.endsWith('.exe')) {
        return { command: cmd, useShell: false };
    }

    // Known Windows wrapper commands that need shell resolution
    const needsShell = ['npx', 'npm', 'yarn', 'pnpm', 'pip', 'uv', 'uvx'];

    if (needsShell.includes(cmd.toLowerCase())) {
        // Use cmd.exe /c to resolve .cmd/.ps1 files, but windowsHide will hide it
        return { command: cmd, useShell: true };
    }

    // For python, pythonw, node, etc. - direct executable
    return { command: cmd, useShell: false };
}

const resolved = resolveCommand(command);

// Spawn with windowsHide: true
// When shell: true + windowsHide: true → cmd.exe runs hidden
const child = spawn(resolved.command, args, {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    shell: resolved.useShell,
    env: { ...process.env },
});

// Transparent STDIO proxy - critical for MCP STDIO transport
process.stdin.pipe(child.stdin);
child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);

// Forward exit code
child.on("close", (code) => {
    process.exit(code ?? 1);
});

child.on("error", (err) => {
    process.stderr.write(`[headless-wrapper] Failed to start '${command}': ${err.message}\n`);
    process.exit(1);
});

// Cleanup on parent exit
process.on("SIGINT", () => {
    child.kill("SIGINT");
});
process.on("SIGTERM", () => {
    child.kill("SIGTERM");
});
