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
 * 5. Kills entire process tree on exit (anti-zombie)
 */

import { spawn, spawnSync } from "child_process";
import { existsSync } from "fs";

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
        return { command: cmd, useShell: true };
    }

    // For python, pythonw, node, etc. - direct executable
    return { command: cmd, useShell: false };
}

/**
 * Kill entire process tree on Windows using taskkill /T /F.
 * child.kill() on Windows only kills the direct process, NOT its children.
 * This causes zombie cmd.exe/node.exe processes when the wrapper exits.
 */
function forceKillTree(pid) {
    if (!pid) return;
    try {
        spawnSync("taskkill", ["/T", "/F", "/PID", String(pid)], {
            windowsHide: true, stdio: "ignore", timeout: 5000
        });
    } catch (_) {
        // Fallback: try killing just the process
        try { process.kill(pid, "SIGKILL"); } catch (_2) { /* already dead */ }
    }
}

const resolved = resolveCommand(command);

// Spawn with windowsHide: true
// When shell: true + windowsHide: true → cmd.exe runs hidden
const child = spawn(resolved.command, args, {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    shell: resolved.useShell,
    // Inherit env directly (no need to spread, spawn inherits by default)
});

// Transparent STDIO proxy - critical for MCP STDIO transport
// Handle EPIPE errors when child terminates while data is being piped
process.stdin.on("error", () => { });
child.stdin.on("error", () => { });
child.stdout.on("error", () => { });
child.stderr.on("error", () => { });
process.stdin.pipe(child.stdin);
child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);

// Forward exit code + unpipe stdin to prevent backpressure
child.on("close", (code) => {
    process.stdin.unpipe(child.stdin);
    process.exit(code ?? 1);
});

child.on("error", (err) => {
    process.stderr.write(`[headless-wrapper] Failed to start '${command}': ${err.message}\n`);
    process.exit(1);
});

// Anti-zombie: kill entire process TREE on parent exit signals
// child.kill("SIGINT") only kills the direct child on Windows,
// leaving grandchild processes (node.exe, python.exe etc.) as zombies.
process.on("SIGINT", () => {
    forceKillTree(child.pid);
    process.exit(0);
});
process.on("SIGTERM", () => {
    forceKillTree(child.pid);
    process.exit(0);
});

// Safety net: if process exits without signal (e.g. parent pipe closed),
// ensure child tree is cleaned up
process.on("exit", () => {
    forceKillTree(child.pid);
});
