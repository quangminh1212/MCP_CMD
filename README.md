# MCP CMD

> A lightweight MCP (Model Context Protocol) server for reliable Windows CMD and PowerShell command execution — designed to **never hang**.

## Why?

AI coding assistants often struggle with Windows shell execution — commands hang indefinitely due to interactive prompts, stdin blocking, or zombie processes. **MCP CMD** solves this with a purpose-built execution engine:

- **`stdin` closed immediately** — no interactive prompt can block
- **Process tree kill on timeout** — `taskkill /T /F /PID` eliminates all child processes
- **Isolated process per command** — each command runs in its own `cmd.exe /c` process
- **PowerShell via Base64 EncodedCommand** — zero escaping issues

## Tools

| Tool | Description |
|------|-------------|
| `cmd_run` | Run a single CMD command safely |
| `cmd_batch` | Run multiple commands sequentially (stops on failure or continues) |
| `powershell_run` | Run PowerShell with `-NonInteractive -NoProfile -EncodedCommand` |
| `system_info` | Quick Windows system diagnostic (OS, arch, user) |

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- Windows OS

### Setup

```bash
git clone https://github.com/quangminh1212/MCP_CMD.git
cd MCP_CMD
npm install
```

### Configure in your MCP client

Add to your MCP configuration (e.g. `mcp_config.json`, `claude_desktop_config.json`, or `.gemini/settings.json`):

```json
{
  "mcpServers": {
    "cmd": {
      "command": "node",
      "args": ["C:\\path\\to\\MCP_CMD\\index.js"],
      "autoApprove": ["cmd_run", "cmd_batch", "powershell_run", "system_info"]
    }
  }
}
```

### Test

```bash
npm start
```

The server communicates via **stdio** using the MCP JSON-RPC protocol.

## Usage Examples

### cmd_run

```json
{
  "name": "cmd_run",
  "arguments": {
    "command": "echo Hello && dir /b",
    "cwd": "C:\\Projects",
    "timeout": 30000
  }
}
```

### cmd_batch

```json
{
  "name": "cmd_batch",
  "arguments": {
    "commands": [
      { "command": "npm install", "cwd": "C:\\Projects\\my-app" },
      { "command": "npm run build", "cwd": "C:\\Projects\\my-app" },
      { "command": "npm test", "cwd": "C:\\Projects\\my-app" }
    ],
    "timeout": 60000,
    "continueOnError": false
  }
}
```

### powershell_run

```json
{
  "name": "powershell_run",
  "arguments": {
    "command": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU",
    "timeout": 15000
  }
}
```

### system_info

```json
{
  "name": "system_info",
  "arguments": {}
}
```

## Anti-Hang Architecture

```
┌─────────────────────────────────────────────┐
│  MCP Client (AI Assistant)                  │
│  Sends JSON-RPC request via stdio           │
└────────────────┬────────────────────────────┘
                 │
┌────────────────▼────────────────────────────┐
│  MCP CMD Server (Node.js)                   │
│                                             │
│  1. spawn("cmd.exe", ["/c", command])       │
│  2. child.stdin.end()  ← close immediately  │
│  3. Collect stdout/stderr with cap          │
│  4. setTimeout → taskkill /T /F /PID        │
│  5. Return result on close/timeout          │
└─────────────────────────────────────────────┘
```

**Key protections:**

| Protection | How |
|-----------|-----|
| No hanging on input | `stdin.end()` called immediately after spawn |
| No zombie processes | `taskkill /T /F /PID` kills entire process tree |
| No memory overflow | Output capped at 5MB |
| No GUI popups | `windowsHide: true` |
| No PS escaping bugs | PowerShell uses `-EncodedCommand` (Base64 UTF-16LE) |

## License

[MIT](LICENSE) © 2026 quangminh1212
