# MCP CMD — Chạy lệnh Windows không bao giờ bị treo 🚀

> MCP Server nhẹ, giúp AI assistant (Antigravity, Claude, Gemini CLI...) chạy lệnh CMD & PowerShell trên Windows **an toàn, không bao giờ bị treo**.

**🔗 Repo:** [github.com/quangminh1212/MCP_CMD](https://github.com/quangminh1212/MCP_CMD)

---

## Vấn đề gì được giải quyết?

Khi dùng AI coding assistant trên Windows, lệnh shell thường **bị treo vĩnh viễn** do:
- Prompt chờ nhập liệu (y/n, password...)
- Process zombie không tự tắt
- Escape ký tự đặc biệt trong PowerShell

**MCP CMD** xử lý tất cả bằng cách:
- ✅ Đóng `stdin` ngay lập tức — không prompt nào block được
- ✅ Tự kill cả process tree khi timeout — không zombie
- ✅ PowerShell chạy qua Base64 — hết lỗi escape
- ✅ Output giới hạn 5MB — không tràn bộ nhớ

---

## 6 Tools có sẵn

| Tool | Mô tả |
|------|--------|
| `cmd_run` | Chạy 1 lệnh CMD đơn lẻ |
| `cmd_batch` | Chạy nhiều lệnh tuần tự (dừng khi lỗi hoặc tiếp tục) |
| `powershell_run` | Chạy PowerShell an toàn, không lỗi escape |
| `system_info` | Xem thông tin hệ thống (OS, RAM, user) |
| `process_list` | Liệt kê các process đang chạy |
| `process_cleanup` | Dọn dẹp process treo/zombie |

---

## Cài đặt nhanh (3 bước)

### 1. Clone & cài đặt

```bash
git clone https://github.com/quangminh1212/MCP_CMD.git
cd MCP_CMD
npm install
```

### 2. Thêm vào MCP config

Thêm đoạn sau vào file cấu hình MCP của bạn (ví dụ: `.gemini/settings.json`, `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cmd": {
      "command": "node",
      "args": ["C:\\path\\to\\MCP_CMD\\index.js"],
      "autoApprove": ["cmd_run", "cmd_batch", "powershell_run", "system_info", "process_list", "process_cleanup"]
    }
  }
}
```

> ⚠️ Thay `C:\\path\\to\\MCP_CMD` bằng đường dẫn thực tế trên máy bạn.

### 3. Xong! 🎉

AI assistant của bạn giờ có thể chạy lệnh Windows mà **không bao giờ bị treo**.

---

## Ví dụ sử dụng

### Chạy lệnh CMD đơn giản

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

### Chạy nhiều lệnh liên tiếp

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

### Chạy PowerShell

```json
{
  "name": "powershell_run",
  "arguments": {
    "command": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU",
    "timeout": 15000
  }
}
```

### Dọn dẹp process treo

```json
{
  "name": "process_cleanup",
  "arguments": {
    "maxAgeSeconds": 10,
    "dryRun": false,
    "includeNode": false
  }
}
```

---

## Kiến trúc Anti-Hang

```
┌─────────────────────────────────────────────┐
│  MCP Client (AI Assistant)                  │
│  Gửi JSON-RPC request qua stdio            │
└────────────────┬────────────────────────────┘
                 │
┌────────────────▼────────────────────────────┐
│  MCP CMD Server (Node.js)                   │
│                                             │
│  1. spawn("cmd.exe", ["/c", command])       │
│  2. child.stdin.end()  ← đóng ngay         │
│  3. Thu stdout/stderr (giới hạn 5MB)        │
│  4. setTimeout → taskkill /T /F /PID        │
│  5. Trả kết quả khi xong hoặc timeout      │
└─────────────────────────────────────────────┘
```

| Bảo vệ | Cách thực hiện |
|---------|---------------|
| Không treo khi chờ input | `stdin.end()` ngay sau spawn |
| Không process zombie | `taskkill /T /F /PID` kill cả cây process |
| Không tràn bộ nhớ | Output giới hạn 5MB |
| Không popup GUI | `windowsHide: true` |
| Không lỗi escape PS | PowerShell dùng `-EncodedCommand` (Base64 UTF-16LE) |

---

## Yêu cầu

- **Node.js** v18+
- **Windows** OS

## License

[MIT](LICENSE) © 2026 quangminh1212
