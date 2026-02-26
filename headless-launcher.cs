using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

/// <summary>
/// Headless Launcher for MCP Servers on Windows
/// 
/// Compiled as a Windows GUI application (/target:winexe) so Windows
/// does NOT create a console window when it's spawned.
/// 
/// Uses Win32 GetStdHandle API to access inherited STDIO pipe handles
/// directly (bypassing Console API which doesn't work for GUI apps).
/// 
/// Anti-zombie features:
///   - Monitors parent process: if parent dies, kills child tree and exits
///   - Optional timeout via HEADLESS_TIMEOUT_SEC env var (0 = no timeout)
///   - Proper process tree cleanup on exit (taskkill /T /F)
///   - Only spawns cmd.exe with CreateNoWindow = true
/// 
/// Usage in mcp_config.json:
///   { "command": "C:\\Dev\\MCP_CMD\\headless-launcher.exe",
///     "args": ["npx", "-y", "@upstash/context7-mcp@latest"] }
/// </summary>
class HeadlessLauncher
{
    // Win32 API for getting standard handles (works even for GUI apps)
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);

    const int STD_INPUT_HANDLE = -10;
    const int STD_OUTPUT_HANDLE = -11;
    const int STD_ERROR_HANDLE = -12;

    // Shared state for cleanup
    static Process _childProcess;
    static volatile bool _exiting = false;

    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            return 1;
        }

        // Build the full command line for cmd.exe /c
        string fullCommand = "";
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Contains(" ") || arg.Contains("\"") || arg.Contains("&") || arg.Contains("|"))
            {
                arg = "\"" + arg.Replace("\"", "\\\"") + "\"";
            }
            fullCommand += (i > 0 ? " " : "") + arg;
        }

        // Parse optional timeout from environment variable (seconds, 0 = no timeout)
        // Range: 0 (disabled) or 1-86400 (max 24 hours) to prevent overflow in Thread.Sleep
        int timeoutSec = 0;
        string timeoutEnv = Environment.GetEnvironmentVariable("HEADLESS_TIMEOUT_SEC");
        if (!string.IsNullOrEmpty(timeoutEnv))
        {
            int.TryParse(timeoutEnv, out timeoutSec);
            if (timeoutSec < 0 || timeoutSec > 86400) timeoutSec = 0;
        }

        try
        {
            // Get inherited STDIO handles from parent process via Win32 API
            // This works even for GUI apps (unlike Console.OpenStandard*)
            IntPtr hStdin = GetStdHandle(STD_INPUT_HANDLE);
            IntPtr hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            IntPtr hStderr = GetStdHandle(STD_ERROR_HANDLE);

            // Wrap Win32 handles into .NET streams
            Stream parentStdin = null;
            Stream parentStdout = null;
            Stream parentStderr = null;

            if (hStdin != IntPtr.Zero && hStdin != new IntPtr(-1))
            {
                var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(hStdin, false);
                parentStdin = new FileStream(safeHandle, FileAccess.Read, 4096, false);
            }
            if (hStdout != IntPtr.Zero && hStdout != new IntPtr(-1))
            {
                var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(hStdout, false);
                parentStdout = new FileStream(safeHandle, FileAccess.Write, 4096, false);
            }
            if (hStderr != IntPtr.Zero && hStderr != new IntPtr(-1))
            {
                var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(hStderr, false);
                parentStderr = new FileStream(safeHandle, FileAccess.Write, 4096, false);
            }

            if (parentStdin == null || parentStdout == null)
            {
                return 1;
            }

            // Spawn child with CreateNoWindow = true via cmd.exe /c
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + fullCommand,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            var process = Process.Start(psi);
            if (process == null) return 1;
            _childProcess = process;

            // ─── Parent Process Monitor Thread ────────────────────────────────
            // Watches if our parent process (Antigravity) dies → kill child tree
            var parentMonitor = new Thread(() =>
            {
                try
                {
                    int ppid = 0;
                    // Get parent PID using PowerShell (WMIC is deprecated since Windows 11)
                    try
                    {
                        var currentProc = Process.GetCurrentProcess();
                        var pinfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = "-NoProfile -NonInteractive -Command \"(Get-CimInstance Win32_Process -Filter 'ProcessId=" + currentProc.Id + "').ParentProcessId\"",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardInput = true,
                            RedirectStandardError = true,
                        };
                        var pp = Process.Start(pinfo);
                        if (pp != null)
                        {
                            pp.StandardInput.Close();
                            string output = pp.StandardOutput.ReadToEnd().Trim();
                            pp.WaitForExit(5000);
                            int.TryParse(output, out ppid);
                        }
                    }
                    catch { }

                    if (ppid <= 0) return; // Can't determine parent, skip monitoring

                    Process parentProcess = null;
                    try { parentProcess = Process.GetProcessById(ppid); }
                    catch { return; } // Parent already gone

                    // Poll every 3 seconds to check if parent is still alive
                    while (!_exiting)
                    {
                        Thread.Sleep(3000);
                        try
                        {
                            if (parentProcess.HasExited)
                            {
                                // Parent died → kill child tree and exit
                                KillChildTree();
                                Environment.Exit(1);
                                return;
                            }
                        }
                        catch
                        {
                            // Can't access parent → assume dead
                            KillChildTree();
                            Environment.Exit(1);
                            return;
                        }
                    }
                }
                catch { }
            });
            parentMonitor.IsBackground = true;
            parentMonitor.Start();

            // ─── Optional Timeout Thread ──────────────────────────────────────
            if (timeoutSec > 0)
            {
                var timeoutThread = new Thread(() =>
                {
                    try
                    {
                        Thread.Sleep(timeoutSec * 1000);
                        if (!_exiting)
                        {
                            KillChildTree();
                            Environment.Exit(1);
                        }
                    }
                    catch { }
                });
                timeoutThread.IsBackground = true;
                timeoutThread.Start();
            }

            // Pipe stdin: parent → child
            var stdinThread = new Thread(() =>
            {
                try
                {
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = parentStdin.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        process.StandardInput.BaseStream.Write(buffer, 0, read);
                        process.StandardInput.BaseStream.Flush();
                    }
                    process.StandardInput.Close();
                }
                catch { }
            });
            stdinThread.IsBackground = true;
            stdinThread.Start();

            // Pipe stdout: child → parent
            var stdoutThread = new Thread(() =>
            {
                try
                {
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        parentStdout.Write(buffer, 0, read);
                        parentStdout.Flush();
                    }
                }
                catch { }
            });
            stdoutThread.IsBackground = true;
            stdoutThread.Start();

            // Pipe stderr: child → parent
            var stderrThread = new Thread(() =>
            {
                try
                {
                    if (parentStderr == null) return;
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = process.StandardError.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        parentStderr.Write(buffer, 0, read);
                        parentStderr.Flush();
                    }
                }
                catch { }
            });
            stderrThread.IsBackground = true;
            stderrThread.Start();

            // Wait for child to exit
            process.WaitForExit();
            _exiting = true;

            // Give output pipes time to flush
            stdoutThread.Join(3000);
            stderrThread.Join(3000);

            return process.ExitCode;
        }
        catch
        {
            return 1;
        }
    }

    /// <summary>
    /// Kill the child process tree using taskkill /T /F.
    /// Also marks _exiting = true to stop all monitoring threads.
    /// </summary>
    static void KillChildTree()
    {
        _exiting = true;
        var proc = _childProcess;
        if (proc == null) return;

        try
        {
            if (!proc.HasExited)
            {
                // Kill entire process tree (cmd.exe + all children like node.exe, npx, etc.)
                var killInfo = new ProcessStartInfo
                {
                    FileName = "taskkill",
                    Arguments = "/T /F /PID " + proc.Id,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                };
                var killer = Process.Start(killInfo);
                if (killer != null)
                {
                    killer.StandardInput.Close();
                    killer.WaitForExit(5000);
                }
            }
        }
        catch { /* Process already gone - that's fine */ }
    }
}
