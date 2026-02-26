using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

/// <summary>
/// Headless Launcher for MCP Servers on Windows
/// 
/// Compiled as a Windows GUI application (/target:winexe) so Windows
/// does NOT create a console window when it's spawned.
/// 
/// Spawns the target command with CreateNoWindow=true and transparently
/// pipes STDIO (required for MCP STDIO transport protocol).
/// 
/// Usage in mcp_config.json:
///   { "command": "C:\\Dev\\MCP_CMD\\headless-launcher.exe",
///     "args": ["npx", "-y", "@upstash/context7-mcp@latest"] }
/// </summary>
class HeadlessLauncher
{
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            try { Console.Error.WriteLine("[headless-launcher] No command specified."); } catch { }
            return 1;
        }

        // Build the command and arguments
        string command = args[0];
        string arguments = "";

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];
            // Quote args containing spaces or special chars
            if (arg.Contains(" ") || arg.Contains("\"") || arg.Contains("&") || arg.Contains("|"))
            {
                arg = "\"" + arg.Replace("\"", "\\\"") + "\"";
            }
            arguments += (i > 1 ? " " : "") + arg;
        }

        try
        {
            // Use cmd.exe /c to handle .cmd/.ps1 wrappers (npx, npm, etc.)
            // CreateNoWindow=true prevents any console window
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + command + (arguments.Length > 0 ? " " + arguments : ""),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            // Inherit all environment variables
            foreach (string key in Environment.GetEnvironmentVariables().Keys)
            {
                try
                {
                    string val = Environment.GetEnvironmentVariable(key);
                    if (val != null) psi.EnvironmentVariables[key] = val;
                }
                catch { }
            }

            var process = Process.Start(psi);
            if (process == null) return 1;

            // Pipe stdin: parent → child (async thread)
            var stdinThread = new Thread(() =>
            {
                try
                {
                    Stream input = Console.OpenStandardInput();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
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

            // Pipe stdout: child → parent (async thread)
            var stdoutThread = new Thread(() =>
            {
                try
                {
                    Stream output = Console.OpenStandardOutput();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, read);
                        output.Flush();
                    }
                }
                catch { }
            });
            stdoutThread.IsBackground = true;
            stdoutThread.Start();

            // Pipe stderr: child → parent (async thread)
            var stderrThread = new Thread(() =>
            {
                try
                {
                    Stream error = Console.OpenStandardError();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = process.StandardError.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        error.Write(buffer, 0, read);
                        error.Flush();
                    }
                }
                catch { }
            });
            stderrThread.IsBackground = true;
            stderrThread.Start();

            // Wait for child to exit
            process.WaitForExit();

            // Give output pipes time to flush
            stdoutThread.Join(3000);
            stderrThread.Join(3000);

            return process.ExitCode;
        }
        catch (Exception ex)
        {
            try { Console.Error.WriteLine("[headless-launcher] Error: " + ex.Message); } catch { }
            return 1;
        }
    }
}
