import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function connectClient(t, serverParams) {
  const transport = new StdioClientTransport({
    cwd: repoRoot,
    stderr: "pipe",
    ...serverParams,
  });

  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const client = new Client({ name: "mcp-cmd-tests", version: "1.0.0" });
  t.after(async () => {
    await transport.close().catch(() => { });
  });

  await client.connect(transport);
  return { client, stderr };
}

function resultText(result) {
  return result.content
    ?.map((item) => ("text" in item ? item.text : ""))
    .filter(Boolean)
    .join("\n") ?? "";
}

function extractFirstPid(text) {
  const match = text.match(/(?:^|\n)(\d{2,})(?:\n|$)/);
  return match ? Number(match[1]) : null;
}

function processExists(pid) {
  const query = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id`,
    ],
    { cwd: repoRoot, encoding: "utf8", windowsHide: true }
  );

  return query.stdout.trim() === String(pid);
}

function listProcessIdsByCommandMatch(matchText) {
  const escaped = matchText.replace(/'/g, "''");
  const query = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Get-CimInstance Win32_Process -Filter "Name='ping.exe'" | Where-Object { $_.CommandLine -like '*${escaped}*' } | Select-Object -ExpandProperty ProcessId`,
    ],
    { cwd: repoRoot, encoding: "utf8", windowsHide: true }
  );

  return new Set(
    query.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^\d+$/.test(line))
      .map((line) => Number(line))
  );
}

test("cmd_run terminates prompt-style commands and enforces timeouts", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const promptCases = [
    { command: "set /p value=Nhap:", expected: /Nhap:/ },
    { command: "pause", expected: /Press any key to continue/i },
    { command: "more", expected: /\[EXIT 0\]/ },
    { command: "choice /c YN /n", expected: /ERROR:/i },
  ];

  for (const { command, expected } of promptCases) {
    const promptStarted = Date.now();
    const promptResult = await client.callTool({
      name: "cmd_run",
      arguments: {
        command,
        cwd: repoRoot,
        timeout: 1500,
      },
    });
    const promptElapsed = Date.now() - promptStarted;
    const promptText = resultText(promptResult);

    assert.ok(promptElapsed < 1500, `Expected '${command}' to fail fast, got ${promptElapsed}ms`);
    assert.match(promptText, expected);
  }

  const timeoutStarted = Date.now();
  const timeoutResult = await client.callTool({
    name: "cmd_run",
    arguments: {
      command: "ping -t 127.0.0.1",
      cwd: repoRoot,
      timeout: 1200,
    },
  });
  const timeoutElapsed = Date.now() - timeoutStarted;
  const timeoutText = resultText(timeoutResult);

  assert.ok(timeoutElapsed < 2600, `Expected timeout command to resolve quickly, got ${timeoutElapsed}ms`);
  assert.match(timeoutText, /\[TIMEOUT\] Killed after 1200ms/);
});

test("cmd_run kills spawned child trees on timeout", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });
  const marker = "127.0.0.77";
  const before = listProcessIdsByCommandMatch(marker);

  const result = await client.callTool({
    name: "cmd_run",
    arguments: {
      command: `start "" /b ping -t ${marker}`,
      cwd: repoRoot,
      timeout: 1200,
    },
  });
  const text = resultText(result);

  assert.match(text, /\[TIMEOUT\]/);

  await delay(500);
  const after = listProcessIdsByCommandMatch(marker);
  assert.deepEqual(after, before, `Expected no lingering detached ping.exe processes for ${marker}`);
});

test("powershell_run returns plain text errors and no CLIXML noise", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const promptResult = await client.callTool({
    name: "powershell_run",
    arguments: {
      command: "Read-Host 'Nhap'",
      cwd: repoRoot,
      timeout: 1500,
    },
  });
  const promptText = resultText(promptResult);

  assert.doesNotMatch(promptText, /CLIXML/i);
  assert.match(promptText, /NonInteractive mode/i);
  assert.match(promptText, /\[EXIT 1\]/);

  const timeoutResult = await client.callTool({
    name: "powershell_run",
    arguments: {
      command: "while ($true) { Start-Sleep -Milliseconds 200 }",
      cwd: repoRoot,
      timeout: 1200,
    },
  });
  const timeoutText = resultText(timeoutResult);

  assert.doesNotMatch(timeoutText, /CLIXML/i);
  assert.match(timeoutText, /\[TIMEOUT\] Killed after 1200ms/);
});

test("powershell_run kills child processes it spawns before timing out", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const result = await client.callTool({
    name: "powershell_run",
    arguments: {
      command: "$p = Start-Process ping -ArgumentList '-t','127.0.0.1' -WindowStyle Hidden -PassThru; $p.Id; Start-Sleep -Seconds 60",
      cwd: repoRoot,
      timeout: 1200,
    },
  });
  const text = resultText(result);
  const pid = extractFirstPid(text);

  assert.ok(pid, `Expected child PID in output, got: ${text}`);
  assert.match(text, /\[TIMEOUT\]/);

  await delay(500);
  assert.equal(processExists(pid), false, `Expected spawned PowerShell child PID ${pid} to be terminated`);
});

test("cmd_batch applies timeout per command and respects stop/continue behavior", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const stopResult = await client.callTool({
    name: "cmd_batch",
    arguments: {
      commands: [
        { command: "echo before-timeout", cwd: repoRoot },
        { command: "ping -t 127.0.0.1", cwd: repoRoot },
        { command: "echo after-timeout", cwd: repoRoot },
      ],
      timeout: 1200,
      continueOnError: false,
    },
  });
  const stopText = resultText(stopResult);

  assert.match(stopText, /before-timeout/);
  assert.match(stopText, /\[TIMEOUT\]/);
  assert.match(stopText, /\[STOPPED\] at command 2/);
  assert.doesNotMatch(stopText, /\[3\/3\] echo after-timeout/);

  const continueResult = await client.callTool({
    name: "cmd_batch",
    arguments: {
      commands: [
        { command: "echo before-timeout", cwd: repoRoot },
        { command: "ping -t 127.0.0.1", cwd: repoRoot },
        { command: "echo after-timeout", cwd: repoRoot },
      ],
      timeout: 1200,
      continueOnError: true,
    },
  });
  const continueText = resultText(continueResult);

  assert.match(continueText, /\[2\/3\] ping -t 127\.0\.0\.1/);
  assert.match(continueText, /\[TIMEOUT\]/);
  assert.match(continueText, /\[3\/3\] echo after-timeout/);
  assert.match(continueText, /after-timeout/);
});

test("diagnostic tools respond without hanging", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const systemInfo = resultText(await client.callTool({ name: "system_info", arguments: {} }));
  assert.match(systemInfo, /OS:/);

  const processList = resultText(await client.callTool({ name: "process_list", arguments: { filter: "node" } }));
  assert.match(processList, /ProcessId|PID|node\.exe/i);

  const securityRules = resultText(await client.callTool({ name: "show_security_rules", arguments: {} }));
  assert.match(securityRules, /Security Configuration/);
  assert.match(securityRules, /Per-request timeout includes queue wait/);
});

test("server entrypoints work through direct node, wrapper, and launcher", async (t) => {
  const launches = [
    { name: "node", command: "node", args: ["index.js"] },
    { name: "wrapper", command: "node", args: ["wrapper.js", "node", "index.js"] },
  ];

  if (existsSync(resolve(repoRoot, "launcher.exe"))) {
    launches.push({
      name: "launcher",
      command: "launcher.exe",
      args: ["node", "index.js"],
      env: { HEADLESS_TIMEOUT_SEC: "30" },
    });
  }

  for (const launch of launches) {
    await t.test(launch.name, async (subtest) => {
      const { client } = await connectClient(subtest, launch);
      const result = await client.callTool({
        name: "cmd_run",
        arguments: {
          command: `echo ${launch.name}-ok`,
          cwd: repoRoot,
          timeout: 3000,
        },
      });

      assert.match(resultText(result), new RegExp(`${launch.name}-ok`));
      assert.match(resultText(result), /\[EXIT 0\]/);
    });
  }
});

test("parallel executions are queued instead of killing in-flight work", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const started = Date.now();
  const results = await Promise.all(
    [1, 2, 3, 4].map(async (job) => {
      const result = await client.callTool({
        name: "powershell_run",
        arguments: {
          command: `Start-Sleep -Seconds 2; Write-Output job${job}`,
          cwd: repoRoot,
          timeout: 5000,
        },
      });

      return { job, text: resultText(result) };
    })
  );
  const elapsed = Date.now() - started;

  assert.ok(elapsed >= 3500, `Expected queued execution to take at least one extra slot window, got ${elapsed}ms`);
  assert.ok(elapsed < 9000, `Expected queued execution to finish within bounded time, got ${elapsed}ms`);

  for (const { job, text } of results) {
    assert.match(text, new RegExp(`job${job}`));
    assert.match(text, /\[EXIT 0\]/);
    assert.doesNotMatch(text, /CLIXML/i);
  }
});

test("queued requests honor their own total timeout budget", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const blockerCalls = [1, 2, 3].map((job) =>
    client.callTool({
      name: "powershell_run",
      arguments: {
        command: `Start-Sleep -Seconds 2; Write-Output blocker${job}`,
        cwd: repoRoot,
        timeout: 4000,
      },
    })
  );

  const queuedStarted = Date.now();
  const queuedCall = client.callTool({
    name: "powershell_run",
    arguments: {
      command: "Write-Output queued-should-timeout",
      cwd: repoRoot,
      timeout: 900,
    },
  });
  const queuedResult = await queuedCall;
  const queuedElapsed = Date.now() - queuedStarted;
  const queuedText = resultText(queuedResult);

  assert.ok(queuedElapsed < 2200, `Expected queued timeout to resolve within its own budget, got ${queuedElapsed}ms`);
  assert.match(queuedText, /\[TIMEOUT\] Queue wait exceeded 900ms before process start/);
  assert.doesNotMatch(queuedText, /queued-should-timeout/);

  const blockerResults = await Promise.all(blockerCalls);
  for (const [index, result] of blockerResults.entries()) {
    const text = resultText(result);
    assert.match(text, new RegExp(`blocker${index + 1}`));
    assert.match(text, /\[EXIT 0\]/);
  }
});

test("queued requests with enough budget still succeed after waiting", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const blockers = [1, 2, 3].map((job) =>
    client.callTool({
      name: "powershell_run",
      arguments: {
        command: `Start-Sleep -Milliseconds 1500; Write-Output gate${job}`,
        cwd: repoRoot,
        timeout: 3500,
      },
    })
  );

  const queuedStarted = Date.now();
  const queued = client.callTool({
    name: "powershell_run",
    arguments: {
      command: "Start-Sleep -Milliseconds 800; Write-Output queued-success",
      cwd: repoRoot,
      timeout: 4500,
    },
  });

  const queuedResult = await queued;
  const queuedElapsed = Date.now() - queuedStarted;
  const queuedText = resultText(queuedResult);

  assert.ok(queuedElapsed >= 1800, `Expected queued request to wait for a slot, got ${queuedElapsed}ms`);
  assert.ok(queuedElapsed < 5600, `Expected queued request to finish within total budget, got ${queuedElapsed}ms`);
  assert.match(queuedText, /queued-success/);
  assert.match(queuedText, /\[EXIT 0\]/);

  await Promise.all(blockers);
});
