import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
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

test("cmd_run terminates prompt-style commands and enforces timeouts", async (t) => {
  const { client } = await connectClient(t, {
    command: "node",
    args: ["index.js"],
  });

  const promptStarted = Date.now();
  const promptResult = await client.callTool({
    name: "cmd_run",
    arguments: {
      command: "set /p value=Nhap:",
      cwd: repoRoot,
      timeout: 1500,
    },
  });
  const promptElapsed = Date.now() - promptStarted;
  const promptText = resultText(promptResult);

  assert.ok(promptElapsed < 1200, `Expected prompt command to fail fast, got ${promptElapsed}ms`);
  assert.match(promptText, /Nhap:/);
  assert.match(promptText, /\[EXIT 1\]/);

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
