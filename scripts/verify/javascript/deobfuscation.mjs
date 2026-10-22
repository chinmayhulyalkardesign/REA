#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../../dist/domain/evidence.js";
import { javascriptDeobfuscationResultSchema } from "../../../dist/domain/javascript/javascriptDeobfuscation.js";
import { mcpTextValue } from "../../lib/mcp-verifier-results.mjs";

const AUDITED_REVISION = "42ca30ade268b8c9abf9277feffa3cd23f533518";
const command = process.env.REA_JS_REDOX_COMMAND;
if (!command)
  throw new Error(
    "Provide REA_JS_REDOX_COMMAND for the pinned js-redox deobfuscate-safe 0.1.1 binary",
  );

const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("../../rea.mjs", import.meta.url));
const root = await mkdtemp(join(tmpdir(), "rea-real-js-redox-"));
const source = join(root, "input.mjs");
const environment = { ...process.env, REA_LOG_LEVEL: "silent" };
const run = promisify(execFile);
const fingerprint = (bytes) => createHash("sha256").update(bytes).digest("hex");
const engineSha256 = fingerprint(await readFile(command));
const inputText =
  'const table = ["hello", "world"];\nconsole.log(table[0] + " " + table[1]);\n';
await writeFile(source, inputText, "utf8");
const inputSha256 = fingerprint(Buffer.from(inputText, "utf8"));

const cli = async (output) => {
  const { stdout } = await run(
    process.execPath,
    [entrypoint, "deobfuscate-javascript-source", source, output, "--json"],
    {
      env: environment,
      timeout: 150_000,
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  return parseEvidence(JSON.parse(stdout));
};

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const client = new Client({ name: "real-js-redox", version: "1" });
const mcp = async (output) => {
  const response = await client.callTool(
    {
      name: "deobfuscate_javascript_source",
      arguments: { path: source, output_directory: output },
    },
    { timeout: 150_000 },
  );
  assert.notEqual(response.isError, true, mcpTextValue(response));
  return parseEvidence(JSON.parse(mcpTextValue(response)));
};

const results = [];
try {
  await client.connect(transport);
  for (const surface of ["cli", "stdio_mcp"]) {
    const outputRoot = join(root, surface);
    const evidence =
      surface === "cli" ? await cli(outputRoot) : await mcp(outputRoot);
    const result = javascriptDeobfuscationResultSchema.parse(
      evidence.normalized_result,
    );
    assert.equal(evidence.provider.id, "js-redox");
    assert.equal(evidence.provider.version, "0.1.1");
    assert.equal(evidence.authority, "shipped-artifact");
    assert.equal(evidence.confidence, "derived");
    assert.equal(result.status, "changed");
    assert.equal(result.source.path, source);
    assert.equal(result.source.sha256, inputSha256);
    assert.equal(result.proof.input_sha256, inputSha256);
    assert.equal(result.proof.output_sha256, result.output.sha256);

    for (const artifact of [
      result.source.published_copy,
      result.output,
      result.report,
      result.manifest,
    ]) {
      const bytes = await readFile(artifact.path);
      assert.equal(bytes.length, artifact.bytes);
      assert.equal(fingerprint(bytes), artifact.sha256);
    }

    const report = JSON.parse(await readFile(result.report.path, "utf8"));
    assert.equal(report.schema, "js-safe-deobfuscate/v1");
    assert.equal(report.source_mode, "module");
    assert.match(result.source.published_copy.path, /\/inputs\/source\.mjs$/u);
    assert.match(result.output.path, /\/deobfuscated\/source\.mjs$/u);
    assert.equal(report.input_sha256, result.proof.input_sha256);
    assert.equal(report.output_sha256, result.proof.output_sha256);
    assert.equal(report.analysis_source_sha256, result.output.sha256);
    assert.equal(report.safe_static_only, true);
    assert.equal(report.presentation_formatted, false);
    assert.equal(report.runtime_semantics_preserved_by_design, true);

    const manifest = JSON.parse(await readFile(result.manifest.path, "utf8"));
    assert.equal(manifest.engine.version, "0.1.1");
    assert.equal(manifest.engine.sha256, engineSha256);
    assert.equal(manifest.engine.audited_source_revision, AUDITED_REVISION);
    assert.equal(manifest.engine.executed_source_revision, null);
    assert.equal(
      manifest.resource_limiter.resolved_path,
      await realpath("/usr/bin/prlimit"),
    );
    for (const phase of ["version", "execution"]) {
      const limiter = manifest.resource_limiter.runs[phase];
      assert.equal(limiter.snapshot_sha256, manifest.resource_limiter.sha256);
      assert.ok(
        limiter.arguments.includes("--"),
        `Expected ${phase} limiter argv to contain the command separator`,
      );
    }

    const original = await run(process.execPath, [source], {
      env: environment,
      timeout: 10_000,
    });
    const transformed = await run(process.execPath, [result.output.path], {
      env: environment,
      timeout: 10_000,
    });
    assert.equal(transformed.stdout, original.stdout);
    assert.equal(transformed.stderr, original.stderr);

    results.push({
      surface,
      status: result.status,
      input_sha256: result.proof.input_sha256,
      output_sha256: result.proof.output_sha256,
      engine_sha256: engineSha256,
      transforms: report.transforms,
      verified: true,
    });
  }
} finally {
  await client.close();
  await transport.close();
  await rm(root, { recursive: true, force: true });
}

console.log(
  JSON.stringify({
    engine: "js-redox deobfuscate-safe 0.1.1",
    audited_revision: AUDITED_REVISION,
    results,
    verified: true,
  }),
);
