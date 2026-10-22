import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { recording } from "./fixtures.ts";

const cli = fileURLToPath(new URL("./cli.js", import.meta.url));

test("CLI preserves inspection results and primary errors when close fails", async (t) => {
  const folder = mkdtempSync(join(tmpdir(), "mcap-prototype-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const path = join(folder, "input.mcap");
  const preload = join(folder, "deny-close.mjs");
  writeFileSync(
    preload,
    `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const open = fs.openSync;
const close = fs.closeSync;
let target;
fs.openSync = (...args) => {
  const fd = open(...args);
  if (args[0] === process.argv[2]) target = fd;
  return fd;
};
fs.closeSync = (fd) => {
  if (fd === target) throw new Error('injected close denial');
  return close(fd);
};
syncBuiltinESMExports();
`,
  );
  for (const bytes of [await recording(), Buffer.from("malformed recording")]) {
    writeFileSync(path, bytes);
    const run = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(preload).href, cli, path],
      { encoding: "utf8" },
    );
    assert.equal(run.status, 1, run.stderr);
    const output: unknown = JSON.parse(run.stdout);
    assert.ok(output !== null && typeof output === "object" && "ok" in output);
    assert.equal(output.ok, false);
    assert.ok("cleanup_error" in output && "error" in output);
    assert.match(JSON.stringify(output.cleanup_error), /injected close denial/);
    assert.match(
      JSON.stringify(output),
      bytes.length > 100 ? /"message_count":"2"/ : /"reader_rejected"/,
    );
  }
});

test("CLI rejects mutation after its final read and closes on read failure", async (t) => {
  const folder = mkdtempSync(join(tmpdir(), "mcap-prototype-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const path = join(folder, "input.mcap");
  const preload = join(folder, "read-fault.mjs");
  writeFileSync(
    preload,
    `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const open = fs.openSync, read = fs.readSync, close = fs.closeSync;
let target, calls = 0, closed = false;
fs.openSync = (...args) => {
  const fd = open(...args);
  if (args[0] === process.argv[2]) target = fd;
  return fd;
};
fs.readSync = (...args) => {
  if (args[0] !== target) return read(...args);
  if (process.env.MCAP_TEST_FAULT === 'read') throw new Error('injected read denial');
  const bytes = read(...args);
  if (++calls === 4) fs.appendFileSync(process.argv[2], 'x');
  return bytes;
};
fs.closeSync = (fd) => {
  close(fd);
  if (fd === target) closed = true;
};
process.on('exit', () => { if (!closed) process.exitCode = 9; });
syncBuiltinESMExports();
`,
  );
  for (const fault of ["read", "mutation", "parse-and-mutation"]) {
    const bytes = await recording();
    if (fault === "parse-and-mutation")
      bytes.writeUInt8(
        bytes.readUInt8(bytes.length - 12) ^ 1,
        bytes.length - 12,
      );
    writeFileSync(path, bytes);
    const run = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(preload).href, cli, path],
      {
        encoding: "utf8",
        env: { ...process.env, MCAP_TEST_FAULT: fault },
      },
    );
    assert.equal(run.status, 1, run.stderr);
    const output: unknown = JSON.parse(run.stdout);
    assert.ok(
      output !== null && typeof output === "object" && "error" in output,
    );
    assert.match(
      JSON.stringify(output.error),
      fault === "read"
        ? /"kind":"io"/
        : fault === "mutation"
          ? /"kind":"changed"/
          : /"kind":"reader_rejected"/,
    );
    if (fault !== "read") {
      assert.ok("read_ranges" in output);
      assert.ok(
        Array.isArray(output.read_ranges) && output.read_ranges.length === 4,
      );
    }
    if (fault === "parse-and-mutation") {
      assert.ok("file_error" in output);
      assert.match(JSON.stringify(output.file_error), /"kind":"changed"/);
    }
  }
});
