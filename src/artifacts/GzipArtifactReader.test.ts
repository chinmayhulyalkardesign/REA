import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { GzipArtifactReader } from "./GzipArtifactReader.js";

describe("GzipArtifactReader", () => {
  it("extracts and streams compressed content correctly", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-test-"));
    const gzipPath = join(tempDir, "solve_me.gz");
    const payload = Buffer.from("ELF binary test payload for CTF challenge");
    const compressed = gzipSync(payload);

    await writeFile(gzipPath, compressed);

    const reader = new GzipArtifactReader(gzipPath);
    expect(reader.format).toBe("gzip");

    const entries = [];
    for await (const entry of reader.entries()) {
      entries.push(entry);
    }

    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe("solve_me");
    expect(entries[0]!.kind).toBe("file");
    expect(entries[0]!.declaredSize).toBeNull();

    const stream = await reader.open(entries[0]!);
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
    }
    const result = Buffer.concat(chunks);
    expect(result.toString("utf-8")).toBe(
      "ELF binary test payload for CTF challenge",
    );

    await reader.close();
    await rm(tempDir, { recursive: true, force: true });
  });
});
