import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { parseEvidence } from "../../src/domain/evidence.js";
import { buildManagedPeFixture } from "../../src/dotnet/ManagedPe.fixture.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest.for([
  ["000001", null],
  ["00", "truncated compressed integer"],
  ["0080", "truncated compressed integer"],
  ["00c0", "truncated compressed integer"],
  ["00c000", "truncated compressed integer"],
  ["00c00000", "truncated compressed integer"],
  ["1080", "truncated compressed integer"],
  ["00e0", "reserved compressed integer"],
  ["00ff", "reserved compressed integer"],
] as const)(
  "CLI and MCP preserve the managed signature diagnostic for %s",
  async ([hex, issue], { cli }) => {
    const root = await createTestTempDirectory("rea-managed-signature-");
    const path = join(root, "signature.dll");
    const bytes = buildManagedPeFixture({
      methodSignature: Buffer.from(hex, "hex"),
    });
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(path, bytes);
    const result = await cli.run({
      arguments: ["inspect-managed-members", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const cliEvidence = parseEvidence(result.json);
    const { call } = await connectLocalToolsMcp();
    const response = await call("inspect_managed_members", { path });
    expect(response.isError).not.toBe(true);
    const mcpEvidence = parseEvidence(response.structuredContent);
    expect(mcpEvidence.normalized_result).toEqual(
      cliEvidence.normalized_result,
    );
    for (const evidence of [cliEvidence, mcpEvidence]) {
      expect(evidence.subject?.digest.sha256).toBe(sha256);
      expect(evidence.normalized_result).toMatchObject({
        coverage: { state: issue === null ? "complete" : "partial" },
        methods: [
          expect.objectContaining({
            token: "0x06000001",
            signature: expect.objectContaining({
              parse_status: issue === null ? "decoded" : "malformed",
              issue,
            }),
          }),
        ],
      });
    }
  },
);
