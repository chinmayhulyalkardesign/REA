import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createEvidence } from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const PROVIDER = { id: "fixture", name: "Fixture", version: "1" } as const;

const leakedBundle = () =>
  createEvidenceBundle([
    createEvidence(undefined, PROVIDER, {
      operation: "observe",
      parameters: {},
      result: {
        header: "Bearer abc123def456ghi789",
        note: "cached at /Users/alice/Downloads/prog.exe",
      },
      confidence: "observed",
      authority: "shipped-artifact",
    }),
  ]);

const cleanBundle = () =>
  createEvidenceBundle([
    createEvidence(undefined, PROVIDER, {
      operation: "observe",
      parameters: {},
      result: { observed: { address: "0x1000", name: "main" } },
      confidence: "observed",
      authority: "shipped-artifact",
    }),
  ]);

cliTest(
  "reports leaked credentials as failures and local paths as warnings",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-evidence-audit-leak-");
    const path = join(root, "bundle.json");
    await writeFile(path, JSON.stringify(leakedBundle()));
    const result = await cli.run({
      arguments: ["evidence-audit", path, "--json"],
    });
    // The audit command succeeds as a command; findings are report data,
    // not a command error, so the exit code stays zero for scriptability.
    expect(result.exitCode).toBe(0);
    expect(result.json).toMatchObject({
      failures: 1,
      warnings: 1,
      scanned_records: 1,
      scanned_unknowns: 0,
    });
    const report = result.json as {
      findings: ReadonlyArray<{ rule_id: string }>;
    };
    const findings = report.findings;
    expect(findings.map(({ rule_id }) => rule_id).sort()).toEqual([
      "credential-bearer-token",
      "local-path-posix-home",
    ]);
    // The report must never echo the matched secret or the home directory.
    expect(JSON.stringify(result.json)).not.toContain("abc123def456ghi789");
    expect(JSON.stringify(result.json)).not.toContain("alice");
  },
);

cliTest("exits zero for a clean bundle", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-evidence-audit-clean-");
  const path = join(root, "bundle.json");
  await writeFile(path, JSON.stringify(cleanBundle()));
  const result = await cli.run({
    arguments: ["evidence-audit", path, "--json"],
  });
  expect(result.exitCode).toBe(0);
  expect(result.json).toMatchObject({
    failures: 0,
    warnings: 0,
    findings: [],
  });
});

cliTest(
  "rejects a non-bundle JSON input with the wrong input file kind",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-evidence-audit-input-");
    const path = join(root, "record.json");
    await writeFile(path, JSON.stringify(cleanBundle().records[0] ?? {}));
    const result = await cli.run({
      arguments: ["evidence-audit", path, "--json"],
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "invalid_request",
      category: "invalid_input",
    });
  },
);
