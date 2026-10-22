import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  firmwareStagingBudgetRemediation,
  inventoryFirmwareOutput,
} from "./FirmwareFiles.js";
import {
  MAX_FIRMWARE_STAGING_BYTES,
  MAX_FIRMWARE_STAGING_ENTRIES,
} from "../domain/firmware/firmwareAnalysis.js";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const staged = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rea-firmware-budget-"));
  roots.push(root);
  await mkdir(join(root, "rootfs"));
  await writeFile(join(root, "rootfs", "config"), "config bytes");
  return root;
};

const inventory = async (
  root: string,
  maxBytes: number,
  maxEntries: number,
): Promise<AnalysisResourceConstraintError> => {
  const failure = await inventoryFirmwareOutput(
    root,
    maxBytes,
    maxEntries,
    "extract_firmware",
  ).catch((cause: unknown) => cause);
  if (!(failure instanceof AnalysisResourceConstraintError))
    throw new Error(
      `Expected a resource constraint, received ${String(failure)}`,
    );
  return failure;
};

it("reports an exceeded staging entry budget as the caller's entry allowance", async () => {
  const root = await staged();
  // The staged tree holds one directory and one file, so a one-entry budget is exceeded.
  const failure = await inventory(root, 1024, 1);
  expect(failure).toMatchObject({
    operation: "extract_firmware",
    resource: "capacity",
    reportedLimits: { max_output_files: 1 },
    retryable: false,
  });
  expect(projectAnalysisError(failure)).toMatchObject({
    code: "resource_constraint",
    retryable: false,
    details: { reported_limits: { max_output_files: 1 } },
    remediation: { action: expect.stringContaining("max_output_files") },
  });
});

it("reports an exceeded staging byte budget as the caller's byte allowance", async () => {
  const root = await staged();
  const failure = await inventory(root, 4, 1000);
  expect(failure).toMatchObject({
    operation: "extract_firmware",
    resource: "capacity",
    reportedLimits: { max_output_bytes: 4 },
    retryable: false,
  });
  expect(projectAnalysisError(failure)).toMatchObject({
    code: "resource_constraint",
    retryable: false,
    details: {
      resource: "capacity",
      reason: "Staging byte budget exceeded (4)",
      reported_limits: { max_output_bytes: 4 },
    },
    remediation: { action: expect.stringContaining("max_output_bytes") },
  });
});

it.each([
  ["max_output_files", MAX_FIRMWARE_STAGING_ENTRIES],
  ["max_output_bytes", MAX_FIRMWARE_STAGING_BYTES],
] as const)(
  "does not recommend raising %s at its supported maximum",
  (budget, maximum) => {
    const remediation = firmwareStagingBudgetRemediation(budget, maximum);
    expect(remediation).toContain(`maximum ${String(maximum)}`);
    expect(remediation).toContain("smaller firmware byte range");
    expect(remediation).not.toContain(`Increase ${budget}`);
    expect(remediation).toContain(`Raising ${budget} further is not supported`);
  },
);
