import { expect, it } from "vitest";

import { finishAnalysisCommand } from "../../../src/cli/finishAnalysisCommand.js";
import { AnalysisOutputError } from "../../../src/domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { err, ok } from "../../../src/domain/result.js";
import { scriptCaptureEvidenceFixture } from "../../fixtures/webScriptCapture.js";

it("preserves producer-owned cleanup failure when service close does not resolve it", async () => {
  const evidence = scriptCaptureEvidenceFixture();
  const failure = new ProviderCleanupError(
    "fixture-provider",
    ["producer-owned-resource"],
    { reason: "producer cleanup was not confirmed" },
    { operation: "inspect_web_page", partialObservation: evidence },
  );
  const expected = projectAnalysisError(failure);
  const result = await finishAnalysisCommand(
    async () => err(failure),
    { close: async () => {} },
    "fixture-provider",
    "inspect_web_page",
    new AbortController().signal,
  );

  expect(result).toEqual(expected);
  expect(failure.cleanupIncomplete).toBe(true);
});

it("returns completed partial Evidence when cancellation arrives during close", async () => {
  const evidence = scriptCaptureEvidenceFixture();
  const controller = new AbortController();
  const result = await finishAnalysisCommand(
    async () => ok(evidence),
    {
      close: async () => {
        controller.abort(new Error("cancelled during close"));
      },
    },
    "fixture-provider",
    "capture_browser_scenario",
    controller.signal,
  );

  expect(result).toMatchObject({
    code: "cancelled",
    details: { partial_observation: { evidence_id: evidence.evidence_id } },
  });
});

it("preserves the primary operation error when cancellation arrives during close", async () => {
  const controller = new AbortController();
  const result = await finishAnalysisCommand(
    async () =>
      err(new AnalysisOutputError("inspect_web_page", "primary failure")),
    {
      close: async () => {
        controller.abort();
      },
    },
    "fixture-provider",
    "inspect_web_page",
    controller.signal,
  );

  expect(result).toMatchObject({
    code: "unreadable_output",
    details: {
      reason: "primary failure",
      operation: "inspect_web_page",
    },
  });
});

it("promotes resolved cleanup-only partial Evidence after final close", async () => {
  const evidence = scriptCaptureEvidenceFixture();
  const failure = new AnalysisOutputError(
    "inspect_web_page",
    "verified output cleanup remains incomplete",
    {
      cleanup: {
        reason: "fixture retained descriptor",
        resources: ["fixture-descriptor"],
      },
      partialObservation: evidence,
      cleanupOnly: true,
    },
  );
  const result = await finishAnalysisCommand(
    async () => err(failure),
    {
      close: async () => {
        failure.resolveCleanup();
      },
    },
    "fixture-provider",
    "inspect_web_page",
    new AbortController().signal,
    undefined,
    (partial) => (partial === evidence ? evidence : undefined),
  );

  expect(result).toEqual(evidence);
  expect(failure.cleanupIncomplete).toBe(false);
});

it("applies late cancellation after promoting resolved cleanup-only Evidence", async () => {
  const evidence = scriptCaptureEvidenceFixture();
  const failure = new AnalysisOutputError(
    "inspect_web_page",
    "verified output cleanup remains incomplete",
    {
      cleanup: {
        reason: "fixture retained descriptor",
        resources: ["fixture-descriptor"],
      },
      partialObservation: evidence,
      cleanupOnly: true,
    },
  );
  const controller = new AbortController();
  const reason = Object.freeze({ kind: "cancelled-after-cleanup", nonce: 101 });
  const result = await finishAnalysisCommand(
    async () => err(failure),
    {
      close: async () => {
        failure.resolveCleanup();
        controller.abort(reason);
      },
    },
    "fixture-provider",
    "inspect_web_page",
    controller.signal,
    undefined,
    (partial) => (partial === evidence ? evidence : undefined),
  );

  expect(result).toMatchObject({
    code: "cancelled",
    category: "cancelled",
    details: {
      partial_observation: { evidence_id: evidence.evidence_id },
    },
  });
  expect(failure.cleanupIncomplete).toBe(false);
});
