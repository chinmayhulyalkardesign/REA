import { expect, it } from "vitest";

import {
  createAnalysisExecution,
  createAnalysisExecutionEvidence,
} from "./AnalysisProvider.js";
import { resolveAnalysisDocument } from "./AnalysisDocument.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { createEvidence, parseEvidence } from "../domain/evidence.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import { err, ok } from "../domain/result.js";

const PROVIDER = { id: "fixture", name: "Fixture", version: "1" };

it("records no raw result unless the provider supplies a distinct one", () => {
  const result = { entries: [{ value: "normalized" }] };

  expect(createAnalysisExecution(result, PROVIDER)).toMatchObject({
    result,
    rawResult: null,
  });
  expect(
    createAnalysisExecution(result, PROVIDER, {
      rawResult: { stdout: "raw" },
    }).rawResult,
  ).toEqual({ stdout: "raw" });
  expect(
    createAnalysisExecution(result, PROVIDER, { rawResult: null }).rawResult,
  ).toBeNull();
});

it("carries the execution's analysis profile into the composed Evidence", () => {
  const profile = createAnalysisProfile(PROVIDER, { mode: "fixture" });
  const execution = createAnalysisExecution("selected", PROVIDER, {
    analysisProfile: profile,
  });
  const evidence = createAnalysisExecutionEvidence(
    "current_document",
    {},
    execution,
    "observed",
  );
  expect(evidence.analysis_profile).toEqual(profile);
});

it("keeps analysis_profile null when the execution has no profile", () => {
  const execution = createAnalysisExecution("selected", PROVIDER);
  const evidence = createAnalysisExecutionEvidence(
    "current_document",
    {},
    execution,
    "observed",
  );
  expect(evidence.analysis_profile).toBeNull();
  const control = createEvidence(undefined, PROVIDER, {
    operation: "current_document",
    parameters: {},
    result: execution.result,
    rawResult: execution.rawResult,
    limitations: execution.limitations,
    locations: execution.locations,
    confidence: "observed",
  });
  expect(evidence.evidence_id).toBe(control.evidence_id);
});

it("converges evidence_id with a directly projected control sharing the profile", () => {
  const profile = createAnalysisProfile(PROVIDER, { mode: "fixture" });
  const execution = createAnalysisExecution("selected", PROVIDER, {
    analysisProfile: profile,
    rawResult: { source: "fixture" },
    limitations: ["fixture only"],
  });
  const evidence = createAnalysisExecutionEvidence(
    "current_document",
    {},
    execution,
    "observed",
  );
  const control = createEvidence(undefined, PROVIDER, {
    operation: "current_document",
    parameters: {},
    result: execution.result,
    rawResult: execution.rawResult,
    limitations: execution.limitations,
    locations: execution.locations,
    confidence: "observed",
    analysisProfile: profile,
  });
  expect(evidence.evidence_id).toBe(control.evidence_id);
});

it("preserves the completed execution's analysis profile on late cancellation", async () => {
  const controller = new AbortController();
  const reason = { request: "late selection" };
  const profile = createAnalysisProfile(PROVIDER, { mode: "fixture" });
  const execution = createAnalysisExecution("selected", PROVIDER, {
    analysisProfile: profile,
  });
  const result = await resolveAnalysisDocument(
    {
      execute: async (operation) => {
        controller.abort(reason);
        return operation === "current_document"
          ? ok(execution)
          : err(
              new AnalysisCapabilityUnavailableError(
                PROVIDER.id,
                operation,
                "No current UI selection",
              ),
            );
      },
    },
    undefined,
    controller.signal,
  );
  if (result.ok) throw new Error("expected cancelled completion");
  expect(result.error).toBeInstanceOf(AnalysisCancelledError);
  expect(result.error.cause).toBe(reason);
  const partial = parseEvidence(result.error.partialObservation);
  expect(partial.analysis_profile).toEqual(profile);
  const control = createEvidence(undefined, PROVIDER, {
    operation: "current_document",
    parameters: {},
    result: execution.result,
    rawResult: execution.rawResult,
    limitations: execution.limitations,
    locations: execution.locations,
    confidence: "observed",
    analysisProfile: profile,
  });
  expect(partial.evidence_id).toBe(control.evidence_id);
});

it("keeps analysis_profile null on late cancellation when the producer has none", async () => {
  const controller = new AbortController();
  const result = await resolveAnalysisDocument(
    {
      execute: async (operation) => {
        controller.abort({ request: "late selection" });
        return operation === "current_document"
          ? ok(createAnalysisExecution("selected", PROVIDER))
          : err(
              new AnalysisCapabilityUnavailableError(
                PROVIDER.id,
                operation,
                "No current UI selection",
              ),
            );
      },
    },
    undefined,
    controller.signal,
  );
  if (result.ok) throw new Error("expected cancelled completion");
  expect(result.error).toBeInstanceOf(AnalysisCancelledError);
  expect(
    parseEvidence(result.error.partialObservation).analysis_profile,
  ).toBeNull();
});
