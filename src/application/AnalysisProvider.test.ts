import { expect, it } from "vitest";

import {
  createAnalysisExecution,
  createAnalysisExecutionEvidence,
} from "./AnalysisProvider.js";
import { isImmutableEvidence } from "../domain/evidence.js";

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

it("preserves selected Evidence authority alongside immutable snapshot ownership", () => {
  const execution = createAnalysisExecution(
    { entries: ["observed"] },
    PROVIDER,
  );
  const evidence = createAnalysisExecutionEvidence(
    "perform_adb_ui_action",
    { serial: "selected-device" },
    execution,
    "observed",
    { authority: "controlled-replay", immutable: true },
  );

  expect(evidence).toMatchObject({
    authority: "controlled-replay",
    parameters: { serial: "selected-device" },
    normalized_result: { entries: ["observed"] },
  });
  expect(isImmutableEvidence(evidence)).toBe(true);
  expect(Object.isFrozen(evidence.normalized_result)).toBe(true);
  expect(
    createAnalysisExecutionEvidence("inspect", {}, execution, "observed", {
      immutable: true,
    }).authority,
  ).toBe("shipped-artifact");
});
