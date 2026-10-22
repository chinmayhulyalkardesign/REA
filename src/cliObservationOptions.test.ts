import { describe, expect, it } from "vitest";
import { z } from "zod";
import { observationDuration } from "./cliObservationOptions.js";
import {
  MAX_WEB_EXECUTION_OBSERVATION_MS,
  observeWebExecutionInputSchema,
} from "./domain/webExecution.js";

describe("observationDuration", () => {
  it("advertises the execution maximum in JSON Schema", () => {
    const schema = observationDuration(
      10_000,
      1,
      MAX_WEB_EXECUTION_OBSERVATION_MS,
    );
    const json = z.toJSONSchema(schema) as {
      maximum?: number;
      minimum?: number;
    };

    expect(json.maximum).toBe(MAX_WEB_EXECUTION_OBSERVATION_MS);
    expect(json.minimum).toBe(1);
  });

  it("accepts the boundary and rejects the next value", () => {
    const schema = observationDuration(
      10_000,
      1,
      MAX_WEB_EXECUTION_OBSERVATION_MS,
    );

    expect(schema.safeParse(MAX_WEB_EXECUTION_OBSERVATION_MS).success).toBe(
      true,
    );
    expect(schema.safeParse(MAX_WEB_EXECUTION_OBSERVATION_MS + 1).success).toBe(
      false,
    );
  });

  it("matches the domain input schema limit", () => {
    const base = { cdp_endpoint: "http://127.0.0.1:1", target_id: "t" };

    expect(
      observeWebExecutionInputSchema.safeParse({
        ...base,
        observation_ms: MAX_WEB_EXECUTION_OBSERVATION_MS + 1,
      }).success,
    ).toBe(false);
  });

  it("keeps other callers at the safe-integer ceiling", () => {
    const json = z.toJSONSchema(observationDuration(500)) as {
      maximum?: number;
    };

    expect(json.maximum).toBe(Number.MAX_SAFE_INTEGER);
  });
});
