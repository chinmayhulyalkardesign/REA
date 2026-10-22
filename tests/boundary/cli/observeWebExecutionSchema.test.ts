import { expect, it } from "vitest";

import { MAX_WEB_EXECUTION_OBSERVATION_MS } from "../../../src/domain/webExecution.js";
import { serveCli } from "./cliServeHarness.js";

interface AdvertisedSchema {
  readonly options: {
    readonly properties: {
      readonly observationMs: {
        readonly minimum?: number;
        readonly maximum?: number;
      };
    };
  };
}

it("advertises the enforced observation maximum through observe-web-execution --schema", async () => {
  const result = await serveCli([
    "observe-web-execution",
    "--schema",
    "--json",
  ]);
  expect(result.exitCode).toBe(0);
  const { observationMs } = (JSON.parse(result.stdout) as AdvertisedSchema)
    .options.properties;
  expect(observationMs.minimum).toBe(1);
  expect(observationMs.maximum).toBe(2_147_483_647);
  expect(observationMs.maximum).toBe(MAX_WEB_EXECUTION_OBSERVATION_MS);
});
