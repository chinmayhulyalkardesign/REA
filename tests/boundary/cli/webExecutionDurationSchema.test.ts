import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { serveCli } from "./cliServeHarness.js";

it("advertises the execution timer range and rejects overflow before connecting", async () => {
  const result = await serveCli([
    "observe-web-execution",
    "--schema",
    "--json",
  ]);
  const schema = JSON.parse(result.stdout);
  const accepts = new Ajv2020({ strict: false }).compile(schema.options);
  expect(accepts({ observationMs: 2_147_483_647 })).toBe(true);
  expect(accepts({ observationMs: 2_147_483_648 })).toBe(false);
  expect(accepts({ observationMs: 0 })).toBe(false);
  const rejected = await serveCli([
    "observe-web-execution",
    "http://127.0.0.1:1",
    "target",
    "--observation-ms",
    "2147483648",
    "--json",
  ]);
  expect(JSON.parse(rejected.stdout)).toMatchObject({
    code: "VALIDATION_ERROR",
  });
});
