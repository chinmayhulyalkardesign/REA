import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { serveCli } from "./cliServeHarness.js";

it.each([
  [
    "recover-javascript-sources",
    "additionalPath",
    "--additional-path",
    ["/input.js", "/output"],
  ],
  ["inspect-wasm-artifact", "glue_paths", "--glue_paths", ["input.wasm"]],
  [
    "inspect-wasm-artifact",
    "candidate_paths",
    "--candidate_paths",
    ["input.wasm"],
  ],
] as const)(
  "%s advertises and enforces the %s cardinality",
  async (command, field, option, args) => {
    const result = await serveCli([command, "--schema", "--json"]);
    const schema = JSON.parse(result.stdout);
    const accepts = new Ajv2020({ strict: false }).compile(schema.options);
    const paths = Array.from({ length: 17 }, (_, i) => `selected-${i}.js`);
    expect(accepts({ [field]: paths.slice(0, 16) })).toBe(true);
    expect(accepts({ [field]: paths })).toBe(false);
    const rejected = await serveCli([
      command,
      ...args,
      ...paths.flatMap((p) => [option, p]),
      "--json",
    ]);
    expect(JSON.parse(rejected.stdout)).toMatchObject({
      code: "VALIDATION_ERROR",
    });
  },
);
