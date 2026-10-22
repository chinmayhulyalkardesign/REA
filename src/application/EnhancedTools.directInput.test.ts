import assert from "node:assert/strict";
import { describe, it } from "vitest";

import { createAnalysisExecution } from "./AnalysisProvider.js";
import { EnhancedTools } from "./EnhancedTools.js";

describe("EnhancedTools direct-call input validation", () => {
  it("rejects undeclared properties for get_objc_protocols before the provider runs", async () => {
    let calls = 0;
    const tools = new EnhancedTools({
      execute: async () => {
        calls += 1;
        return {
          ok: true,
          value: createAnalysisExecution([], {
            id: "fixture",
            name: "fixture",
            version: "1",
          }),
        };
      },
    });

    const valid = await tools.execute("get_objc_protocols", {});
    assert.equal(valid.ok, true);
    assert.equal(calls, 1);

    const extra = await tools.execute("get_objc_protocols", {
      unexpected: "benign",
    });
    assert.equal(extra.ok, false);
    assert.equal(extra.error._tag, "AnalysisInputError");
    assert.equal(calls, 1);

    const classes = await tools.execute("get_objc_classes", {
      unexpected: "benign",
    });
    assert.equal(classes.ok, false);
    assert.equal(classes.error._tag, "AnalysisInputError");
    assert.equal(calls, 1);
  });
});
