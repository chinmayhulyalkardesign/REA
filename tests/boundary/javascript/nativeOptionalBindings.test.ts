import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { analyzeJavaScriptApplication } from "../../../src/application/javascript/JavaScriptApplicationService.js";
import type { JavaScriptApplicationAnalysisResult } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { buildJavaScriptNativeHandoffs } from "../../../src/domain/javascript/javascriptNativeHandoff.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const analyzeFixture = async (source: string) => {
  const fixture = await createTestTempDirectory("rea-native-optional-");
  const scope = new ArtifactResourceScope();
  try {
    await writeFile(join(fixture, "main.cjs"), `${source}\n`);
    await writeFile(
      join(fixture, "addon.node"),
      "inert fixture, never executed",
    );
    const result = await analyzeJavaScriptApplication(
      { input_path: fixture, format: "directory" },
      scope,
    );
    if (!result.ok) throw result.error;
    return result.value
      .normalized_result as unknown as JavaScriptApplicationAnalysisResult;
  } finally {
    await scope.close();
  }
};

it.each([
  ["const addon = CALL;", [], true, false, "require"],
  ["const { load } = CALL;", ["load"], false, false, "require"],
  ["const load = CALL?.load;", ["load"], false, false, "require"],
  ["const load = CALL[key];", [], false, true, "require"],
  ["module.exports = CALL;", [], true, false, "re-export"],
] as const)(
  "preserves optional native requests through the application graph: %s",
  async (template, members, namespaceAccess, dynamicMemberAccess, kind) => {
    for (const call of [
      'require("./addon.node")',
      'require?.("./addon.node")',
    ]) {
      const result = await analyzeFixture(template.replace("CALL", call));
      expect(result.summary.native_addon_bindings).toBe(1);
      expect(result.summary.resolved_native_addon_bindings).toBe(1);
      expect(
        result.graph.edges.filter((edge) => edge.relation === "loads"),
      ).toEqual([
        expect.objectContaining({
          properties: expect.objectContaining({
            kind: "require",
            specifier: "./addon.node",
            resolved_path: "addon.node",
            resolution_status: "resolved",
          }),
        }),
      ]);
      const bindings = result.graph.nodes.filter(
        (node) => node.kind === "native-export",
      );
      expect(bindings).toHaveLength(1);
      expect(bindings[0]?.observations[0]?.properties).toMatchObject({
        specifier: "./addon.node",
        binding_kind: kind,
        requested_members: [...members],
        namespace_access: namespaceAccess,
        dynamic_member_access: dynamicMemberAccess,
        resolved_path: "addon.node",
        native_export_verification: "not-performed",
      });
      expect(
        buildJavaScriptNativeHandoffs(
          result.graph.nodes,
          result.graph.edges,
          [],
        ).flatMap((handoff) => handoff.requested_exports),
      ).toEqual([...members]);
    }
  },
);

it.each([
  'const addon = load?.("./addon.node");',
  "const addon = require?.(path);",
  'const addon = require?.("./addon.node?helper.js");',
])("does not invent native requests for %s", async (source) => {
  const result = await analyzeFixture(source);
  expect(result.summary.native_addon_bindings).toBe(0);
  expect(result.summary.resolved_native_addon_bindings).toBe(0);
  expect(
    result.graph.nodes.filter((node) => node.kind === "native-export"),
  ).toEqual([]);
});
