import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("native addon type-only TypeScript imports", () => {
  it("ignores declaration-wide import type and export type from .node modules", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      import type { NativeThing } from "./addon.node";
      export type { Extra } from "./addon.node";
    `);
    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.native_addon_bindings).toEqual([]);
  });

  it("keeps only value members from mixed type/value native imports", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      import { type OtherThing, load } from "./addon.node";
      load();
    `);
    expect(analysis.electron.native_addon_bindings).toEqual([
      expect.objectContaining({
        specifier: "./addon.node",
        binding_kind: "import",
        members: ["load"],
      }),
    ]);
  });

  it("retains ordinary value imports of native addons", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      import { load } from "./addon.node";
      load();
    `);
    expect(analysis.electron.native_addon_bindings).toEqual([
      expect.objectContaining({
        specifier: "./addon.node",
        binding_kind: "import",
        members: ["load"],
      }),
    ]);
  });
});

describe("native addon type-only re-exports", () => {
  it.each([
    ['export { type Extra, load } from "./addon.node";', ["load"]],
    ['export { type Extra } from "./addon.node";', []],
    ['export type * from "./addon.node";', []],
  ] as const)("retains only runtime members from %s", (source, members) => {
    const analysis = analyzeJavaScriptStaticSource(source);
    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.native_addon_bindings).toEqual(
      members.length === 0
        ? []
        : [
            expect.objectContaining({
              specifier: "./addon.node",
              binding_kind: "re-export",
              members: [...members],
            }),
          ],
    );
  });
});

describe("native addon loader provenance", () => {
  it("distinguishes CommonJS and ESM re-exports", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const required = require("./addon.node#literal.node");
      module.exports = require("./addon.node#literal.node");
      import imported from "./addon.node#literal.node";
      export { default } from "./addon.node#literal.node";
    `);
    expect(analysis.electron.native_addon_bindings).toHaveLength(4);
    expect(analysis.electron.native_addon_bindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          binding_kind: "require",
          module_kind: "require",
        }),
        expect.objectContaining({
          binding_kind: "import",
          module_kind: "import",
        }),
        expect.objectContaining({
          binding_kind: "re-export",
          module_kind: "require",
        }),
        expect.objectContaining({
          binding_kind: "re-export",
          module_kind: "import",
        }),
      ]),
    );
  });

  it.each(["#", "?"])(
    "classifies require filenames literally for %s",
    (punctuation) => {
      const analysis = analyzeJavaScriptStaticSource(`
      const script = require("./addon.node${punctuation}helper.js");
      import native from "./addon.node${punctuation}helper.js";
    `);
      expect(analysis.electron.native_addon_bindings).toEqual([
        expect.objectContaining({
          binding_kind: "import",
          module_kind: "import",
        }),
      ]);
    },
  );

  it.each([
    ['exports.value += require("./fake.node");', "require"],
    ['exports.value -= require("./fake.node");', "require"],
    ['exports.value *= require("./fake.node");', "require"],
    ['exports.value = require("./fake.node");', "re-export"],
    ['const addon = require("./fake.node");', "require"],
  ] as const)(
    "classifies %s as binding_kind %s",
    (source, expectedBindingKind) => {
      const analysis = analyzeJavaScriptStaticSource(source);
      expect(analysis.parse_status).toBe("complete");
      expect(analysis.electron.native_addon_bindings).toEqual([
        expect.objectContaining({
          specifier: "./fake.node",
          binding_kind: expectedBindingKind,
          module_kind: "require",
        }),
      ]);
    },
  );

  it("ignores local .require method calls and shadowed require bindings while retaining proven loaders", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const helper = { require: () => ({ ok: true }) };
      const localMethod = helper.require("./fake.node");
      module.exports.reexportedMethod = helper.require("./fake.node");
      function shadowed(require, __webpack_require__) {
        const localParam = require("./fake.node");
        const localBundlerParam = __webpack_require__("./fake.node");
        return [localParam, localBundlerParam];
      }
      const realAddon = require("./real.node");
      globalThis.webpackChunkApp.push([[1], {
        "factory": function (module, exports, __webpack_require__) {
          const bundledAddon = __webpack_require__("./bundled.node");
          return bundledAddon;
        }
      }]);
    `);
    expect(analysis.electron.native_addon_bindings).toEqual([
      expect.objectContaining({
        specifier: "./real.node",
        binding_kind: "require",
        module_kind: "require",
      }),
      expect.objectContaining({
        specifier: "./bundled.node",
        binding_kind: "require",
        module_kind: "require",
        module_key: "factory",
      }),
    ]);
  });

  it("retains native addon bindings from optional require calls", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const localHelper = { require: () => ({ ok: true }) };
      const ignored = localHelper.require?.("./ignored.node");
      const addon = require?.("./addon.node");
      const helper = require?.("./addon.node")?.helper;
      module.exports = require?.("./addon.node");
    `);
    expect(analysis.electron.native_addon_bindings).toEqual([
      expect.objectContaining({
        specifier: "./addon.node",
        binding_kind: "require",
        module_kind: "require",
        namespace_access: true,
      }),
      expect.objectContaining({
        specifier: "./addon.node",
        binding_kind: "require",
        module_kind: "require",
        members: ["helper"],
        namespace_access: false,
      }),
      expect.objectContaining({
        specifier: "./addon.node",
        binding_kind: "re-export",
        module_kind: "require",
        namespace_access: true,
      }),
    ]);
  });
});
