import { expect, it } from "vitest";
import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";

it("resolves void keys while retaining their calls and binding writes", () => {
  const ir = analyzeJavaScriptSemantics(`
    import {spawn} from "node:child_process";
    const routes = {[void sideEffect()]: "HOME"};
    const root = routes[void 0];
    let argv=[]; const changed = {[void (argv={})]: 1};
    spawn("changed",argv,{stdio:"inherit"});
  `);
  expect(ir.bindings.find(({ name }) => name === "root")?.value).toEqual({
    status: "literal",
    value: "HOME",
  });
  expect(ir.references.some(({ name }) => name === "sideEffect")).toBe(true);
  expect(ir.childProcessSpawns[0]?.stdioMode).toBe("dynamic");
});

it.each([
  "const routes = {'': 'HOME'}; const root = routes[''];",
  "const routes = {['']: 'HOME'}; const root = routes[''];",
  "const routes = {'': 'HOME'}; const {'': root} = routes;",
  "const routes = {'': 'HOME'}; const {['']: root} = routes;",
  "const routes = {home: 'HOME'}; const root = routes.home;",
])("preserves exact string keys in %s", (source) => {
  const ir = analyzeJavaScriptSemantics(source);
  expect(ir.bindings.find(({ name }) => name === "root")?.value).toEqual({
    status: "literal",
    value: "HOME",
  });
  expect(
    ir.frontiers.filter(({ kind }) => kind === "dynamic-property"),
  ).toEqual([]);
});

it("keeps a computed identifier key unresolved", () => {
  const ir = analyzeJavaScriptSemantics(
    "const routes = {'': 'HOME'}; const root = routes[key];",
  );
  expect(ir.bindings.find(({ name }) => name === "root")?.value.status).toBe(
    "unknown",
  );
  expect(ir.frontiers).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ kind: "dynamic-property" }),
    ]),
  );
});

it("retains exact empty method names and environment keys", () => {
  const ir = analyzeJavaScriptSemantics(`
    const target = { ['']() { return 42; } };
    class Holder { ""() { return 2; } }
    const empty = process.env[''];
    const dynamic = process.env[key];
  `);
  expect(
    ir.callables
      .filter(({ kind }) => kind === "method")
      .map(({ name }) => name),
  ).toEqual(["", ""]);
  expect(
    ir.configurationOperations.map(({ kind, key, resolution }) => ({
      kind,
      key,
      resolution,
    })),
  ).toEqual([
    { kind: "environment", key: "", resolution: "complete" },
    { kind: "environment", key: null, resolution: "partial" },
  ]);
});

it("retains exact empty require paths and dependencies without dynamic-key bindings", () => {
  const ir = analyzeJavaScriptSemantics(`
    const { '': fromPattern } = require("./table.js");
    const fromMember = require("./table.js")[''];
    const { [key]: dynamicPattern } = require("./table.js");
    const dynamicMember = require("./table.js")[key];
    module.exports.root = require("./table.js")[''];
  `);
  expect(
    ir.moduleLinks.map(({ kind, importedName, localName, exportedName }) => ({
      kind,
      importedName,
      localName,
      exportedName,
    })),
  ).toEqual([
    {
      kind: "require",
      importedName: "",
      localName: "fromPattern",
      exportedName: null,
    },
    {
      kind: "require",
      importedName: "",
      localName: "fromMember",
      exportedName: null,
    },
    {
      kind: "require",
      importedName: null,
      localName: null,
      exportedName: null,
    },
    {
      kind: "require",
      importedName: null,
      localName: null,
      exportedName: null,
    },
    {
      kind: "commonjs-export",
      importedName: "",
      localName: null,
      exportedName: "root",
    },
  ]);
});

it("retains exact empty request field names without dynamic fields", () => {
  const ir = analyzeJavaScriptSemantics(`
    fetch("https://example.test", { '': value, [key]: 1, body: "x" });
  `);
  expect(
    ir.requestOperations.flatMap(({ fields }) =>
      fields.map(({ name }) => name),
    ),
  ).toEqual(["", "body"]);
});

it("retains the exact empty CommonJS export name", () => {
  const ir = analyzeJavaScriptSemantics(`
    exports[''] = 1;
    module.exports[''] = 2;
    exports['ok'] = 3;
    exports[key] = 4;
  `);
  expect(ir.moduleLinks.map(({ exportedName }) => exportedName)).toEqual([
    "",
    "",
    "ok",
    "*",
  ]);
});

it.each([
  "const table = { [`token`]: 'VALUE' }; const selected = table[`token`];",
  "const table = { [true]: 'VALUE' }; const selected = table[true];",
  "const table = { [false]: 'VALUE' }; const selected = table[false];",
  "const table = { [null]: 'VALUE' }; const selected = table[null];",
])("retains an exact supported primitive key in %s", (source) => {
  const ir = analyzeJavaScriptSemantics(source);
  expect(ir.bindings.find(({ name }) => name === "selected")?.value).toEqual({
    status: "literal",
    value: "VALUE",
  });
  expect(
    ir.frontiers.filter(({ kind }) => kind === "dynamic-property"),
  ).toEqual([]);
});

it("keeps arbitrary template expressions unresolved while retaining literal names", () => {
  const ir = analyzeJavaScriptSemantics(
    "const table = { [`token`]: 'VALUE' }; const selected = table[`token${suffix}`];",
  );
  expect(
    ir.bindings.find(({ name }) => name === "selected")?.value.status,
  ).toBe("unknown");
});

it("retains complete returned objects with all supported primitive computed keys", () => {
  const ir = analyzeJavaScriptSemantics(`
    export function create() {
      return { [\`token\`]: "VALUE", [true]: 1, [false]: 2, [null]: 3 };
    }
  `);
  expect(
    ir.callables.find(({ name }) => name === "create")?.returnSites[0]?.value,
  ).toEqual({
    status: "object",
    unknownProperties: false,
    omittedProperties: 0,
    properties: [
      {
        name: "false",
        presence: "present",
        value: { status: "literal", value: 2 },
      },
      {
        name: "null",
        presence: "present",
        value: { status: "literal", value: 3 },
      },
      {
        name: "token",
        presence: "present",
        value: { status: "literal", value: "VALUE" },
      },
      {
        name: "true",
        presence: "present",
        value: { status: "literal", value: 1 },
      },
    ],
  });
});

it("preserves partial returned-object coverage for an unresolved computed key", () => {
  const ir = analyzeJavaScriptSemantics(`
    export function create(key) { return { [\`token\`]: "VALUE", [key]: 1 }; }
  `);
  expect(
    ir.callables.find(({ name }) => name === "create")?.returnSites[0]?.value,
  ).toEqual({
    status: "object",
    unknownProperties: true,
    omittedProperties: 1,
    properties: [
      {
        name: "token",
        presence: "present",
        value: {
          status: "unknown",
          reason: "A later property may overwrite this value.",
        },
      },
    ],
  });
});

it("retains supported primitive literal method names", () => {
  const ir = analyzeJavaScriptSemantics(`
    const target = { [\`task\`]() { return 42; } };
    class Holder { [true]() { return 2; } }
  `);
  expect(
    ir.callables
      .filter(({ kind }) => kind === "method")
      .map(({ name }) => name),
  ).toEqual(["task", "true"]);
});

it("retains literal-template environment keys", () => {
  const ir = analyzeJavaScriptSemantics(
    "const deployment = process.env[`DEPLOYMENT`];",
  );
  expect(
    ir.configurationOperations.map(({ key, resolution }) => ({
      key,
      resolution,
    })),
  ).toEqual([{ key: "DEPLOYMENT", resolution: "complete" }]);
});

it.each([
  ["`task`", "task"],
  ["true", "true"],
  ["false", "false"],
  ["null", "null"],
])("keeps the exact CommonJS export key %s", (key, expected) => {
  const ir = analyzeJavaScriptSemantics(`module.exports[${key}] = 42;`);
  expect(ir.moduleLinks.map(({ exportedName }) => exportedName)).toEqual([
    expected,
  ]);
});

it("keeps nonfinite numeric property names as exact strings", () => {
  const ir = analyzeJavaScriptSemantics(
    "const table = {[1e999]: 'VALUE'}; const selected = table[1e999];",
  );
  expect(ir.bindings.find(({ name }) => name === "selected")?.value).toEqual({
    status: "literal",
    value: "VALUE",
  });
});
