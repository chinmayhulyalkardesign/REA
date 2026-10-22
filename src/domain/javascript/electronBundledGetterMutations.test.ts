import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import {
  LOADER_GETTER_REPLACEMENT as replacement,
  webpackGetterSource,
} from "./electronBundledGetter.fixture.js";

it.each([
  ["stable alias", `const alias = load; alias.n = ${replacement};`],
  [
    "alias chain",
    `const first = load; const alias = first; alias.n = ${replacement};`,
  ],
  ["assigned alias", `let alias; alias = load; alias.n = ${replacement};`],
  [
    "saved capture",
    `let first = load; const alias = first; first = {}; alias.n = ${replacement};`,
  ],
  [
    "conditional origin",
    `const alias = flag ? load : {}; alias.n = ${replacement};`,
  ],
  ["logical origin", `const alias = flag && load; alias.n = ${replacement};`],
  [
    "sequence result",
    `const alias = (metadata, load); alias.n = ${replacement};`,
  ],
  [
    "assignment result",
    `let first; const alias = (first = load); alias.n = ${replacement};`,
  ],
  [
    "logical assignment result",
    `let first = {}; const alias = (first &&= load); alias.n = ${replacement};`,
  ],
  [
    "cyclic aliases",
    `let first = load, alias = first; while (flag) { first = alias; alias = first; } alias.n = ${replacement};`,
  ],
  [
    "reflective alias write",
    `const alias = load; Reflect.set(alias, "n", ${replacement});`,
  ],
  ["alias deletion", "const alias = load; delete alias.n;"],
  [
    "destructuring target",
    `const alias = load; ({ getter: alias.n } = { getter: ${replacement} });`,
  ],
  ["unknown property", `const alias = load; alias[key] = ${replacement};`],
  [
    "object default",
    `const { api: alias = load } = {}; alias.n = ${replacement};`,
  ],
  ["array default", `const [alias = load] = []; alias.n = ${replacement};`],
  [
    "inherited nested default source",
    `Object.prototype.api = { inner: undefined }; const { api: { inner: alias = load } = { inner: {} } } = {}; alias.n = ${replacement};`,
  ],
  [
    "intrinsic inherited nested default source",
    `const { constructor: { missing: alias = load } = { missing: {} } } = {}; alias.n = ${replacement};`,
  ],
  [
    "inherited sparse array default source",
    `Array.prototype[0] = { inner: undefined }; const [{ inner: alias = load } = { inner: {} }] = []; alias.n = ${replacement};`,
  ],
  [
    "Object prototype inherited by a sparse array",
    `Object.prototype[0] = { inner: undefined }; const [{ inner: alias = load } = { inner: {} }] = []; alias.n = ${replacement};`,
  ],
  [
    "uncertain object default",
    `const { api: alias = load } = runtime; alias.n = ${replacement};`,
  ],
  [
    "uncertain array default",
    `const [alias = load] = runtime; alias.n = ${replacement};`,
  ],
  [
    "mutated object default source",
    `const source = { api: {} }; source.api = undefined; const { api: alias = load } = source; alias.n = ${replacement};`,
  ],
  [
    "mutated array default source",
    `const source = [{}]; source[0] = undefined; const [alias = load] = source; alias.n = ${replacement};`,
  ],
  [
    "escaped default source",
    `const source = { api: {} }; mutate(source); const { api: alias = load } = source; alias.n = ${replacement};`,
  ],
  [
    "member read in a fresh default source",
    `const source = { api: {} }; source.api = undefined; const { api: alias = load } = { api: source.api }; alias.n = ${replacement};`,
  ],
  [
    "replaced array iterator",
    `Array.prototype[Symbol.iterator] = function* () { yield undefined; }; const [alias = load] = [{}]; alias.n = ${replacement};`,
  ],
])("invalidates the canonical getter after a %s", (_name, mutation) => {
  const result = analyzeJavaScriptStaticSource(webpackGetterSource(mutation));
  expect(result.electron.browser_windows).toEqual([]);
  expect(result.references).toContainEqual(
    expect.objectContaining({ kind: "require", specifier: "electron" }),
  );
});

it.each([
  ["no mutation", ""],
  ["unrelated key", "const alias = load; alias.d = 1;"],
  [
    "reassigned alias",
    `let alias = load; alias = {}; alias.n = ${replacement};`,
  ],
  [
    "later loader assignment",
    `let alias = {}; alias.n = ${replacement}; alias = load;`,
  ],
  [
    "shadowed alias",
    `const alias = load; { const alias = {}; alias.n = ${replacement}; }`,
  ],
  [
    "unrelated cycle",
    `let first = {}, second = first; while (flag) { first = second; second = first; } first.n = ${replacement};`,
  ],
  [
    "unused object default",
    `const { api: alias = load } = { api: {} }; alias.n = ${replacement};`,
  ],
  [
    "unused array default",
    `const [alias = load] = [{}]; alias.n = ${replacement};`,
  ],
  [
    "nested own property despite prototype writes",
    `Object.prototype.api = { inner: undefined }; const { api: { inner: alias = load } = { inner: {} } } = { api: { inner: {} } }; alias.n = ${replacement};`,
  ],
  [
    "unused nested outer default",
    `const { api: { inner: alias = load } = { inner: {} } } = {}; alias.n = ${replacement};`,
  ],
  [
    "own constructor overrides the inherited constructor",
    `const { constructor: { missing: alias = load } = { missing: {} } } = { constructor: { missing: {} } }; alias.n = ${replacement};`,
  ],
])("preserves the canonical getter with %s", (_name, mutation) => {
  expect(
    analyzeJavaScriptStaticSource(webpackGetterSource(mutation)).electron
      .browser_windows,
  ).toHaveLength(1);
});

it("bounds long lexical alias chains without losing the getter write", () => {
  const aliases = Array.from(
    { length: 2_000 },
    (_, index) =>
      `const alias${index} = ${index === 0 ? "load" : `alias${index - 1}`};`,
  ).join("\n");
  expect(
    analyzeJavaScriptStaticSource(
      webpackGetterSource(`${aliases} alias1999.n = ${replacement};`),
    ).electron.browser_windows,
  ).toEqual([]);
});
