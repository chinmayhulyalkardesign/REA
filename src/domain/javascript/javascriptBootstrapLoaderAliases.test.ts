import * as t from "@babel/types";
import { expect, it, vi } from "vitest";

import { createBootstrapLoaderAliasLookup } from "./javascriptBootstrapLoaderAliases.js";
import { indexJavaScriptBindingsSteps } from "./javascriptSemanticAnalysis.js";
import * as initializers from "./javascriptSemanticMutationInitializers.js";
import { traverseJavaScriptAst } from "./javascriptSemanticTraversal.js";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";

const fixture = (source: string) => {
  const program = parseJavaScriptSource(
    `function load() {} ${source}`,
  )?.program;
  if (program === undefined) throw new Error("Expected parsed source");
  const steps = indexJavaScriptBindingsSteps(program);
  let step = steps.next();
  while (step.done !== true) step = steps.next();
  const state = step.value;
  const loader = [...state.bindingsById.values()].find(
    ({ name }) => name === "load",
  );
  if (loader === undefined) throw new Error("Missing loader");
  const roots: t.Node[] = [];
  traverseJavaScriptAst(program, {
    enter: (node) => {
      if (t.isAssignmentExpression(node) && t.isMemberExpression(node.left))
        roots.push(node.left.object);
    },
  });
  return {
    roots,
    lookup: createBootstrapLoaderAliasLookup(
      new Set([loader.bindingId]),
      state,
    ),
    withoutLoader: createBootstrapLoaderAliasLookup(new Set(), state),
  };
};

it.each([
  ["load", false],
  ["load", true],
  ["{}", false],
  ["{}", true],
] as const)(
  "reuses intermediate reads across many writes with origin %s, reverse %s",
  (origin, reverse) => {
    const count = 512;
    const { roots, lookup } = fixture(
      `const a0 = ${origin};${Array.from(
        { length: count },
        (_, index) =>
          `const a${index + 1} = a${index}; a${index + 1}.other = 1;`,
      ).join("")}`,
    );
    const read = vi.spyOn(initializers, "semanticBindingAtRead");
    try {
      expect(roots).toHaveLength(count);
      if (reverse) roots.reverse();
      for (const root of roots) expect(lookup(root)).toBe(origin === "load");
      expect(read.mock.calls.length).toBeLessThan(4 * count);
    } finally {
      read.mockRestore();
    }
  },
);

it("does not mark a dead alternative as a loader when another branch reaches it", () => {
  const { roots, lookup } = fixture(`
    const dead = {}; const mixed = flag ? dead : load;
    mixed.other = 1; dead.n = 1;
  `);
  expect(roots.map(lookup)).toEqual([true, false]);
});

it.each([false, true])(
  "settles cyclic aliases with a loader exit: %s",
  (exit) => {
    const { roots, lookup } = fixture(`
    let first = {}, second = first;
    while (flag) { first = second; second = first; ${exit ? "if (other) second = load;" : ""} }
    first.other = 1; second.other = 1;
  `);
    expect(roots.map(lookup)).toEqual([exit, exit]);
    expect([...roots].reverse().map(lookup)).toEqual([exit, exit]);
  },
);

it("keeps cached captures separate from later reads and other lookup lifetimes", () => {
  const source = `let alias = load; const saved = alias;
    saved.other = 1; alias = {}; alias.n = 1; saved.n = 1;`;
  const { roots, lookup, withoutLoader } = fixture(source);
  expect(roots.map(lookup)).toEqual([true, false, true]);
  expect(roots.map(withoutLoader)).toEqual([false, false, false]);
  const unrelated = fixture(source.replace("alias = load", "alias = {}"));
  expect(unrelated.roots.map(unrelated.lookup)).toEqual([false, false, false]);
});
