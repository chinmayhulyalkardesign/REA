import * as t from "@babel/types";

import {
  readExactJavaScriptLiteral,
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { semanticBindingAtRead } from "./javascriptSemanticMutationInitializers.js";
import { semanticReferenceSourcesInactive } from "./javascriptSemanticReferenceSources.js";
import {
  semanticArrayIndex,
  semanticPropertyPathKeyMatches,
  type JavaScriptSemanticPropertyPath,
} from "./javascriptSemanticPropertyPaths.js";
import { semanticContainer } from "./javascriptSemanticSlots.js";
import { evaluateSemanticExpression } from "./javascriptSemanticValues.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";

// ECMAScript Object.prototype properties, including legacy accessor helpers.
// These can be inherited even with no visible prototype writes in the source.
const OBJECT_PROTOTYPE_KEYS = new Set([
  "constructor",
  "hasOwnProperty",
  "isPrototypeOf",
  "propertyIsEnumerable",
  "toLocaleString",
  "toString",
  "valueOf",
  "__proto__",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

/** Own-slot absence is not a Get proof when a prototype may supply that slot. */
const literalReferenceSource = (
  source: {
    readonly node: t.Node;
    readonly projection: JavaScriptSemanticPropertyPath;
  },
  state: JavaScriptSemanticAnalysisState,
  unknownPrototypes: ReadonlySet<string>,
): boolean => {
  if (!literalDataSource(source.node, state)) return false;
  let value = evaluateSemanticExpression(source.node, state, source.node);
  for (const key of source.projection) {
    if (key === null || typeof key === "object") return false;
    const container = semanticContainer(value);
    if (container === null) return false;
    const name = String(key);
    const slot = container.slots.find((item) => item.name === name);
    if (slot === undefined)
      return (
        container.coverage.status === "complete" &&
        !unknownPrototypes.has("Object") &&
        !OBJECT_PROTOTYPE_KEYS.has(name) &&
        (value.status !== "array" ||
          (!unknownPrototypes.has("Array") &&
            semanticArrayIndex(name) !== null))
      );
    if (slot.presence !== "present") return false;
    value = slot.value;
  }
  return true;
};

/** Loader proof precedes member effects; only inline data has no stale mutable reads. */
const literalDataSource = (
  root: t.Node,
  state: JavaScriptSemanticAnalysisState,
): boolean => {
  const pending = [root];
  for (let cursor = 0; cursor < pending.length; cursor++) {
    const current = pending[cursor];
    if (current === undefined) continue;
    const node = unwrapJavaScriptExpression(current).node;
    if (readExactJavaScriptLiteral(node).found) continue;
    if (t.isArrayExpression(node)) {
      if (state.ambientWrites.covers(["global", "Array", "prototype", null]))
        return false;
      for (const element of node.elements)
        if (element !== null) pending.push(element);
    } else if (t.isObjectExpression(node)) {
      for (const property of node.properties) {
        if (!t.isObjectProperty(property)) return false;
        const key = semanticStaticPropertyKey(property.key, property.computed);
        if (key === null || (key === "__proto__" && !property.computed))
          return false;
        pending.push(property.value);
      }
    } else return false;
  }
  return true;
};

/**
 * Possible loader identities for writes, preserving each lexical alias's capture.
 * The cache belongs to one bootstrap proof over a fixed binding/ambient-write
 * snapshot, before member effects are indexed. Never share it across analyses.
 */
export const createBootstrapLoaderAliasLookup = (
  loaderBindingIds: ReadonlySet<string>,
  state: JavaScriptSemanticAnalysisState,
): ((root: t.Node) => boolean) => {
  const known = new WeakMap<t.Node, boolean>();
  const prototypeEffects = [
    ...state.ambientWriteEffects,
    ...state.ambientEscapeEffects,
  ];
  const unknownPrototypes = new Set(
    ["Object", "Array"].filter((name) =>
      prototypeEffects.some(({ path }) =>
        path
          .slice(0, 3)
          .every((key, index) =>
            semanticPropertyPathKeyMatches(
              key,
              ["global", name, "prototype"][index] ?? "",
            ),
          ),
      ),
    ),
  );
  return (root) => {
    root = unwrapJavaScriptExpression(root).node;
    const cached = known.get(root);
    if (cached !== undefined) return cached;
    const pending: t.Node[] = [root];
    const seen = new Set<t.Node>();
    const dependents = new Map<t.Node, t.Node[]>();
    const loaders: t.Node[] = [];
    for (let cursor = 0; cursor < pending.length; cursor++) {
      const node = pending[cursor];
      if (node === undefined) continue;
      if (seen.has(node)) continue;
      seen.add(node);
      const result = known.get(node);
      if (result !== undefined) {
        if (result) loaders.push(node);
        continue;
      }
      const follow = (...sources: t.Node[]): void => {
        for (const source of sources) {
          const child = unwrapJavaScriptExpression(source).node;
          const parents = dependents.get(child);
          if (parents === undefined) dependents.set(child, [node]);
          else parents.push(node);
          pending.push(child);
        }
      };
      if (t.isIdentifier(node)) {
        const binding = resolveSemanticBindingState(state, node, node.name);
        if (binding === undefined) continue;
        if (loaderBindingIds.has(binding.bindingId)) {
          loaders.push(node);
          continue;
        }
        const selected = semanticBindingAtRead(
          binding,
          node,
          state.parentsByNode,
        ).binding;
        // Destructuring projections and rest copies do not denote the loader
        // itself. Only follow direct lexical references, not arbitrary fields.
        for (const initializer of [
          ...selected.initializers,
          ...selected.referenceInitializers.filter(
            (origin) =>
              origin.copyKind === undefined &&
              !(
                [
                  ...(origin.requiredSources ?? []),
                  ...(origin.fallbackSources ?? []),
                ].every((source) =>
                  literalReferenceSource(source, state, unknownPrototypes),
                ) && semanticReferenceSourcesInactive(origin, state)
              ),
          ),
        ])
          if (initializer.projection.length === 0) follow(initializer.node);
      } else if (t.isConditionalExpression(node)) {
        follow(node.consequent, node.alternate);
      } else if (t.isLogicalExpression(node)) {
        follow(node.left, node.right);
      } else if (t.isSequenceExpression(node)) {
        const last = node.expressions.at(-1);
        if (last !== undefined) follow(last);
      } else if (t.isAssignmentExpression(node, { operator: "=" })) {
        follow(node.right);
      } else if (
        t.isAssignmentExpression(node) &&
        ["&&=", "||=", "??="].includes(node.operator)
      ) {
        follow(node.left, node.right);
      }
    }
    // Solve the complete reachable graph before caching negatives: a cycle
    // may reach a loader through a different branch. Propagate positives only
    // to their dependents, never to unrelated alternatives visited alongside it.
    const reachesLoader = new Set<t.Node>();
    for (let cursor = 0; cursor < loaders.length; cursor++) {
      const node = loaders[cursor];
      if (node === undefined || reachesLoader.has(node)) continue;
      reachesLoader.add(node);
      for (const parent of dependents.get(node) ?? []) loaders.push(parent);
    }
    for (const node of seen) known.set(node, reachesLoader.has(node));
    return known.get(root) === true;
  };
};
