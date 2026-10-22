import { createHash } from "node:crypto";
import type { Element, Node } from "@xmldom/xmldom";

import {
  ADB_VIEW_NODE_FLAGS,
  type AdbViewNode,
} from "../domain/adb/adbDeviceAnalysis.js";
import { err, ok, type Result } from "../domain/result.js";
import { parseXmlDocument } from "../domain/xmlDocument.js";

/**
 * Parser for `uiautomator dump /dev/tty` read through `adb exec-out`.
 *
 * exec-out returns one merged byte stream: the hierarchy document followed by
 * uiautomator's status line ("UI hierchary dumped to: /dev/tty", Android's
 * spelling), or only an error line such as "ERROR: could not get idle state."
 * when the device never became idle. `adb shell` does not return the document
 * at all on tested builds, so this parser assumes the exec-out stream.
 */

export interface AdbViewHierarchyObservation {
  readonly hierarchy_status: "captured" | "not_idle" | "unavailable";
  readonly rotation: number | null;
  readonly nodes: readonly AdbViewNode[];
  readonly document_sha256: string | null;
  readonly document_bytes: number | null;
  readonly device_messages: readonly string[];
}

/** The stream contained a hierarchy document that is not well-formed XML. */
export class AdbViewHierarchyParseError extends Error {
  readonly _tag = "AdbViewHierarchyParseError";
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
  }
}

const NOT_IDLE = /could not get idle state/iu;
const BOUNDS = /^\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]$/u;
const KNOWN_TEXT_ATTRIBUTES = new Set([
  "index",
  "text",
  "resource-id",
  "class",
  "package",
  "content-desc",
  "bounds",
]);
const FLAG_NAMES: ReadonlySet<string> = new Set(ADB_VIEW_NODE_FLAGS);

/** Locate the document by byte offsets so its digest covers device bytes. */
const documentRange = (
  stream: Buffer,
): { readonly start: number; readonly end: number } | null => {
  const declaration = stream.indexOf("<?xml");
  const start = declaration >= 0 ? declaration : stream.indexOf("<hierarchy");
  if (start < 0) return null;
  const closing = stream.lastIndexOf("</hierarchy>");
  if (closing >= start) return { start, end: closing + "</hierarchy>".length };
  const root = stream.indexOf("<hierarchy", start);
  if (root < 0) return null;
  const selfClosing = stream.indexOf("/>", root);
  const nextTag = stream.indexOf("<", root + 1);
  return selfClosing >= 0 && (nextTag < 0 || selfClosing < nextTag)
    ? { start, end: selfClosing + 2 }
    : null;
};

const messageLines = (text: string): string[] =>
  text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "");

const nonNegativeInteger = (value: string): number | null =>
  /^\d+$/u.test(value) && Number.isSafeInteger(Number(value))
    ? Number(value)
    : null;

const elementChildren = (node: Node): Element[] => {
  const children: Element[] = [];
  for (let index = 0; index < node.childNodes.length; index += 1) {
    const child = node.childNodes.item(index);
    if (child !== null && child.nodeType === 1) children.push(child as Element);
  }
  return children;
};

const projectNode = (
  element: Element,
  index: number,
  parent: number | null,
  depth: number,
): AdbViewNode => {
  const flags: (typeof ADB_VIEW_NODE_FLAGS)[number][] = [];
  const undeclared: (typeof ADB_VIEW_NODE_FLAGS)[number][] = [];
  const other: { name: string; value: string }[] = [];
  const text = (name: string): string | null => {
    const value = element.getAttribute(name);
    return value === null || value === "" ? null : value;
  };
  for (const flag of ADB_VIEW_NODE_FLAGS) {
    if (!element.hasAttribute(flag)) {
      undeclared.push(flag);
      continue;
    }
    const value = element.getAttribute(flag);
    if (value === "true") flags.push(flag);
    else if (value !== "false") other.push({ name: flag, value: value ?? "" });
  }
  const rawIndex = element.getAttribute("index");
  const siblingIndex = rawIndex === null ? null : nonNegativeInteger(rawIndex);
  if (rawIndex !== null && siblingIndex === null)
    other.push({ name: "index", value: rawIndex });
  const rawBounds = element.getAttribute("bounds");
  const match = rawBounds === null ? null : BOUNDS.exec(rawBounds);
  if (rawBounds !== null && rawBounds !== "" && match === null)
    other.push({ name: "bounds", value: rawBounds });
  for (let position = 0; position < element.attributes.length; position += 1) {
    const attribute = element.attributes.item(position);
    if (attribute === null) continue;
    if (KNOWN_TEXT_ATTRIBUTES.has(attribute.name)) continue;
    if (FLAG_NAMES.has(attribute.name)) continue;
    if (attribute.value === "") continue;
    other.push({ name: attribute.name, value: attribute.value });
  }
  return {
    index,
    parent,
    depth,
    sibling_index: siblingIndex,
    class_name: text("class"),
    package: text("package"),
    resource_id: text("resource-id"),
    text: text("text"),
    content_desc: text("content-desc"),
    bounds:
      match === null
        ? null
        : {
            left: Number(match[1]!),
            top: Number(match[2]!),
            right: Number(match[3]!),
            bottom: Number(match[4]!),
          },
    flags,
    undeclared_flags: undeclared,
    other_attributes: other,
  };
};

/** Parse the merged exec-out stream into a hierarchy observation. */
export const parseUiAutomatorDump = (
  stream: Buffer,
): Result<AdbViewHierarchyObservation, AdbViewHierarchyParseError> => {
  const range = documentRange(stream);
  if (range === null) {
    const messages = messageLines(stream.toString("utf8"));
    return ok({
      hierarchy_status: messages.some((line) => NOT_IDLE.test(line))
        ? "not_idle"
        : "unavailable",
      rotation: null,
      nodes: [],
      document_sha256: null,
      document_bytes: null,
      device_messages: messages,
    });
  }
  const documentBytes = stream.subarray(range.start, range.end);
  const parsed = parseXmlDocument(documentBytes.toString("utf8"), {
    doctype: "reject",
    lineEndings: "preserve",
  });
  if (!parsed.ok)
    return err(
      new AdbViewHierarchyParseError(
        `uiautomator returned a hierarchy document that is not well-formed: ${parsed.error.message}`,
        parsed.error,
      ),
    );
  const root = parsed.value.documentElement;
  if (root === null || root.nodeName !== "hierarchy")
    return err(
      new AdbViewHierarchyParseError(
        "uiautomator hierarchy document root must be <hierarchy>",
      ),
    );
  const nodes: AdbViewNode[] = [];
  const pending: { element: Element; parent: number | null; depth: number }[] =
    elementChildren(root)
      .reverse()
      .map((element) => ({ element, parent: null, depth: 0 }));
  while (pending.length > 0) {
    const { element, parent, depth } = pending.pop()!;
    if (element.nodeName !== "node") continue;
    const index = nodes.length;
    nodes.push(projectNode(element, index, parent, depth));
    for (const child of elementChildren(element).reverse())
      pending.push({ element: child, parent: index, depth: depth + 1 });
  }
  const rawRotation = root.getAttribute("rotation");
  return ok({
    hierarchy_status: "captured",
    rotation:
      rawRotation === null || !/^-?\d+$/u.test(rawRotation)
        ? null
        : Number(rawRotation),
    nodes,
    document_sha256: createHash("sha256").update(documentBytes).digest("hex"),
    document_bytes: documentBytes.byteLength,
    device_messages: messageLines(
      Buffer.concat([
        stream.subarray(0, range.start),
        Buffer.from("\n"),
        stream.subarray(range.end),
      ]).toString("utf8"),
    ),
  });
};
