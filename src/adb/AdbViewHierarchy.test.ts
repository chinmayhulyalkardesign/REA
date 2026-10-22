import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { parseUiAutomatorDump } from "./AdbViewHierarchy.js";

const STATUS_LINE = "UI hierchary dumped to: /dev/tty\n";
const flags = (overrides: Readonly<Record<string, string>> = {}): string =>
  Object.entries({
    checkable: "false",
    checked: "false",
    clickable: "false",
    enabled: "true",
    focusable: "false",
    focused: "false",
    scrollable: "false",
    "long-clickable": "false",
    password: "false",
    selected: "false",
    ...overrides,
  })
    .map(([name, value]) => `${name}="${value}"`)
    .join(" ");

const DOCUMENT =
  `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>` +
  `<hierarchy rotation="0">` +
  `<node index="0" text="" resource-id="com.example.app:id/root" class="android.widget.FrameLayout" package="com.example.app" content-desc="" ${flags()} bounds="[0,0][1080,2376]" drawing-order="0" hint="">` +
  `<node index="0" text="Play" resource-id="" class="android.widget.Button" package="com.example.app" content-desc="Play track" ${flags({ clickable: "true", focusable: "true" })} bounds="[24,2100][240,2244]" drawing-order="1" hint="" />` +
  `<node index="1" text="Café ☕" resource-id="com.example.app:id/title" class="android.widget.TextView" package="com.example.app" content-desc="" ${flags({ selected: "maybe" })} bounds="[264,618][529,684]" />` +
  `</node>` +
  `<node index="1" text="" resource-id="" class="android.view.View" package="com.android.systemui" content-desc="" enabled="true" bounds="not-bounds" />` +
  `</hierarchy>`;

describe("parseUiAutomatorDump", () => {
  it("projects nodes in document order and digests the exact document bytes", () => {
    const parsed = parseUiAutomatorDump(Buffer.from(DOCUMENT + STATUS_LINE));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = parsed.value;
    expect(result.hierarchy_status).toBe("captured");
    expect(result.rotation).toBe(0);
    const bytes = Buffer.from(DOCUMENT);
    expect(result.document_bytes).toBe(bytes.byteLength);
    expect(result.document_sha256).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
    expect(result.device_messages).toEqual([
      "UI hierchary dumped to: /dev/tty",
    ]);
    expect(
      result.nodes.map(({ index, parent, depth }) => [index, parent, depth]),
    ).toEqual([
      [0, null, 0],
      [1, 0, 1],
      [2, 0, 1],
      [3, null, 0],
    ]);
    expect(result.nodes[0]).toMatchObject({
      resource_id: "com.example.app:id/root",
      text: null,
      content_desc: null,
      bounds: { left: 0, top: 0, right: 1080, bottom: 2376 },
      other_attributes: [{ name: "drawing-order", value: "0" }],
    });
    expect(result.nodes[1]).toMatchObject({
      sibling_index: 0,
      class_name: "android.widget.Button",
      text: "Play",
      content_desc: "Play track",
      resource_id: null,
      flags: ["clickable", "enabled", "focusable"],
      undeclared_flags: [],
    });
  });

  it("keeps unparsable known values and undeclared flags as unknowns", () => {
    const parsed = parseUiAutomatorDump(Buffer.from(DOCUMENT + STATUS_LINE));
    if (!parsed.ok) throw parsed.error;
    const [, , title, partial] = parsed.value.nodes;
    expect(title).toMatchObject({
      text: "Café ☕",
      flags: ["enabled"],
      other_attributes: [{ name: "selected", value: "maybe" }],
    });
    expect(partial).toMatchObject({
      bounds: null,
      flags: ["enabled"],
      other_attributes: [{ name: "bounds", value: "not-bounds" }],
    });
    expect(partial!.undeclared_flags).toEqual([
      "checkable",
      "checked",
      "clickable",
      "focusable",
      "focused",
      "scrollable",
      "long-clickable",
      "password",
      "selected",
    ]);
  });

  it("reports an idle-state failure as not_idle with the device message", () => {
    const parsed = parseUiAutomatorDump(
      Buffer.from("ERROR: could not get idle state.\n"),
    );
    expect(parsed).toEqual({
      ok: true,
      value: {
        hierarchy_status: "not_idle",
        rotation: null,
        nodes: [],
        document_sha256: null,
        document_bytes: null,
        device_messages: ["ERROR: could not get idle state."],
      },
    });
  });

  it("reports output without a document or known reason as unavailable", () => {
    for (const output of ["", "Killed\n"]) {
      const parsed = parseUiAutomatorDump(Buffer.from(output));
      if (!parsed.ok) throw parsed.error;
      expect(parsed.value.hierarchy_status).toBe("unavailable");
      expect(parsed.value.device_messages).toEqual(
        output === "" ? [] : ["Killed"],
      );
    }
  });

  it("accepts an empty self-closing hierarchy", () => {
    const parsed = parseUiAutomatorDump(
      Buffer.from(`<hierarchy rotation="1"/>\n${STATUS_LINE}`),
    );
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value).toMatchObject({
      hierarchy_status: "captured",
      rotation: 1,
      nodes: [],
    });
  });

  it("rejects a malformed or foreign document", () => {
    for (const output of [
      `<hierarchy rotation="0"><node index="0"></hierarchy>`,
      `<?xml version='1.0'?><!DOCTYPE hierarchy><hierarchy rotation="0"/>`,
    ]) {
      const parsed = parseUiAutomatorDump(Buffer.from(output));
      expect(parsed.ok, output).toBe(false);
    }
  });
});
