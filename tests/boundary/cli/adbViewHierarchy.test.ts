import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished } from "vitest";

import { AdbProvider } from "../../../src/adb/AdbProvider.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const DOCUMENT =
  `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>` +
  `<hierarchy rotation="0"><node index="0" text="Play" resource-id="com.example.app:id/play" class="android.widget.Button" package="com.example.app" content-desc="" clickable="true" enabled="true" bounds="[0,0][300,144]" /></hierarchy>`;

const fakeAdb = `#!/bin/sh
if [ "$1" = version ]; then
  printf 'Android Debug Bridge version 1.0.41\\nVersion 34.0.5-fixture\\nInstalled as %s\\n' "$0"
  exit 0
fi
if [ "$1" = -s ] && [ "$3" = exec-out ] && [ "$4" = uiautomator ] && [ "$5" = dump ]; then
  printf '%s\\n' "$6" >> "$0.calls"
  case "$2" in
    captured-device) cat "$0.xml"; printf 'UI hierchary dumped to: /dev/tty\\n' ;;
    busy-device) printf 'ERROR: could not get idle state.\\n' ;;
    malformed-device) printf '<hierarchy rotation="0"><node></hierarchy>\\n' ;;
  esac
  exit 0
fi
exit 1
`;

for (const { serial, status } of [
  { serial: "captured-device", status: "captured" },
  { serial: "busy-device", status: "not_idle" },
] as const) {
  cliTest.skipIf(process.platform === "win32")(
    `reports the view hierarchy through CLI and MCP: ${serial}`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-adb-view-hierarchy-");
      const binary = join(root, "adb");
      await writeFile(binary, fakeAdb, { mode: 0o755 });
      await writeFile(`${binary}.xml`, DOCUMENT);
      const output = await cli.run({
        arguments: ["inspect-adb-view-hierarchy", serial, "--json"],
        environment: { REA_ADB_PATH: binary },
      });
      expect(output.exitCode).toBe(0);
      const provider = new AdbProvider({
        environment: { REA_ADB_PATH: binary },
      });
      const harness = await createApplicationMcpHarness({
        serverOptions: { adbDeviceAnalysis: provider },
      });
      onTestFinished(() => harness.close());
      const schemas = await advertisedMcpToolSchemas(
        harness.client,
        "inspect_adb_view_hierarchy",
      );
      const args = { serial };
      expect(schemas.ajv.validate(schemas.inputSchema, args)).toBe(true);
      const response = await harness.client.callTool({
        name: schemas.name,
        arguments: args,
      });
      expect(response.isError).not.toBe(true);
      expect(
        schemas.ajv.validate(schemas.outputSchema, response.structuredContent),
      ).toBe(true);
      for (const raw of [output.json, response.structuredContent]) {
        const evidence = parseEvidence(
          toolContract("inspect_adb_view_hierarchy").outputSchema.parse(raw),
        );
        expect(evidence.normalized_result).toMatchObject(
          status === "captured"
            ? {
                hierarchy_status: "captured",
                nodes: [
                  {
                    index: 0,
                    parent: null,
                    resource_id: "com.example.app:id/play",
                    text: "Play",
                    bounds: { left: 0, top: 0, right: 300, bottom: 144 },
                    flags: ["clickable", "enabled"],
                  },
                ],
                document_bytes: Buffer.byteLength(DOCUMENT),
                device_messages: ["UI hierchary dumped to: /dev/tty"],
              }
            : {
                hierarchy_status: "not_idle",
                nodes: [],
                document_sha256: null,
                device_messages: ["ERROR: could not get idle state."],
              },
        );
        expect(evidence.limitations).toContainEqual(
          expect.stringContaining("no device-side file was written"),
        );
        if (status === "not_idle")
          expect(evidence.limitations).toContainEqual(
            expect.stringContaining("the hierarchy is unknown, not empty"),
          );
      }
      expect(
        (await readFile(`${binary}.calls`, "utf8")).trim().split("\n"),
      ).toEqual(["/dev/tty", "/dev/tty"]);
    },
  );
}

cliTest.skipIf(process.platform === "win32")(
  "rejects a malformed hierarchy document as a protocol error",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-adb-view-hierarchy-");
    const binary = join(root, "adb");
    await writeFile(binary, fakeAdb, { mode: 0o755 });
    const output = await cli.run({
      arguments: ["inspect-adb-view-hierarchy", "malformed-device", "--json"],
      environment: { REA_ADB_PATH: binary },
    });
    expect(output.exitCode).not.toBe(0);
    expect(output.json).toMatchObject({ code: "unreadable_output" });
  },
);
