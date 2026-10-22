import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, vi } from "vitest";
import { AnalysisCleanupLease } from "../../../src/artifacts/AnalysisCleanupLease.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import * as runtimes from "../../../src/native/NativeUiHelperRuntime.js";
import { NativeMacOSProvider } from "../../../src/native/NativeMacOSProvider.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { NativeFixtureRunner } from "../../fixtures/nativeCommands.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

it("reports an unresolved native UI PID as invalid input without withdrawing the tool", async () => {
  const directory = await createTestTempDirectory("rea-native-ui-selection-");
  const path = join(directory, "Inert");
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(0x0100000c, 4);
  header.writeUInt32LE(2, 12);
  await writeFile(path, header);
  const snapshot = {
    window: {
      pid: 123,
      window_id: 456,
      executable: path,
      launch_time: 1,
      title: "Fixture",
    },
    nodes: [],
    screenshot: null,
    gaps: [],
    truncated: false,
  };
  const refusal =
    "LaunchServices has no running application for selected PID 999 (/bin/sleep); select the PID that owns the window";
  const factory = vi
    .spyOn(runtimes, "createNativeUiHelperRuntime")
    .mockImplementation(() => {
      const cleanupLease = new AnalysisCleanupLease(async () => undefined);
      return {
        signal: new AbortController().signal,
        cleanupLease,
        invoke: async (parameters) =>
          parameters.pid === 999
            ? { ok: false, code: "process-not-application", message: refusal }
            : { ok: true, result: snapshot },
        close: () => cleanupLease.release(),
        resources: () => [],
      };
    });
  const session = createTestBinarySession(
    new NativeMacOSProvider({}, new NativeFixtureRunner(), "darwin"),
  );
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "native-ui-selection", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const observeAvailability = async () => {
    const reply = await client.callTool({
      name: "binary_session",
      arguments: {},
    });
    return expandToolAvailability(
      toolContract("binary_session").outputSchema.parse(reply.structuredContent)
        .result.tool_availability,
    ).find((tool) => tool.name === "observe_native_ui");
  };
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const opened = await client.callTool({
      name: "open_binary",
      arguments: { path },
    });
    expect(opened.isError).not.toBe(true);
    const rejected = await client.callTool({
      name: "observe_native_ui",
      arguments: { pid: 999, window_id: 456, screenshot: false },
    });
    expect(parseMcpToolError(rejected)).toMatchObject({
      error: {
        category: "invalid_input",
        message: refusal,
        details: {
          operation: "observe_native_ui",
          issues: [
            {
              path: ["pid"],
              reason: "invalid_value",
              message: `process-not-application: ${refusal}`,
            },
          ],
        },
      },
    });
    expect(await observeAvailability()).toMatchObject({
      available: true,
      reason: "available",
    });
    const observed = await client.callTool({
      name: "observe_native_ui",
      arguments: { pid: 123, window_id: 456, screenshot: false },
    });
    expect(observed.isError).not.toBe(true);
  } finally {
    await session.close();
    await client.close();
    await server.close();
    factory.mockRestore();
  }
});
