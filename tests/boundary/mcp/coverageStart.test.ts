import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { webPageInspectionSchema } from "../../../src/domain/browserObservationSchemas.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { startFakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";

it("starts section coverage when the corresponding domain is enabled", async () => {
  const received = new Map<string, number>();
  let pageEnableRepliedAt = 0;
  const browser = await startFakeCdpBrowser({
    eventsBeforeReply: ["Network.enable"],
    commandResult(command) {
      received.set(command.method, Date.now());
      if (
        command.method === "Page.enable" ||
        command.method === "Runtime.enable" ||
        command.method === "Network.enable"
      ) {
        // Deterministic reply barriers: each acknowledgment lands at least one
        // clock tick after receipt, and Page.enable lands after the capture
        // window starts. A coverage timestamp recorded after any enable reply
        // would exceed that command's receipt time and fail the assertions
        // below.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
        if (command.method === "Page.enable") pageEnableRepliedAt = Date.now();
      }
      return undefined;
    },
  });
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(ok(null)),
  }));
  const server = createServer(
    { kind: "session", session },
    {
      environment: process.env,
      browserObservation: new CdpBrowserProvider(),
      availabilityPolicy: () => ({
        processCaptureEnabled: false,
        investigationInputRoots: 0,
      }),
    },
  );
  const client = new Client({ name: "coverage-start", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({
      name: "inspect_web_page",
      arguments: {
        cdp_endpoint: browser.endpoint,
        target_id: "allowed-page",
        allowed_origins: [browser.allowedOrigin],
        observation_ms: 0,
      },
    });
    expect(result.isError).not.toBe(true);
    const inspection = webPageInspectionSchema.parse(
      (result.structuredContent as { normalized_result: unknown })
        .normalized_result,
    );
    const captureStart = Date.parse(inspection.capture_window.started_at);
    const networkStart = Date.parse(inspection.network.coverage_started_at);
    const consoleStart = Date.parse(inspection.console.coverage_started_at);
    expect(networkStart).toBeGreaterThan(captureStart);
    expect(consoleStart).toBeGreaterThan(captureStart);
    expect(networkStart).toBeGreaterThanOrEqual(pageEnableRepliedAt);
    expect(consoleStart).toBeGreaterThanOrEqual(pageEnableRepliedAt);
    expect(networkStart).toBeLessThanOrEqual(received.get("Network.enable")!);
    expect(consoleStart).toBeLessThanOrEqual(received.get("Runtime.enable")!);
    // The fake delivered the request before acknowledging Network.enable, so
    // it remains represented inside the reported network coverage boundary.
    expect(inspection.network.requests.length).toBeGreaterThan(0);
    expect(inspection.network.prior_activity_available).toBe(false);
    expect(inspection.console.prior_activity_available).toBe(false);
  } finally {
    await client.close();
    await server.close();
    await session.close();
    await browser.close();
  }
}, 20_000);
