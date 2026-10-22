import { describe, expect, it } from "vitest";

import type { InspectElectronPageInput } from "../domain/javascript/electronObservation.js";
import { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import type { CdpConnection } from "./CdpConnection.js";
import type { CdpEndpointTarget } from "./CdpEndpoint.js";
import { captureElectronWorkers } from "./CdpElectronWorkers.js";

/** `authorizedElectronFile` only admits a file the host can resolve. */
const localFileUrl = import.meta.url;

const workerTarget = (
  over: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> => ({
  targetId: "worker-1",
  type: "service_worker",
  url: localFileUrl,
  openerId: "electron-page",
  attached: true,
  ...over,
});

/** An Electron worker target whose `TargetInfo.type` is not delivered at all. */
const targetWithoutType: Readonly<Record<string, unknown>> = {
  targetId: "worker-1",
  url: localFileUrl,
  openerId: "electron-page",
  attached: true,
};

const capture = async (inventory: unknown) => {
  const completeness = new CdpCaptureCompleteness();
  const workers = await captureElectronWorkers({
    connection: {
      async send() {
        return inventory;
      },
    } as unknown as CdpConnection,
    target: {
      id: "electron-page",
      type: "page",
      title: "Fixture",
      url: localFileUrl,
      attached: false,
    } satisfies CdpEndpointTarget,
    request: {} as InspectElectronPageInput,
    frameIds: new Set<string>(),
    completeness,
    limitations: [],
  });
  return { workers, completeness: completeness.snapshot() };
};

describe("Electron worker target inventory", () => {
  it("preserves an explicit empty inventory", async () => {
    const result = await capture({ targetInfos: [] });

    expect(result.workers).toEqual([]);
    expect(result.completeness.unavailable_sections).not.toContain("workers");
    expect(result.completeness.excluded).not.toContainEqual(
      expect.objectContaining({ section: "workers" }),
    );
  });

  it.each([undefined, { length: 1 }, "worker-one"])(
    "reports a missing or non-array target inventory as unknown: %s",
    async (targetInfos) => {
      const result = await capture({ targetInfos });

      expect(result.workers).toEqual([]);
      expect(result.completeness).toMatchObject({
        unavailable_sections: ["workers"],
        excluded: [
          { section: "workers", reason: "invalid_protocol_value", count: null },
        ],
      });
    },
  );

  it("records a target entry that carries no type discriminator", async () => {
    const result = await capture({ targetInfos: [targetWithoutType] });

    expect(result.workers).toEqual([]);
    expect(result.completeness.unavailable_sections).toContain("workers");
    expect(result.completeness.excluded).toContainEqual({
      section: "workers",
      reason: "invalid_protocol_value",
      count: 1,
    });
  });

  it.each([
    ["null", null],
    ["numeric", 42],
    ["empty", ""],
  ] as const)(
    "records a target entry whose type is an undecodable %s value",
    async (_label, type) => {
      const result = await capture({ targetInfos: [workerTarget({ type })] });

      expect(result.workers).toEqual([]);
      expect(result.completeness.excluded).toContainEqual({
        section: "workers",
        reason: "invalid_protocol_value",
        count: 1,
      });
    },
  );

  it("keeps a decodable non-worker type out of the malformed ledger", async () => {
    const result = await capture({
      targetInfos: [workerTarget({ type: "page" })],
    });

    expect(result.workers).toEqual([]);
    expect(result.completeness.unavailable_sections).not.toContain("workers");
    expect(result.completeness.excluded).not.toContainEqual(
      expect.objectContaining({ section: "workers" }),
    );
  });

  it("retains valid worker records beside malformed entries", async () => {
    const result = await capture({
      targetInfos: [
        null,
        targetWithoutType,
        { url: localFileUrl, type: "worker", openerId: "electron-page" },
        workerTarget({ targetId: "worker-2" }),
      ],
    });

    expect(result.workers.map((worker) => worker.target_id)).toEqual([
      "worker-2",
    ]);
    expect(result.completeness.unavailable_sections).toContain("workers");
    expect(result.completeness.excluded).toContainEqual({
      section: "workers",
      reason: "invalid_protocol_value",
      count: 3,
    });
    expect(result.completeness.excluded).not.toContainEqual(
      expect.objectContaining({
        section: "workers",
        reason: "out_of_target_scope",
      }),
    );
  });
});
