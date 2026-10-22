import type { AsarHeaderAdmission } from "../config/asarHeaderAdmission.js";
import type {
  ElectronPageInspection,
  InspectElectronPageInput,
} from "../domain/javascript/electronObservation.js";
import type { CdpConnection } from "./CdpConnection.js";
import { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import {
  admitRecords,
  recordValue,
  cdpStringValue,
} from "./CdpCaptureValues.js";
import type { CdpEndpointTarget } from "./CdpEndpoint.js";
import { optionalCdpCommand } from "./CdpOptionalCommand.js";
import { authorizedElectronFile } from "./ElectronFileScope.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";

/** Inventory local worker targets without attaching to them. */
export const captureElectronWorkers = async (input: {
  readonly connection: CdpConnection;
  readonly signal?: AbortSignal;
  readonly target: CdpEndpointTarget;
  readonly request: InspectElectronPageInput;
  readonly frameIds: ReadonlySet<string>;
  readonly completeness: CdpCaptureCompleteness;
  readonly limitations: string[];
  readonly asarHeaderAdmission: AsarHeaderAdmission;
}): Promise<ElectronPageInspection["workers"]> => {
  const result = await optionalCdpCommand(
    {
      connection: input.connection,
      sessionId: undefined,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    },
    "Target.getTargets",
    {},
    input.limitations,
  );
  if (result === undefined) {
    input.completeness.unavailable("workers");
    return [];
  }
  const workers: ElectronPageInspection["workers"] = [];
  // A missing target list or a non-record entry is unreadable, not empty.
  const targetInfos = admitRecords(recordValue(result)?.targetInfos);
  if (targetInfos === undefined) {
    input.completeness.exclude("workers", "invalid_protocol_value", null);
    return [];
  }
  let malformedEntries = 0;
  for (const entry of targetInfos) {
    throwIfElectronWorkerCaptureCancelled(input.signal);
    const target = recordValue(entry);
    if (target === undefined) {
      malformedEntries += 1;
      continue;
    }
    // An undecodable discriminator cannot prove the entry is not a worker.
    const type = cdpStringValue(target.type);
    if (type === undefined || type.length === 0) {
      malformedEntries += 1;
      continue;
    }
    if (!type.includes("worker")) continue;
    const openerTargetId = boundedTargetField(target.openerId);
    const parentFrameId = boundedTargetField(target.parentFrameId);
    if (
      openerTargetId !== input.target.id &&
      (parentFrameId === null || !input.frameIds.has(parentFrameId))
    ) {
      input.completeness.exclude("workers", "out_of_target_scope");
      continue;
    }
    const path = await authorizedElectronFile(
      cdpStringValue(target.url) ?? "",
      input.signal,
      "inspect_electron_page",
      input.asarHeaderAdmission,
    );
    if (path === undefined) {
      input.completeness.exclude("workers", "out_of_target_scope");
      continue;
    }
    const targetId = boundedTargetField(target.targetId);
    if (targetId === null) {
      malformedEntries += 1;
      continue;
    }
    if (typeof target.attached !== "boolean") {
      malformedEntries += 1;
      continue;
    }
    workers.push({
      target_id: targetId,
      type,
      file_path: path,
      attached: target.attached,
      opener_target_id: openerTargetId,
      parent_frame_id: parentFrameId,
    });
  }
  if (malformedEntries > 0)
    input.completeness.exclude(
      "workers",
      "invalid_protocol_value",
      malformedEntries,
    );
  return workers.sort((left, right) =>
    compareUnicodeCodePoints(left.target_id, right.target_id),
  );
};

const throwIfElectronWorkerCaptureCancelled = (signal?: AbortSignal): void => {
  if (signal?.aborted === true)
    throw new AnalysisCancelledError("inspect_electron_page", {
      cause: signal.reason,
    });
};

const boundedTargetField = (value: unknown): string | null => {
  const field = cdpStringValue(value);
  return field === undefined || field === "" ? null : field;
};
