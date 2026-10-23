import type { Readable } from "node:stream";
import { setImmediate, setTimeout } from "node:timers/promises";
import { AnalysisCleanupLease } from "./AnalysisCleanupLease.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";

// After cancellation, input destruction gets the same bounded closure grace as
// process output. Cancellation alone does not prove that the source closed.
const SOURCE_DESTRUCTION_GRACE_MS = 1_000;
const SOURCE_CLOSURE_POLL_MS = 10;

/**
 * Yield chunks until the source ends or the caller cancels. A closing source
 * ends its iterator only at close, so cancellation also ends that wait.
 */
export async function* readSourceChunks(
  source: Readable,
  signal: AbortSignal | undefined,
): AsyncGenerator<unknown, void, undefined> {
  // The write owner joins destruction and records its failures on early exit.
  const chunks = source.iterator({ destroyOnReturn: false });
  let abandoned = false;
  try {
    while (true) {
      const next = await untilAborted(chunks.next(), signal);
      if (next === undefined) {
        abandoned = true;
        return;
      }
      if (next.done === true) return;
      yield next.value;
    }
  } finally {
    // Returning an iterator with a pending read would queue behind that read.
    if (!abandoned) await chunks.return?.();
  }
}

/** Settle with the read, or with undefined once cancellation is observed. */
const untilAborted = <T>(
  read: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T | undefined> => {
  if (signal === undefined) return read;
  return new Promise((resolve, reject) => {
    const onAbort = (): void => resolve(undefined);
    // An abandoned read still settles here; its source error has an owner.
    void read
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", onAbort));
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
};

/**
 * Join started destruction, including silent auto-destroy after normal end.
 * A destruction that outlives cancellation is returned as an owned failure.
 */
export const settleSourceDestruction = async (
  source: Readable,
  signal: AbortSignal | undefined,
  resource: string,
): Promise<ArtifactReaderFailure | undefined> => {
  // Let queued end/destroy notifications run before observing the resource state.
  // A completed readable side need not destroy an open duplex writable side.
  await setImmediate();
  let cancelledAt: number | undefined;
  while (source.destroyed && !source.closed) {
    if (signal?.aborted === true) {
      cancelledAt ??= performance.now();
      if (performance.now() - cancelledAt >= SOURCE_DESTRUCTION_GRACE_MS)
        return retainUnsettledSource(source, resource, signal.reason);
    }
    await setTimeout(SOURCE_CLOSURE_POLL_MS);
  }
  return undefined;
};

/** Retain the source until closure is observed without a late destroy error. */
const retainUnsettledSource = (
  source: Readable,
  resource: string,
  reason: unknown,
): ArtifactReaderFailure => {
  let late: { readonly cause: unknown } | undefined;
  const observe = (cause: unknown): void => {
    late ??= { cause };
  };
  // A late destroy error must not escape once the write stops waiting for it.
  source.on("error", observe);
  // Release confirms closure without waiting; an unsettled retry stays failed.
  const lease = new AnalysisCleanupLease(async () => {
    // Closure is recorded before its queued error notification runs.
    await setImmediate();
    if (!source.closed)
      throw new ArtifactReaderFailure(
        "io",
        `Input stream destruction has not settled: ${resource}`,
      );
    source.off("error", observe);
    if (late !== undefined) throw late.cause;
  }, [resource]);
  // A failed release leaves the lease, and every error bound to it, unresolved.
  void observeClosure(source)
    .then(() => lease.release())
    .catch(() => undefined);
  const message = `Input stream destruction did not settle after cancellation: ${resource}`;
  return new ArtifactReaderFailure("cancelled", message, {
    cause: reason,
    cleanup: { reason: message, resources: [resource] },
    cleanupLeases: [lease],
  });
};

/**
 * Wake on close, or poll a silent source, without keeping the process alive.
 * Each wait settles and is released, so a source that never closes retains
 * only one pending wait and one close listener.
 */
const observeClosure = async (source: Readable): Promise<void> => {
  let wake: (() => void) | undefined;
  const onClose = (): void => wake?.();
  source.once("close", onClose);
  try {
    while (!source.closed)
      await new Promise<void>((resolve) => {
        const timer = globalThis.setTimeout(resolve, SOURCE_CLOSURE_POLL_MS);
        timer.unref();
        wake = () => {
          globalThis.clearTimeout(timer);
          resolve();
        };
      });
  } finally {
    wake = undefined;
    source.off("close", onClose);
  }
};
