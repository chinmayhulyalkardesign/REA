/** Class-file identity used to disambiguate JVM CAFEBABE from Mach-O FAT. */

export const MAX_JVM_CLASS_PROBE_BYTES = 64 * 1024;

export type JvmClassProbeState = "pending" | "matched" | "rejected";

/**
 * Streaming, bounded JVM class signature probe.
 * Checks magic (0xcafebabe), valid major/minor version framing, and parses
 * up to 3 constant pool entries without requiring the complete file or EOF.
 */
export const createJvmClassSignatureProbe = (): {
  write(bytes: Uint8Array): JvmClassProbeState;
  readonly state: JvmClassProbeState;
} => {
  let state: JvmClassProbeState = "pending";
  let buffered = new Uint8Array(0);

  return {
    get state() {
      return state;
    },
    write(bytes: Uint8Array): JvmClassProbeState {
      if (state !== "pending" || bytes.length === 0) return state;

      const needed = Math.min(
        MAX_JVM_CLASS_PROBE_BYTES - buffered.length,
        bytes.length,
      );
      if (needed <= 0) {
        state = "rejected";
        return state;
      }

      const next = new Uint8Array(buffered.length + needed);
      next.set(buffered);
      next.set(bytes.subarray(0, needed), buffered.length);
      buffered = next;

      if (buffered.length < 4) return state;

      const view = new DataView(
        buffered.buffer,
        buffered.byteOffset,
        buffered.byteLength,
      );

      if (view.getUint32(0, false) !== 0xcafebabe) {
        state = "rejected";
        return state;
      }

      if (buffered.length < 10) return state;

      const minor = view.getUint16(4, false);
      const major = view.getUint16(6, false);
      const poolCount = view.getUint16(8, false);

      if (
        major < 45 ||
        major > 100 ||
        (minor !== 0 && minor !== 65535) ||
        poolCount === 0
      ) {
        state = "rejected";
        return state;
      }

      const targetEntries = Math.min(poolCount - 1, 3);
      if (targetEntries === 0) {
        state = "matched";
        return state;
      }

      let offset = 10;
      let parsed = 0;

      for (let index = 1; index < poolCount; index += 1) {
        if (offset >= buffered.length) break;
        const tag = buffered[offset]!;

        if (tag === 1) {
          if (offset + 3 > buffered.length) break;
          const len = view.getUint16(offset + 1, false);
          if (offset + 3 + len > buffered.length) break;
          offset += 3 + len;
        } else if (tag === 3 || tag === 4) {
          if (offset + 5 > buffered.length) break;
          offset += 5;
        } else if (tag === 5 || tag === 6) {
          if (offset + 9 > buffered.length) break;
          offset += 9;
          index += 1;
        } else if (
          tag === 7 ||
          tag === 8 ||
          tag === 16 ||
          tag === 19 ||
          tag === 20
        ) {
          if (offset + 3 > buffered.length) break;
          offset += 3;
        } else if (
          tag === 9 ||
          tag === 10 ||
          tag === 11 ||
          tag === 12 ||
          tag === 17 ||
          tag === 18
        ) {
          if (offset + 5 > buffered.length) break;
          offset += 5;
        } else if (tag === 15) {
          if (offset + 4 > buffered.length) break;
          offset += 4;
        } else {
          state = "rejected";
          return state;
        }

        parsed += 1;
        if (parsed >= targetEntries) {
          state = "matched";
          return state;
        }
      }

      if (buffered.length >= MAX_JVM_CLASS_PROBE_BYTES) {
        state = "rejected";
      }

      return state;
    },
  };
};

/** Bounded framing check that distinguishes JVM class prefixes from Mach-O FAT without requiring full file EOF. */
export const hasBoundedJvmClassFraming = (bytes: Uint8Array): boolean =>
  createJvmClassSignatureProbe().write(bytes) === "matched";
