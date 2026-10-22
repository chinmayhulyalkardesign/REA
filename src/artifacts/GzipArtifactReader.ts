import { createGunzip } from "node:zlib";
import { PassThrough, pipeline, type Readable } from "node:stream";
import { basename } from "node:path";
import type { Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";

import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
  type ArtifactTraversalOptions,
} from "./ArtifactReader.js";
import type { ArtifactCommand } from "../domain/artifactGraph.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  openRegularFile,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";

/** Extract original filename from GZIP header flags (RFC 1952) if present. */
const readGzipOriginalFilename = (
  prefix: Buffer,
  fallbackPath: string,
): string => {
  if (prefix.length >= 10 && prefix[0] === 0x1f && prefix[1] === 0x8b) {
    const flags = prefix[3] ?? 0;
    // Bit 3 is FNAME
    if ((flags & 0x08) !== 0) {
      let offset = 10;
      // If FEXTRA is set, skip extra field
      if ((flags & 0x04) !== 0 && prefix.length >= 12) {
        const xlen = prefix.readUInt16LE(10);
        offset = 12 + xlen;
      }
      if (offset < prefix.length) {
        const nullByte = prefix.indexOf(0, offset);
        if (nullByte > offset) {
          const name = prefix
            .subarray(offset, nullByte)
            .toString("latin1")
            .trim();
          if (name.length > 0 && !name.includes("/") && !name.includes("\\")) {
            return name;
          }
        }
      }
    }
  }
  const base = basename(fallbackPath);
  if (base.toLowerCase().endsWith(".gz")) {
    return base.slice(0, -3);
  }
  return base.length > 0 ? `${base}.unpacked` : "decompressed_payload";
};

/** Single-stream decompression reader for GZIP archives. */
export class GzipArtifactReader implements ArtifactReader {
  readonly format = "gzip" as const;
  private handle: FileHandle | undefined;
  private owner: OwnedFileHandle | undefined;
  private fileSize = 0;
  private cachedEntry: ArtifactEntry | null = null;
  private closed = false;

  constructor(
    readonly path: string,
    private readonly admitted?: StableRegularFileDescriptor,
  ) {
    if (admitted !== undefined) {
      this.handle = admitted.handle;
      this.fileSize = admitted.initial.size;
    }
  }

  provenance(): readonly ArtifactCommand[] {
    return [];
  }

  private async ensureOpen(
    signal?: AbortSignal,
  ): Promise<{ handle: FileHandle; size: number }> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader is closed",
      );
    }
    if (this.handle !== undefined) {
      return { handle: this.handle, size: this.fileSize };
    }
    const handle = await openRegularFile(this.path, {
      symlinks: "follow",
      signal,
    });
    this.handle = handle;
    this.owner = new OwnedFileHandle(handle);
    try {
      const metadata: Stats = await handle.stat();
      this.fileSize = metadata.size;
    } catch (cause) {
      await this.close();
      throw cause;
    }
    return { handle: this.handle, size: this.fileSize };
  }

  async *entries(
    signal?: AbortSignal,
    options?: ArtifactTraversalOptions,
  ): AsyncIterable<ArtifactEntry> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader was already closed",
      );
    }
    if (this.cachedEntry === null) {
      const { handle, size } = await this.ensureOpen(signal);
      const prefix = Buffer.alloc(512);
      const readResult = await handle.read(
        prefix,
        0,
        Math.min(prefix.length, size),
        0,
      );
      const innerName = readGzipOriginalFilename(
        prefix.subarray(0, readResult.bytesRead),
        this.path,
      );

      this.cachedEntry = {
        path: innerName,
        kind: "file",
        declaredSize: null,
        compressedSize: size,
        executable: true,
        encrypted: false,
        byteOffset: null,
        declaredIntegrity: null,
        unpacked: false,
        limitations: [],
        adapterKey: this.path,
      };
    }
    if (signal?.aborted) {
      throw new ArtifactReaderFailure("cancelled", "Gzip traversal cancelled", {
        cancellation: { reason: signal.reason },
      });
    }
    options?.onCoverage?.({ status: "complete", limitations: [] });
    yield copyArtifactEntry(this.cachedEntry);
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader is closed",
      );
    }
    const { handle } = await this.ensureOpen(signal);
    const current = this.cachedEntry;
    if (current === null || !sameArtifactEntry(current, entry)) {
      throw new ArtifactReaderFailure(
        "path",
        `Unknown artifact entry: ${entry.path}`,
      );
    }
    if (signal?.aborted) {
      throw new ArtifactReaderFailure("cancelled", "Decompression cancelled", {
        cancellation: { reason: signal.reason },
      });
    }

    const inputStream = handle.createReadStream({
      start: 0,
      autoClose: false,
    });
    const gunzip = createGunzip();
    const output = new PassThrough();

    let totalBytes = 0;
    const MAX_GZIP_EXPANSION = 512 * 1024 * 1024; // 512 MiB budget
    gunzip.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_GZIP_EXPANSION) {
        const err = new ArtifactReaderFailure(
          "limit",
          `GZIP decompression exceeded maximum expansion budget of ${MAX_GZIP_EXPANSION} bytes`,
        );
        inputStream.destroy();
        gunzip.destroy(err);
        output.destroy(err);
      }
    });

    pipeline(inputStream, gunzip, output, (err) => {
      if (err) {
        if (!inputStream.destroyed) inputStream.destroy();
        const failure =
          err instanceof ArtifactReaderFailure
            ? err
            : new ArtifactReaderFailure(
                "format",
                `GZIP decompression error: ${err.message}`,
                { cause: err },
              );
        output.destroy(failure);
      }
    });

    output.on("close", () => {
      if (!gunzip.destroyed) gunzip.destroy();
    });

    if (signal) {
      const onAbort = () => {
        const failure = new ArtifactReaderFailure(
          "cancelled",
          "Decompression cancelled",
          { cancellation: { reason: signal.reason } },
        );
        inputStream.destroy();
        gunzip.destroy();
        output.destroy(failure);
      };
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener("abort", onAbort, { once: true });
        output.on("close", () => {
          signal.removeEventListener("abort", onAbort);
        });
      }
    }

    return output;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.owner !== undefined) {
      await this.owner.close();
      this.owner = undefined;
    }
  }
}
