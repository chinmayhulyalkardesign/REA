import { lstat } from "node:fs/promises";
import { Readable } from "node:stream";
import { finished, pipeline } from "node:stream/promises";
import { createInflateRaw } from "node:zlib";

import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  openRegularFile,
  RegularFileAdmissionFailure,
  sameRegularFileState,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
import { abortIfNeeded } from "./ArtifactHash.js";
import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";
import {
  findDotnetBundleHeader,
  readDotnetBundle,
  type DotnetBundle,
  type DotnetBundleFile,
} from "./dotnet/DotnetBundle.js";
import { hashStableRootArtifactHandle } from "./inventory/hashStableRootArtifact.js";

/** Stable, range-streamed .NET bundle reader; extraction paths remain owned by SafeOutputTree. */
export class DotnetBundleArtifactReader implements ArtifactReader {
  readonly format = "dotnet-bundle" as const;
  #source: StableRegularFileDescriptor | undefined;
  #owner: OwnedFileHandle | undefined;
  #bundle: DotnetBundle | undefined;
  #closed = false;
  readonly #entries = new Map<
    string,
    { entry: ArtifactEntry; file: DotnetBundleFile }
  >();
  readonly #streams = new Set<Readable>();

  constructor(
    private readonly path: string,
    source?: StableRegularFileDescriptor,
  ) {
    this.#source = source;
  }

  /** Bind extraction to the whole host that produced its inventory snapshot. */
  async prepareContainer(
    expectedSha256: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const source = await this.#getSource(signal);
    await this.#verifySource(source, signal);
    const observed = await hashStableRootArtifactHandle(
      this.path,
      source.handle,
      source.initial,
      signal,
    );
    if (observed.sha256 !== expectedSha256)
      throw new ArtifactReaderFailure(
        "integrity",
        ".NET bundle host differs from its inventoried root",
      );
  }

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    const source = await this.#getSource(signal);
    await this.#verifySource(source, signal);
    if (this.#bundle === undefined) {
      const header = await findDotnetBundleHeader(
        source.handle,
        source.initial.size,
        signal,
      );
      if (header === undefined)
        throw new ArtifactReaderFailure(
          "format",
          "Selected file has no .NET bundle header",
        );
      this.#bundle = await readDotnetBundle(
        source.handle,
        source.initial.size,
        header,
        signal,
      );
    }
    const bundle = this.#bundle;
    this.#entries.clear();
    for (const [index, file] of bundle.files.entries()) {
      abortIfNeeded(signal);
      const entry: ArtifactEntry = {
        path: file.path,
        kind: "file",
        declaredSize: file.size,
        compressedSize: file.compressedSize || null,
        byteOffset: file.offset,
        byteLength: file.compressedSize || file.size,
        executable: false,
        encrypted: false,
        declaredIntegrity: null,
        unpacked: false,
        adapterKey: String(index),
        formatMetadata: {
          kind: "dotnet-bundle-entry",
          major_version: bundle.majorVersion,
          minor_version: bundle.minorVersion,
          file_type: file.fileType,
        },
        limitations: [
          ".NET bundle file types are declarations, not proof of assembly validity or executable authority.",
          ...(file.fileType > 5
            ? [
                `Unknown .NET bundle file type ${file.fileType}; bytes are retained without interpreting the type.`,
              ]
            : []),
        ],
      };
      this.#entries.set(entry.adapterKey, {
        entry: copyArtifactEntry(entry),
        file,
      });
      yield entry;
    }
    await this.#verifySource(source, signal);
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    const source = await this.#getSource(signal);
    await this.#verifySource(source, signal);
    const selected = this.#entries.get(entry.adapterKey);
    if (selected === undefined || !sameArtifactEntry(entry, selected.entry))
      throw new ArtifactReaderFailure(
        "integrity",
        "Selected .NET bundle entry differs from its observed manifest",
      );
    const stream = Readable.from(
      this.#readMember(source, selected.file, signal),
      { objectMode: false },
    );
    this.#streams.add(stream);
    stream.once("close", () => this.#streams.delete(stream));
    return stream;
  }

  provenance() {
    return [];
  }

  async close(): Promise<void> {
    for (const stream of this.#streams) stream.destroy();
    await Promise.all(
      [...this.#streams].map((stream) =>
        finished(stream).catch(() => undefined),
      ),
    );
    if (this.#owner !== undefined) {
      // Clear ownership only after a confirmed close, so the resource scope can retry.
      await this.#owner.close();
      this.#owner = undefined;
    }
    this.#closed = true;
  }

  async #getSource(signal?: AbortSignal): Promise<StableRegularFileDescriptor> {
    abortIfNeeded(signal);
    if (this.#closed)
      throw new ArtifactReaderFailure(
        "unavailable",
        ".NET bundle reader is closed",
      );
    if (this.#source !== undefined) return this.#source;
    try {
      const handle = await openRegularFile(this.path, {
        symlinks: "reject",
        signal,
      });
      this.#owner = new OwnedFileHandle(handle);
      this.#source = { handle, initial: await handle.stat() };
      return this.#source;
    } catch (cause) {
      if (cause instanceof RegularFileAdmissionFailure)
        this.#owner = cause.owner;
      abortIfNeeded(signal);
      throw cause;
    }
  }

  async #verifySource(
    source: StableRegularFileDescriptor,
    signal?: AbortSignal,
  ): Promise<void> {
    abortIfNeeded(signal);
    const [opened, named] = await Promise.all([
      source.handle.stat(),
      lstat(this.path),
    ]).catch((cause: unknown) => {
      abortIfNeeded(signal);
      throw new ArtifactReaderFailure(
        "integrity",
        ".NET bundle host identity is no longer available",
        { cause },
      );
    });
    abortIfNeeded(signal);
    if (
      !sameRegularFileState(source.initial, opened) ||
      !sameRegularFileState(source.initial, named) ||
      named.isSymbolicLink()
    )
      throw new ArtifactReaderFailure(
        "integrity",
        ".NET bundle host changed during reading",
      );
  }

  async *#readMember(
    source: StableRegularFileDescriptor,
    file: DotnetBundleFile,
    signal?: AbortSignal,
  ): AsyncGenerator<Buffer> {
    const storedBytes = file.compressedSize || file.size;
    const input =
      storedBytes === 0
        ? Readable.from([])
        : readFileHandleChunks(source.handle, {
            start: file.offset,
            end: file.offset + storedBytes - 1,
            signal,
          });
    const inflater = file.compressedSize === 0 ? undefined : createInflateRaw();
    const decoded = inflater ?? input;
    const pumping =
      inflater === undefined ? undefined : pipeline(input, inflater);
    // Observe early pipeline rejections while the output iterator is still reading.
    void pumping?.catch(() => undefined);
    let bytes = 0;
    try {
      for await (const raw of decoded) {
        abortIfNeeded(signal);
        const chunk: Buffer = raw;
        bytes += chunk.length;
        if (bytes > file.size)
          throw new ArtifactReaderFailure(
            "limit",
            `.NET bundle entry expands beyond its declared size: ${file.path}`,
          );
        yield chunk;
      }
      await pumping;
      if (
        bytes !== file.size ||
        (inflater !== undefined && inflater.bytesWritten !== storedBytes)
      )
        throw new ArtifactReaderFailure(
          "format",
          `.NET bundle member length or compressed extent does not match its declaration: ${file.path}`,
        );
      await this.#verifySource(source, signal);
    } catch (cause) {
      abortIfNeeded(signal);
      if (cause instanceof ArtifactReaderFailure) throw cause;
      const malformedCompression =
        inflater !== undefined &&
        cause instanceof Error &&
        "code" in cause &&
        ["Z_DATA_ERROR", "Z_BUF_ERROR"].includes(String(cause.code));
      throw new ArtifactReaderFailure(
        malformedCompression ? "format" : "io",
        `Could not read .NET bundle member: ${file.path}`,
        { cause },
      );
    } finally {
      input.destroy();
      decoded.destroy();
      await pumping?.catch(() => undefined);
    }
  }
}
