import fs from "node:fs";
import { lstat, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { err, ok, type Result } from "../domain/result.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { RegularFileCleanupFailure } from "../filesystem/OwnedRegularFile.js";
import { readRegularFile, retryRegularFileCleanup } from "./RegularFileRead.js";
import { referenceSourceResourceFailure } from "../reference/ReferenceSourceReaderErrors.js";
import type { ReferenceSourceReaderError } from "../reference/ReferenceSourceReaderTypes.js";

export type ReferenceSourceVcsInfo =
  | {
      readonly kind: "git";
      readonly head: string;
      readonly dirty: boolean | null;
    }
  | { readonly kind: "none"; readonly head: null; readonly dirty: null }
  | { readonly kind: "unknown"; readonly head: null; readonly dirty: null };

export interface ReferenceSourceVcsObservation {
  readonly info: ReferenceSourceVcsInfo;
  /** `null` means a repository was found but its local setting was unreadable or invalid. */
  readonly ignoreCase: boolean | null;
}

/**
 * Read Git metadata for a directory using isomorphic-git.
 *
 * No git subprocess or network is used; only the local `.git` object store is read.
 */
export const readReferenceSourceVcs = async (
  root: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<
  Result<ReferenceSourceVcsObservation, ReferenceSourceReaderError>
> => {
  try {
    return await resources.run(async () => {
      // Like Git, a subdirectory belongs to its nearest enclosing repository;
      // only a missing `.git` at every ancestor means no version control.
      let repository = resolve(root);
      for (;;) {
        if (isAborted(signal))
          return ok({ info: unknownVcs(), ignoreCase: null });
        try {
          await lstat(join(repository, ".git"));
          break;
        } catch (cause: unknown) {
          if (errorCode(cause) !== "ENOENT")
            return ok({ info: unknownVcs(), ignoreCase: null });
        }
        const parent = dirname(repository);
        if (parent === repository)
          return ok({
            info: { kind: "none", head: null, dirty: null },
            ignoreCase: false,
          });
        repository = parent;
      }
      let ignoreCase: boolean | null = null;
      try {
        const metadata = await resolveGitMetadata(
          repository,
          resources,
          signal,
        );
        ignoreCase = await readIgnoreCase(metadata, resources, signal);
        const head = await resolveSourceHead(metadata, resources, signal);
        if (isAborted(signal))
          return ok({ info: unknownVcs(), ignoreCase: null });
        return ok({ info: { kind: "git", head, dirty: null }, ignoreCase });
      } catch (cause: unknown) {
        if (cause instanceof ArtifactReaderFailure) throw cause;
        return ok({ info: unknownVcs(), ignoreCase });
      }
    });
  } catch (cause: unknown) {
    if (!(cause instanceof ArtifactReaderFailure)) throw cause;
    return err(referenceSourceResourceFailure(cause));
  }
};

const unknownVcs = (): ReferenceSourceVcsInfo => ({
  kind: "unknown",
  head: null,
  dirty: null,
});

interface GitMetadataIdentity {
  readonly gitdir: string;
  readonly commonDirectory?: string;
}

const readIgnoreCase = async (
  metadata: GitMetadataIdentity,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<boolean | null> => {
  try {
    const configPath = join(
      metadata.commonDirectory ?? metadata.gitdir,
      "config",
    );
    const configText = await readOwnedMetadataText(
      configPath,
      resources,
      signal,
    );
    return parseEffectiveIgnoreCase(configText);
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) throw cause;
    return null;
  }
};

// Preserve symlink/.. traversal until the filesystem resolves the identity.
// path.resolve/join would collapse those components before following the link.
const canonicalGitDirectory = (base: string, path: string): Promise<string> =>
  realpath(isAbsolute(path) ? path : `${base}${sep}${path}`);

/** Resolve repository identity once for the config and HEAD consumers. */
const resolveGitMetadata = async (
  root: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GitMetadataIdentity> => {
  const dotgit = join(root, ".git");
  const metadata = await lstat(dotgit);
  const directory = metadata.isSymbolicLink() ? await stat(dotgit) : metadata;
  const gitdir = await canonicalGitDirectory(
    root,
    directory.isDirectory()
      ? dotgit
      : await readGitMetadataPath(dotgit, "gitdir: ", resources, signal),
  );
  let common: string;
  try {
    common = await readGitMetadataPath(
      join(gitdir, "commondir"),
      "",
      resources,
      signal,
    );
  } catch (cause: unknown) {
    if (errorCode(cause) !== "ENOENT") throw cause;
    return { gitdir };
  }
  // Only an absent pointer means there is no common directory. An unreadable
  // target leaves identity unknown instead of falling back to private metadata.
  return {
    gitdir,
    commonDirectory: await canonicalGitDirectory(gitdir, common),
  };
};

const readGitMetadataPath = async (
  path: string,
  prefix: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<string> => {
  // Git strips trailing CR/LF record terminators, not path whitespace. Decode
  // strictly so invalid UTF-8 cannot select a different replacement-character path.
  const record = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
    .decode(await readOwnedMetadataBytes(path, resources, signal))
    .replace(/[\r\n]+$/u, "");
  const target = record.slice(prefix.length);
  if (!record.startsWith(prefix) || target === "" || target.includes("\0"))
    throw new Error("Invalid Git metadata directory pointer");
  return target;
};

// Git config syntax uses ASCII whitespace; Unicode whitespace remains data.
const trimGitConfigWhitespace = (value: string): string =>
  value.replace(/^[ \t\r]+|[ \t\r]+$/gu, "");

/** Read Git's section/subsection syntax without flattening includeIf identities. */
const parseEffectiveIgnoreCase = (text: string): boolean | null => {
  let section: string | undefined;
  let subsection: string | undefined;
  const values: string[] = [];
  let worktreeConfig: boolean | null | undefined;
  let worktreeConfigUnknown = false;
  // Only a BOM at the start of the file is an encoding marker.
  for (const rawLine of text.replace(/^\uFEFF/u, "").split(/\r?\n/u)) {
    const line = trimGitConfigWhitespace(rawLine);
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const header =
      /^\[([A-Za-z][A-Za-z0-9-]*)(?:[ \t]+"((?:[^"\\]|\\.)*)")?\](?:[ \t]*[#;].*)?$/u.exec(
        line,
      );
    if (header !== null) {
      if (/\\(?![\\"])/u.test(header[2] ?? "")) return null;
      section = header[1]?.toLowerCase();
      subsection = header[2]?.replace(/\\([\\"])/gu, "$1");
      if (section === "include" || section === "includeif") return null;
      continue;
    }
    if (section === undefined) return null;
    const variable = /^([A-Za-z][A-Za-z0-9-]*)[ \t]*(?:=[ \t\r]*(.*))?$/u.exec(
      line,
    );
    if (variable === null) return null;
    const name = variable[1]?.toLowerCase();
    const sourceValue = variable[2];
    const parsedValue =
      sourceValue === undefined ? "true" : parseGitConfigValue(sourceValue);
    // This parser deliberately supports only ordinary single-line Git config
    // values. If any value is outside that grammar, no nearby core setting is
    // trusted: Git may reject the file or apply a different interpretation.
    if (parsedValue === undefined) return null;
    if (section === "core" && subsection === undefined && name === "ignorecase")
      values.push(parsedValue);
    if (
      section === "extensions" &&
      subsection === undefined &&
      name === "worktreeconfig"
    ) {
      worktreeConfig = parseGitBoolean(parsedValue);
      if (worktreeConfig === null) worktreeConfigUnknown = true;
    }
  }
  if (worktreeConfig === true || worktreeConfigUnknown) return null;
  const parsedValues = values.map(parseGitBoolean);
  if (parsedValues.some((value) => value === null)) return null;
  return parsedValues.at(-1) ?? null;
};

const parseGitBoolean = (value: string | undefined): boolean | null => {
  switch (value?.toLowerCase()) {
    case "true":
    case "yes":
    case "on":
      return true;
    case "":
    case "false":
    case "no":
    case "off":
      return false;
  }
  if (value === undefined) return null;
  // Git parses numeric booleans as base-0 signed integers with binary units.
  // Keep the portable decimal/octal/hex grammar; C23 binary prefixes depend
  // on the Git/libc build and cannot be inferred from this local config.
  const numeric =
    /^[ \t\r\n\v\f]*([+-]?)(0[xX][0-9A-Fa-f]+|0[0-7]*|[1-9][0-9]*)([kKmMgG]?)$/u.exec(
      value,
    );
  if (numeric === null || numeric[0] !== value) return null;
  const digits = numeric[2]!;
  const radix = /^0x/iu.test(digits) ? 16 : digits.startsWith("0") ? 8 : 10;
  const multiplier =
    numeric[3] === ""
      ? 1
      : 1024 ** ("kmg".indexOf(numeric[3]!.toLowerCase()) + 1);
  const integer =
    Number.parseInt(digits, radix) * multiplier * (numeric[1] === "-" ? -1 : 1);
  // Every integer within Git's signed-int range is exact in a Number; larger
  // values (including Infinity) must stay unknown, never wrap into a boolean.
  return integer >= -2147483648 && integer <= 2147483647 ? integer !== 0 : null;
};

const parseGitConfigValue = (source: string): string | undefined => {
  let quoted = false;
  let parsed = "";
  let trimFrom: number | undefined;
  for (let index = 0; index < source.length; index++) {
    const character = source[index]!;
    if (!quoted && /[ \t\r]/u.test(character)) {
      if (parsed.length > 0) {
        trimFrom ??= parsed.length;
        parsed += character;
      }
      continue;
    }
    if (!quoted && (character === "#" || character === ";")) break;
    // A later fragment consumes preceding whitespace, even if its quotes are
    // empty. Only trailing unquoted whitespace is discarded; escapes stay data.
    trimFrom = undefined;
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (character !== "\\") {
      parsed += character;
      continue;
    }
    const escaped = source[++index];
    switch (escaped) {
      case "\\":
      case '"':
        parsed += escaped;
        break;
      case "n":
        parsed += "\n";
        break;
      case "t":
        parsed += "\t";
        break;
      case "b":
        parsed += "\b";
        break;
      default:
        return undefined;
    }
  }
  return quoted ? undefined : parsed.slice(0, trimFrom);
};

const readOwnedMetadataText = async (
  path: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<string> =>
  (await readOwnedMetadataBytes(path, resources, signal)).toString("utf8");

const readOwnedMetadataBytes = async (
  path: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Buffer> => {
  try {
    return await readRegularFile(path, { signal });
  } catch (cause: unknown) {
    if (signal?.aborted === true && cause === signal.reason)
      throw new ArtifactReaderFailure(
        "cancelled",
        "Git metadata read cancelled",
        {
          cause,
          cancellation: { reason: signal.reason },
        },
      );
    if (!(cause instanceof RegularFileCleanupFailure)) {
      if (isAborted(signal))
        throw new ArtifactReaderFailure(
          "cancelled",
          "Git metadata read cancelled",
          {
            cause: signal?.reason,
            cancellation: { reason: signal?.reason },
          },
        );
      throw cause;
    }
    const retry = await retryRegularFileCleanup(cause, resources, signal);
    if (retry.cleanup !== undefined || retry.outcome.kind === "failed") {
      const primary =
        retry.outcome.kind === "failed"
          ? retry.outcome.cause
          : cause.cleanupCause;
      throw new ArtifactReaderFailure(
        isAborted(signal) ? "cancelled" : "io",
        `Git metadata could not be read safely: ${errorMessage(primary)}`,
        {
          cause: primary,
          ...(isAborted(signal)
            ? { cancellation: { reason: signal?.reason } }
            : {}),
          ...(retry.cleanup === undefined ? {} : { cleanup: retry.cleanup }),
        },
      );
    }
    if (isAborted(signal))
      throw new ArtifactReaderFailure(
        "cancelled",
        "Git metadata read cancelled",
        {
          cause: signal?.reason,
          cancellation: { reason: signal?.reason },
        },
      );
    return retry.outcome.value;
  }
};

const resolveSourceHead = async (
  metadata: GitMetadataIdentity,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<string> => {
  // isomorphic-git is loaded on first use so CLI and MCP startup skip it.
  const { resolveRef } = await import("isomorphic-git");
  let failedRead: { readonly cause: unknown } | undefined;
  const cleanupFailures: ArtifactReaderFailure[] = [];
  const readMetadataBytes = async (path: string): Promise<Buffer> => {
    try {
      return await readOwnedMetadataBytes(path, resources, signal);
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure) {
        if (cause.reason !== "cancelled" && errorCode(cause.cause) !== "ENOENT")
          failedRead ??= { cause: cause.cause };
        throw cause;
      }
      throw cause;
    }
  };
  const readMetadataText = async (path: string): Promise<string> =>
    (await readMetadataBytes(path)).toString("utf8");
  const throwCleanupFailures = (primary: unknown): never => {
    const observations = cleanupFailures.flatMap((failure) =>
      failure.cleanup === undefined ? [] : [failure.cleanup],
    );
    throw new ArtifactReaderFailure(
      isAborted(signal) ? "cancelled" : "io",
      `Git metadata could not be read safely: ${errorMessage(primary)}`,
      {
        cause: new AggregateError(
          [primary, ...cleanupFailures],
          "Git metadata reads and cleanup failed",
          { cause: primary },
        ),
        ...(observations.length === 0
          ? {}
          : {
              cleanup: {
                reason: observations.map(({ reason }) => reason).join("; "),
                resources: [
                  ...new Set(
                    observations.flatMap(({ resources }) => resources),
                  ),
                ],
              },
            }),
      },
    );
  };
  const referenceFs = {
    ...fs,
    promises: {
      ...fs.promises,
      // Let isomorphic-git continue from a failed loose ref to packed-refs,
      // then report the original read failure after resolution. This preserves
      // both observations when packed metadata also fails cleanup.
      readFile: async (
        path: string | undefined,
        options:
          | BufferEncoding
          | { readonly encoding?: BufferEncoding | null }
          | null = null,
      ) => {
        // The library probes readFile() without a path to detect promise APIs.
        // Reject that invocation without attributing it to a source read.
        if (path === undefined)
          throw new TypeError("Git metadata path is required");
        try {
          const bytes = await readMetadataBytes(path);
          const encoding =
            typeof options === "string"
              ? options
              : typeof options === "object" &&
                  options !== null &&
                  "encoding" in options
                ? options.encoding
                : undefined;
          if (encoding === undefined || encoding === null) return bytes;
          if (typeof encoding !== "string" || !Buffer.isEncoding(encoding))
            throw new TypeError("Unsupported Git metadata text encoding");
          return bytes.toString(encoding);
        } catch (cause: unknown) {
          if (cause instanceof ArtifactReaderFailure) {
            cleanupFailures.push(cause);
          } else if (errorCode(cause) !== "ENOENT") failedRead ??= { cause };
          throw cause;
        }
      },
    },
  };
  const readRef = async (options: {
    readonly gitdir: string;
    readonly ref: string;
  }) => {
    let head: string;
    try {
      head = await resolveRef({ fs: referenceFs, ...options });
    } catch (cause: unknown) {
      if (cleanupFailures.length > 0)
        throwCleanupFailures(failedRead?.cause ?? cause);
      if (failedRead !== undefined) throw failedRead.cause;
      throw cause;
    }
    if (cleanupFailures.length > 0)
      throwCleanupFailures(failedRead?.cause ?? cleanupFailures[0]?.cause);
    signal?.throwIfAborted();
    if (failedRead !== undefined) throw failedRead.cause;
    return head;
  };
  const { gitdir, commonDirectory } = metadata;
  if (commonDirectory === undefined) return readRef({ gitdir, ref: "HEAD" });
  const head = (await readMetadataText(join(gitdir, "HEAD"))).trim();
  if (!head.startsWith("ref: ")) return readRef({ gitdir, ref: "HEAD" });
  const ref = head.slice(5);
  const privateRef = ["refs/bisect/", "refs/rewritten/", "refs/worktree/"].some(
    (prefix) => ref.startsWith(prefix),
  );
  return readRef({
    gitdir: privateRef ? gitdir : commonDirectory,
    ref,
  });
};

const errorCode = (cause: unknown): string | undefined =>
  typeof cause === "object" && cause !== null && "code" in cause
    ? String(cause.code)
    : undefined;

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;
