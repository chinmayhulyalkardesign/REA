import { realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import {
  ArtifactFileCleanupFailure,
  artifactFileCancellationCause,
  bindArtifactFileCleanup,
} from "../../artifacts/ArtifactFileOperation.js";
import { AnalysisCleanupLeaseGroup } from "../../artifacts/AnalysisCleanupLease.js";
import {
  readStableArtifact,
  type StableArtifactSnapshot,
} from "../../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceSubjectTarget,
} from "../../domain/evidence.js";
import {
  JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS,
  javascriptDeobfuscationInputSchema,
  javascriptDeobfuscationResultSchema,
} from "../../domain/javascript/javascriptDeobfuscation.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { isPathWithinRoot } from "../../domain/localPath.js";
import { absoluteCallerPath } from "../../filesystem/callerPath.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { JavaScriptDeobfuscationPort } from "./JavaScriptDeobfuscationPort.js";

const OPERATION = "deobfuscate_javascript_source";

/** Shared CLI/MCP validation and Evidence for proof-gated JavaScript rewriting. */
export class JavaScriptDeobfuscationService {
  readonly #verificationResources = new ArtifactResourceScope();
  #closing = false;

  constructor(readonly provider: JavaScriptDeobfuscationPort) {}

  async close(): Promise<void> {
    this.#closing = true;
    const results = await Promise.allSettled([
      this.provider.close?.() ?? Promise.resolve(),
      this.#verificationResources.close(),
    ]);
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(
        failures,
        "JavaScript deobfuscation cleanup failed",
      );
  }

  async deobfuscate(
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (isAborted(options?.signal))
      return err(
        new AnalysisCancelledError(OPERATION, {
          cause: options?.signal?.reason,
        }),
      );
    if (this.#closing) return err(new AnalysisCancelledError(OPERATION));
    try {
      return await this.#verificationResources.run(
        () => this.#deobfuscate(input, options),
        options?.signal,
      );
    } catch (cause: unknown) {
      if (isAborted(options?.signal))
        return err(
          new AnalysisCancelledError(OPERATION, {
            cause: options?.signal?.reason,
          }),
        );
      if (
        cause instanceof ArtifactReaderFailure &&
        cause.reason === "cancelled"
      )
        return err(
          new AnalysisCancelledError(OPERATION, {
            cause: artifactFileCancellationCause(cause),
          }),
        );
      if (this.#closing)
        return err(
          new AnalysisCancelledError(OPERATION, {
            cause:
              options?.signal?.aborted === true ? options.signal.reason : cause,
          }),
        );
      if (cause instanceof ArtifactReaderFailure) {
        const failure = new AnalysisOutputError(
          OPERATION,
          "Artifact verification cleanup from a previous request remains incomplete.",
          { cause },
        );
        bindArtifactFileCleanup(cause, failure);
        return err(failure);
      }
      throw cause;
    }
  }

  async #deobfuscate(
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (isAborted(options?.signal))
      return err(
        new AnalysisCancelledError(OPERATION, {
          cause: options?.signal?.reason,
        }),
      );
    const parsed = javascriptDeobfuscationInputSchema.safeParse(input);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, parsed.error.issues, input, {
          cause: parsed.error,
        }),
      );
    const selected = Object.freeze({ ...parsed.data });
    let outputRoot: string;
    try {
      outputRoot = await canonicalOutputRoot(selected.output_directory);
    } catch (cause: unknown) {
      return err(
        new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["output_directory"],
            reason: "invalid_value",
            message:
              "output_directory must have an existing searchable parent directory.",
          },
        ]),
      );
    }
    const providerInput = Object.freeze({
      ...selected,
      output_directory: outputRoot,
    });
    const providerResult = await this.provider.deobfuscate(
      providerInput,
      options,
    );
    if (!providerResult.ok) return providerResult;
    const { execution, cleanup: providerCleanup } = providerResult.value;
    const returnedSubject = execution.subject;
    const subject: EvidenceSubjectTarget | null =
      returnedSubject === null || returnedSubject === undefined
        ? null
        : Object.freeze({ ...returnedSubject });
    const executionProvider = Object.freeze({ ...execution.provider });
    const executionLimitations = Object.freeze([...execution.limitations]);
    const result = javascriptDeobfuscationResultSchema.safeParse(
      execution.result,
    );
    if (!result.success || subject === null)
      return err(
        withProviderCleanup(
          new AnalysisOutputError(
            OPERATION,
            "Deobfuscation did not return a valid result bound to the original source",
          ),
          providerCleanup,
        ),
      );
    const diagnostics = result.data.diagnostics;
    const diagnosticFiles: ReturnedArtifactFile[] =
      diagnostics === undefined
        ? []
        : [
            { role: "version-stdout", ...diagnostics.version.stdout },
            { role: "version-stderr", ...diagnostics.version.stderr },
            { role: "execution-stdout", ...diagnostics.execution.stdout },
            { role: "execution-stderr", ...diagnostics.execution.stderr },
          ];
    const publishedFiles: ReturnedArtifactFile[] = [
      { role: "source-copy", ...result.data.source.published_copy },
      { role: "output", ...result.data.output },
      { role: "report", ...result.data.report },
      { role: "manifest", ...result.data.manifest },
      ...diagnosticFiles,
    ];
    if (
      result.data.source.path !== selected.path ||
      result.data.source.published_copy.sha256 !== result.data.source.sha256 ||
      result.data.source.published_copy.bytes !== result.data.source.bytes ||
      result.data.proof.input_sha256 !== result.data.source.sha256 ||
      result.data.proof.output_sha256 !== result.data.output.sha256 ||
      subject.path !== result.data.source.path ||
      subject.sha256 !== result.data.source.sha256 ||
      result.data.options.max_iterations !== selected.max_iterations ||
      (result.data.status === "unchanged") !==
        (result.data.source.sha256 === result.data.output.sha256) ||
      subject.format !== "javascript" ||
      result.data.analysis_input.input_path !== dirname(result.data.output.path)
    )
      return err(
        withProviderCleanup(
          new AnalysisOutputError(
            OPERATION,
            "Deobfuscation source, published artifacts, output status, or iteration bound disagrees with its Evidence binding",
          ),
          providerCleanup,
        ),
      );
    let artifactVerification: ReturnedArtifactVerification;
    try {
      artifactVerification = await verifyReturnedArtifacts(
        outputRoot,
        publishedFiles,
        result.data.analysis_input.input_path,
        this.#verificationResources,
      );
    } catch (cause: unknown) {
      if (
        cause instanceof ArtifactReaderFailure &&
        cause.reason === "cancelled"
      ) {
        const cancellation = new AnalysisCancelledError(OPERATION, {
          cause:
            options?.signal?.aborted === true
              ? options.signal.reason
              : artifactFileCancellationCause(cause),
        });
        bindArtifactFileCleanup(cause, cancellation);
        return err(withProviderCleanup(cancellation, providerCleanup));
      }
      const failure = new AnalysisOutputError(
        OPERATION,
        "Deobfuscation returned artifacts that could not be physically verified against their advertised identity",
        { cause },
      );
      bindArtifactFileCleanup(cause, failure);
      return err(withProviderCleanup(failure, providerCleanup));
    }
    if (!artifactVerification.valid)
      return err(
        withProviderCleanup(
          verificationOutputError(
            "Deobfuscation returned artifacts that escape, alias, or disagree with their advertised bytes",
            artifactVerification.cleanupFailures,
            artifactVerification.failure,
          ),
          providerCleanup,
        ),
      );
    const evidence = createEvidence(subject, executionProvider, {
      operation: OPERATION,
      parameters: jsonObjectSchema.parse(selected),
      result: jsonObjectSchema.parse(result.data),
      locations: [
        { kind: "artifact-path", path: selected.path },
        { kind: "artifact-path", path: result.data.output.path },
        { kind: "artifact-path", path: result.data.report.path },
      ],
      limitations: [
        ...new Set([...result.data.limitations, ...executionLimitations]),
      ],
      confidence: "derived",
      authority: "shipped-artifact",
    });
    const cleanup = completedEvidenceCleanupError(
      evidence,
      artifactVerification.cleanupFailures,
      providerCleanup,
    );
    if (cleanup !== undefined) {
      if (isAborted(options?.signal)) {
        const cancellation = new AnalysisCancelledError(OPERATION, {
          cause: options?.signal?.reason,
          cleanup: {
            reason: "Completed deobfuscation cleanup remains incomplete",
            resources: cleanup.cleanupResources,
          },
          partialObservation: evidence,
        }).bindCleanupDependencies([cleanup]);
        cancellation.retainSecondaryFailure(cleanup);
        return err(cancellation);
      }
      return err(cleanup);
    }
    if (isAborted(options?.signal))
      return err(
        new AnalysisCancelledError(OPERATION, {
          cause: options?.signal?.reason,
          partialObservation: evidence,
        }),
      );
    return ok(evidence);
  }
}

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;

const canonicalOutputRoot = async (path: string): Promise<string> => {
  const requested = absoluteCallerPath(path);
  return join(await realpath(dirname(requested)), basename(requested));
};

type ReturnedArtifactRole =
  | "source-copy"
  | "output"
  | "report"
  | "manifest"
  | "version-stdout"
  | "version-stderr"
  | "execution-stdout"
  | "execution-stderr";

interface ReturnedArtifactFile {
  readonly role: ReturnedArtifactRole;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

const returnedArtifactByteCeiling = (role: ReturnedArtifactRole): number => {
  switch (role) {
    case "source-copy":
      return JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.sourceBytes;
    case "output":
      return JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.outputBytes;
    case "report":
      return JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.reportBytes;
    case "manifest":
      return JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.manifestBytes;
    case "version-stdout":
    case "version-stderr":
    case "execution-stdout":
    case "execution-stderr":
      return JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.diagnosticBytes;
  }
};

const returnedPathsStayWithin = async (
  root: string,
  paths: readonly string[],
): Promise<boolean> => {
  const canonicalRoot = await realpath(root);
  if (canonicalRoot !== resolve(root)) return false;
  for (const path of paths) {
    const lexicalPath = resolve(path);
    if (!isPathWithinRoot(root, lexicalPath)) return false;
    const canonicalPath = await realpath(path);
    if (
      canonicalPath !== lexicalPath ||
      !isPathWithinRoot(canonicalRoot, canonicalPath)
    )
      return false;
  }
  return true;
};

interface ReturnedArtifactVerification {
  readonly valid: boolean;
  readonly cleanupFailures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[];
  readonly failure?: unknown;
}

const verifyReturnedArtifacts = async (
  root: string,
  files: readonly ReturnedArtifactFile[],
  analysisInputPath: string,
  resources: ArtifactResourceScope,
): Promise<ReturnedArtifactVerification> => {
  const cleanupFailures: ArtifactFileCleanupFailure<StableArtifactSnapshot>[] =
    [];
  const result = (
    valid: boolean,
    failure?: unknown,
  ): ReturnedArtifactVerification => ({
    valid,
    cleanupFailures: [...cleanupFailures],
    ...(failure === undefined ? {} : { failure }),
  });
  const paths = [...files.map(({ path }) => path), analysisInputPath];
  let before: boolean;
  try {
    before = await returnedPathsStayWithin(root, paths);
  } catch (cause: unknown) {
    return result(false, cause);
  }
  if (!before) return result(false);
  const rolePaths = files.map(({ path }) => resolve(path));
  if (new Set(rolePaths).size !== rolePaths.length) return result(false);
  const physicalIdentities = new Set<string>();
  for (const file of files) {
    const maximumBytes = returnedArtifactByteCeiling(file.role);
    if (file.bytes > maximumBytes) return result(false);
    let observed: StableArtifactSnapshot;
    try {
      observed = await readStableArtifact(
        file.path,
        maximumBytes,
        undefined,
        undefined,
        resources,
      );
    } catch (cause: unknown) {
      if (
        cause instanceof ArtifactFileCleanupFailure &&
        cause.fileCleanupFailure.outcome.kind === "completed"
      ) {
        observed = cause.fileCleanupFailure.outcome.value;
        cleanupFailures.push(cause);
      } else {
        if (cause instanceof ArtifactFileCleanupFailure)
          cleanupFailures.push(cause);
        return result(false, cause);
      }
    }
    if (
      observed.bytes.length !== file.bytes ||
      observed.sha256 !== file.sha256 ||
      observed.physicalIdentity === undefined
    )
      return result(false);
    const physicalIdentity = `${observed.physicalIdentity.device}:${observed.physicalIdentity.inode}`;
    if (physicalIdentities.has(physicalIdentity)) return result(false);
    physicalIdentities.add(physicalIdentity);
  }
  try {
    return result(await returnedPathsStayWithin(root, paths));
  } catch (cause: unknown) {
    return result(false, cause);
  }
};

const verificationCleanupLeases = (
  failures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
) => [...new Set(failures.flatMap((failure) => failure.cleanupLeases ?? []))];

const verificationCleanupResources = (
  failures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
) => [
  ...new Set(failures.flatMap((failure) => failure.cleanup?.resources ?? [])),
];

const bindVerificationCleanup = <ErrorType extends AnalysisError>(
  error: ErrorType,
  failures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
): ErrorType => {
  const leases = verificationCleanupLeases(failures);
  if (leases.length > 0) new AnalysisCleanupLeaseGroup(error, leases);
  return error;
};

const verificationOutputError = (
  reason: string,
  failures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
  primaryCause?: unknown,
): AnalysisOutputError => {
  if (failures.length === 0)
    return new AnalysisOutputError(
      OPERATION,
      reason,
      primaryCause === undefined ? {} : { cause: primaryCause },
    );
  const resources = verificationCleanupResources(failures);
  const causes = [
    ...new Set([
      ...(primaryCause === undefined ? [] : [primaryCause]),
      ...failures,
    ]),
  ];
  const cause = new AggregateError(
    causes,
    "Artifact verification and descriptor cleanup both failed",
  );
  return bindVerificationCleanup(
    new AnalysisOutputError(OPERATION, reason, {
      cause,
      cleanup: {
        reason: "Artifact verification descriptor cleanup remains incomplete",
        resources,
      },
    }),
    failures,
  );
};

const withProviderCleanup = (
  primary: AnalysisError,
  providerCleanup: AnalysisError | undefined,
): AnalysisError => {
  if (providerCleanup?.cleanupIncomplete !== true) return primary;
  const dependencies = primary.cleanupIncomplete
    ? [primary, providerCleanup]
    : [providerCleanup];
  return analysisErrorWithCleanupFailure(
    primary,
    providerCleanup,
    OPERATION,
  ).bindCleanupDependencies(dependencies);
};

const completedEvidenceCleanupError = (
  evidence: Evidence,
  verificationFailures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
  providerCleanup: AnalysisError | undefined,
): AnalysisOutputError | undefined => {
  const dependencies: AnalysisError[] = [];
  if (verificationFailures.length > 0)
    dependencies.push(verificationCleanupError(evidence, verificationFailures));
  if (providerCleanup?.cleanupIncomplete === true)
    dependencies.push(providerCleanup);
  if (dependencies.length === 0) return undefined;
  if (dependencies.length === 1 && verificationFailures.length > 0)
    return dependencies[0] as AnalysisOutputError;
  const resources = [
    ...new Set(dependencies.flatMap((failure) => failure.cleanupResources)),
  ];
  return new AnalysisOutputError(
    OPERATION,
    "Deobfuscation artifacts were verified, but completed-operation cleanup remains incomplete",
    {
      cause:
        dependencies.length === 1
          ? dependencies[0]
          : new AggregateError(
              dependencies,
              "Multiple completed deobfuscation cleanup owners remain",
            ),
      cleanup: {
        reason: "Completed deobfuscation cleanup remains incomplete",
        resources,
      },
      partialObservation: evidence,
      cleanupOnly: true,
    },
  ).bindCleanupDependencies(dependencies);
};

const verificationCleanupError = (
  evidence: Evidence,
  failures: readonly ArtifactFileCleanupFailure<StableArtifactSnapshot>[],
): AnalysisOutputError => {
  const resources = verificationCleanupResources(failures);
  const cause = new AggregateError(
    failures,
    "Verified artifact descriptor cleanup remains incomplete",
  );
  return bindVerificationCleanup(
    new AnalysisOutputError(
      OPERATION,
      "Deobfuscation artifacts were verified, but verification cleanup remains incomplete",
      {
        cause,
        cleanup: {
          reason: "Verified artifact descriptor cleanup remains incomplete",
          resources,
        },
        partialObservation: evidence,
        cleanupOnly: true,
      },
    ),
    failures,
  );
};
