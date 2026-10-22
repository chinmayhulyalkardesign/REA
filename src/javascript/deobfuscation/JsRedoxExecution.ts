import { constants } from "node:fs";
import { access, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { TextDecoder } from "node:util";

import type { AnalysisExecution } from "../../application/AnalysisProvider.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type { JavaScriptDeobfuscationInput } from "../../domain/javascript/javascriptDeobfuscation.js";
import type {
  ProviderProcessRetainedOutput,
  ProviderProcessSnapshot,
} from "../../process/ProviderProcess.js";
import { OwnedCommandFailure } from "../../process/OwnedCommand.js";
import { boundedUtf8Text } from "../../process/boundedUtf8Text.js";
import {
  JS_REDOX_LIMITS,
  JS_REDOX_PROVIDER_IDENTITY,
  JS_REDOX_RELEASE,
} from "./JsRedoxRelease.js";
import { jsRedoxSourceMode, jsRedoxSourceSuffix } from "./JsRedoxSourceMode.js";
import {
  parseJsRedoxReport,
  parseJsRedoxVersion,
  validateJsRedoxReport,
} from "./JsRedoxProtocol.js";
import {
  publishJsRedox,
  type JsRedoxEngineIdentity,
  type JsRedoxLimiterIdentity,
  type JsRedoxLimiterRunIdentity,
} from "./JsRedoxPublication.js";

const OPERATION = "deobfuscate_javascript_source";

export interface JsRedoxEngine extends JsRedoxEngineIdentity {
  readonly limiter: JsRedoxLimiterIdentity & {
    readonly executable: Buffer;
  };
  readonly executable: Buffer;
}

interface StableSource {
  readonly bytes: Buffer;
  readonly sha256: string;
}

export interface JsRedoxRunRequest {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly cwd: string;
  readonly signal?: AbortSignal;
  readonly timeoutMs: number;
}

export interface JsRedoxRunResult {
  readonly snapshot: ProviderProcessSnapshot;
  readonly retainedOutput: ProviderProcessRetainedOutput;
  readonly limiter: JsRedoxLimiterRunIdentity;
}

export const executeJsRedox = async (input: {
  readonly request: JavaScriptDeobfuscationInput;
  readonly signal?: AbortSignal;
  readonly engine: JsRedoxEngine;
  readonly source: StableSource;
  readonly runtimePath: string;
  readonly tree: SafeOutputTree;
  readonly resourceScope?: ArtifactResourceScope;
  readonly run: (request: JsRedoxRunRequest) => Promise<JsRedoxRunResult>;
}): Promise<AnalysisExecution> => {
  const snapshotPath = join(
    input.runtimePath,
    `source${jsRedoxSourceSuffix(input.request.path)}`,
  );
  const versionEnginePath = await snapshotEngine(input, "version");
  const outputPath = join(input.runtimePath, "deobfuscated.js");
  const reportPath = join(input.runtimePath, "report.json");
  assertActive(input.signal);
  await writeFile(snapshotPath, input.source.bytes, {
    flag: "wx",
    mode: 0o600,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  const deadlineAt = performance.now() + JS_REDOX_LIMITS.timeoutMs;
  const runWithinDeadline = (
    command: string,
    arguments_: readonly string[],
  ) => {
    const timeoutMs = remainingTimeoutMs(deadlineAt);
    return input.run({
      command,
      arguments: arguments_,
      cwd: input.runtimePath,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
      timeoutMs,
    });
  };

  let versionObservation: JsRedoxRunResult;
  try {
    versionObservation = await runWithinDeadline(versionEnginePath, [
      "--version",
    ]);
  } catch (cause: unknown) {
    if (
      cause instanceof OwnedCommandFailure &&
      cause.cleanupOwner === undefined &&
      cause.reason !== "cancelled" &&
      cause.reason !== "timeout" &&
      cause.reason !== "output-limit" &&
      cause.snapshot?.signal !== "SIGXCPU" &&
      cause.snapshot?.signal !== "SIGXFSZ"
    )
      throw new AnalysisCapabilityUnavailableError(
        JS_REDOX_PROVIDER_IDENTITY.id,
        OPERATION,
        `Configured js-redox failed its required --version probe: ${cause.message}`,
        {
          cause,
          userMessage: `Provide js-redox deobfuscate-safe ${JS_REDOX_RELEASE.version}; the configured executable must support the audited --version probe.`,
          diagnostics: {
            configured_executable: input.engine.configuredCommand,
            exit_code: cause.snapshot?.exitCode ?? null,
            signal: cause.snapshot?.signal ?? null,
          },
          ...(cause.snapshot === null
            ? {}
            : { capturedOutput: boundedVersionCapturedOutput(cause.snapshot) }),
        },
      );
    throw cause;
  }
  const versionRun = versionObservation.snapshot;
  const version = parseJsRedoxVersion(versionRun.stdout.text);
  if (version !== JS_REDOX_RELEASE.version) {
    throw new AnalysisCapabilityUnavailableError(
      JS_REDOX_PROVIDER_IDENTITY.id,
      OPERATION,
      `Unsupported js-redox version ${version ?? "unrecognized"}; verified version is ${JS_REDOX_RELEASE.version}.`,
      {
        userMessage: `Provide js-redox deobfuscate-safe ${JS_REDOX_RELEASE.version}; the configured executable reported ${version ?? "an unrecognized version"}.`,
        diagnostics: {
          configured_executable: input.engine.configuredCommand,
          observed_version: version,
        },
        capturedOutput: boundedVersionCapturedOutput(versionRun),
      },
    );
  }

  // runOwnedCommand has settled the complete version process family. A fresh
  // exclusive copy cannot follow a pathname the version probe replaced.
  const transformEnginePath = await snapshotEngine(input, "transform");
  const executionObservation = await runWithinDeadline(transformEnginePath, [
    snapshotPath,
    outputPath,
    "--report",
    reportPath,
    "--max-iterations",
    String(input.request.max_iterations),
  ]);
  const executionRun = executionObservation.snapshot;
  const output = await readStableArtifact(
    outputPath,
    JS_REDOX_LIMITS.outputBytes,
    input.signal,
    undefined,
    input.resourceScope,
  );
  assertUtf8JavaScript(output.bytes);
  let reportFile: StableSource;
  try {
    reportFile = await readStableArtifact(
      reportPath,
      JS_REDOX_LIMITS.reportBytes,
      input.signal,
      undefined,
      input.resourceScope,
    );
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
      throw new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        "js-redox proof report exceeded its configured size ceiling.",
        { report_bytes_ceiling: JS_REDOX_LIMITS.reportBytes },
        { cause },
      );
    throw cause;
  }
  const report = parseJsRedoxReport(reportFile.bytes);
  validateJsRedoxReport(report, {
    inputSha256: input.source.sha256,
    outputSha256: output.sha256,
    changed: output.sha256 !== input.source.sha256,
    maxIterations: input.request.max_iterations,
    sourceMode: jsRedoxSourceMode(input.request.path),
  });
  await assertInputsUnchanged(
    input.request.path,
    input.source.sha256,
    input.engine,
    input.signal,
    input.resourceScope,
  );
  return publishJsRedox({
    sourcePath: input.request.path,
    maxIterations: input.request.max_iterations,
    tree: input.tree,
    source: input.source,
    output,
    reportFile,
    report,
    engine: input.engine,
    limiter: input.engine.limiter,
    limiterRuns: {
      version: versionObservation.limiter,
      execution: executionObservation.limiter,
    },
    version,
    versionRun,
    versionOutput: versionObservation.retainedOutput,
    executionRun,
    executionOutput: executionObservation.retainedOutput,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
};

const VERSION_DIAGNOSTIC_TEXT_BYTES = 4_096;

const boundedVersionCapturedOutput = (snapshot: ProviderProcessSnapshot) => {
  const stdout = boundedUtf8Text(
    snapshot.stdout.text,
    VERSION_DIAGNOSTIC_TEXT_BYTES,
  );
  const stderr = boundedUtf8Text(
    snapshot.stderr.text,
    VERSION_DIAGNOSTIC_TEXT_BYTES,
  );
  return {
    stdout: stdout.text,
    stderr: stderr.text,
    stdout_bytes: snapshot.stdout.observedBytes,
    stderr_bytes: snapshot.stderr.observedBytes,
    exit_code: snapshot.exitCode ?? null,
    signal: snapshot.signal ?? null,
    truncated:
      snapshot.diagnosticTruncated === true ||
      stdout.truncated ||
      stderr.truncated,
  };
};

const assertUtf8JavaScript = (bytes: Buffer): void => {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause: unknown) {
    throw new AnalysisOutputError(
      OPERATION,
      "js-redox returned transformed JavaScript that is not valid UTF-8.",
      { cause },
    );
  }
};

export const snapshotJsRedoxExecutable = async (input: {
  readonly runtimePath: string;
  readonly fileName: string;
  readonly executable: Buffer;
  readonly sha256: string;
  readonly bytes: number;
  readonly label: "js-redox" | "resource-limiter";
  readonly signal?: AbortSignal;
  readonly resourceScope?: ArtifactResourceScope;
}): Promise<{
  readonly command: string;
  readonly sha256: string;
  readonly bytes: number;
}> => {
  const path = join(input.runtimePath, input.fileName);
  assertActive(input.signal);
  await writeFile(path, input.executable, {
    flag: "wx",
    mode: 0o700,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  try {
    // Linux access(X_OK) also checks the filesystem's noexec mount policy.
    await access(path, constants.X_OK);
  } catch (cause: unknown) {
    assertActive(input.signal);
    throw new AnalysisCapabilityUnavailableError(
      JS_REDOX_PROVIDER_IDENTITY.id,
      OPERATION,
      `The private ${input.label} snapshot is not executable. Select an exec-capable TMPDIR; noexec runtime mounts are unsupported.`,
      {
        cause,
        userMessage:
          "Set TMPDIR to a writable exec-capable filesystem and retry.",
      },
    );
  }
  const snapshot = await readStableArtifact(
    path,
    JS_REDOX_LIMITS.executableBytes,
    input.signal,
    undefined,
    input.resourceScope,
  );
  if (snapshot.sha256 !== input.sha256 || snapshot.bytes.length !== input.bytes)
    throw new AnalysisOutputError(
      OPERATION,
      `Owned ${input.label} snapshot disagrees with the fingerprinted executable bytes.`,
    );
  return {
    command: path,
    sha256: snapshot.sha256,
    bytes: snapshot.bytes.length,
  };
};

const snapshotEngine = (
  input: {
    readonly runtimePath: string;
    readonly engine: JsRedoxEngine;
    readonly signal?: AbortSignal;
    readonly resourceScope?: ArtifactResourceScope;
  },
  phase: "version" | "transform",
) =>
  snapshotJsRedoxExecutable({
    runtimePath: input.runtimePath,
    fileName: `deobfuscate-safe-${phase}`,
    executable: input.engine.executable,
    sha256: input.engine.sha256,
    bytes: input.engine.bytes,
    label: "js-redox",
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    ...(input.resourceScope === undefined
      ? {}
      : { resourceScope: input.resourceScope }),
  }).then(({ command }) => command);

const remainingTimeoutMs = (deadlineAt: number): number => {
  const remaining = deadlineAt - performance.now();
  if (remaining <= 0)
    throw new AnalysisTimeoutError(OPERATION, JS_REDOX_LIMITS.timeoutMs);
  return Math.max(1, remaining);
};

const assertActive = (signal?: AbortSignal): void => {
  if (signal?.aborted)
    throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
};

const assertInputsUnchanged = async (
  sourcePath: string,
  sourceSha256: string,
  engine: JsRedoxEngine,
  signal?: AbortSignal,
  resourceScope?: ArtifactResourceScope,
): Promise<void> => {
  if ((await realpath(engine.configuredCommand)) !== engine.command)
    throw new AnalysisOutputError(
      OPERATION,
      "Configured js-redox executable selection changed during deobfuscation.",
    );
  const currentSource = await readStableArtifact(
    sourcePath,
    JS_REDOX_LIMITS.inputBytes,
    signal,
    undefined,
    resourceScope,
  );
  const currentEngine = await readStableArtifact(
    engine.command,
    JS_REDOX_LIMITS.executableBytes,
    signal,
    undefined,
    resourceScope,
  );
  if (currentSource.sha256 !== sourceSha256)
    throw new AnalysisOutputError(
      OPERATION,
      `Original input changed during deobfuscation: ${sourcePath}`,
    );
  if (currentEngine.sha256 !== engine.sha256)
    throw new AnalysisOutputError(
      OPERATION,
      "Configured js-redox executable changed during deobfuscation.",
    );
};
