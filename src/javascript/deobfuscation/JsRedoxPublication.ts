import { createHash } from "node:crypto";
import { join } from "node:path";
import { Readable } from "node:stream";

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../../application/AnalysisProvider.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { javascriptDeobfuscationResultSchema } from "../../domain/javascript/javascriptDeobfuscation.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import type {
  ProviderProcessRetainedOutput,
  ProviderProcessSnapshot,
} from "../../process/ProviderProcess.js";
import {
  JS_REDOX_LIMITATIONS,
  JS_REDOX_PROVIDER_IDENTITY,
  JS_REDOX_RELEASE,
} from "./JsRedoxRelease.js";
import { jsRedoxSourceSuffix } from "./JsRedoxSourceMode.js";
import type { JsRedoxReport } from "./JsRedoxProtocol.js";

export interface JsRedoxEngineIdentity {
  readonly configuredCommand: string;
  readonly command: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface JsRedoxLimiterIdentity {
  readonly configuredCommand: string;
  readonly command: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface JsRedoxLimiterRunIdentity {
  readonly snapshotPath: string;
  readonly snapshotSha256: string;
  readonly snapshotBytes: number;
  readonly arguments: readonly string[];
}

interface StableBytes {
  readonly bytes: Buffer;
  readonly sha256: string;
}

interface PublishedFiles {
  readonly source: Awaited<ReturnType<typeof writePublished>>;
  readonly output: Awaited<ReturnType<typeof writePublished>>;
  readonly report: Awaited<ReturnType<typeof writePublished>>;
  readonly manifest: Awaited<ReturnType<typeof writePublished>>;
  readonly diagnostics: {
    readonly version: Awaited<ReturnType<typeof publishCommandDiagnostics>>;
    readonly execution: Awaited<ReturnType<typeof publishCommandDiagnostics>>;
  };
}

export const publishJsRedox = async (input: {
  readonly sourcePath: string;
  readonly maxIterations: number;
  readonly tree: SafeOutputTree;
  readonly source: StableBytes;
  readonly output: StableBytes;
  readonly reportFile: StableBytes;
  readonly report: JsRedoxReport;
  readonly engine: JsRedoxEngineIdentity;
  readonly limiter: JsRedoxLimiterIdentity;
  readonly limiterRuns: {
    readonly version: JsRedoxLimiterRunIdentity;
    readonly execution: JsRedoxLimiterRunIdentity;
  };
  readonly version: string;
  readonly versionRun: ProviderProcessSnapshot;
  readonly versionOutput: ProviderProcessRetainedOutput;
  readonly executionRun: ProviderProcessSnapshot;
  readonly executionOutput: ProviderProcessRetainedOutput;
  readonly signal?: AbortSignal;
}): Promise<AnalysisExecution> => {
  const files = await publishFiles(input);
  const result = buildResult(input, files);
  return createAnalysisExecution(
    result,
    { ...JS_REDOX_PROVIDER_IDENTITY, version: input.version },
    {
      rawResult: jsonValueSchema.parse({
        version: files.diagnostics.version,
        execution: files.diagnostics.execution,
      }),
      subject: {
        path: input.sourcePath,
        sha256: input.source.sha256,
        format: "javascript",
      },
      locations: [
        { kind: "artifact-path", path: input.sourcePath },
        { kind: "artifact-path", path: files.output.path },
        { kind: "artifact-path", path: files.report.path },
      ],
      limitations: result.limitations,
    },
  );
};

const publishFiles = async (
  input: Parameters<typeof publishJsRedox>[0],
): Promise<PublishedFiles> => {
  const suffix = jsRedoxSourceSuffix(input.sourcePath);
  const source = await writePublished(
    input.tree,
    `inputs/source${suffix}`,
    input.source.bytes,
    input.signal,
  );
  const output = await writePublished(
    input.tree,
    `deobfuscated/source${suffix}`,
    input.output.bytes,
    input.signal,
  );
  const report = await writePublished(
    input.tree,
    "reports/js-redox.json",
    input.reportFile.bytes,
    input.signal,
  );
  const diagnostics = {
    version: await publishCommandDiagnostics(
      input.tree,
      "version",
      input.versionRun,
      input.versionOutput,
      input.signal,
    ),
    execution: await publishCommandDiagnostics(
      input.tree,
      "execution",
      input.executionRun,
      input.executionOutput,
      input.signal,
    ),
  };
  const manifestBytes = Buffer.from(
    `${JSON.stringify({ ...manifestValue(input, source, output, report), diagnostics }, null, 2)}\n`,
    "utf8",
  );
  const manifest = await writePublished(
    input.tree,
    "manifest.json",
    manifestBytes,
    input.signal,
  );
  return { source, output, report, manifest, diagnostics };
};

const manifestValue = (
  input: Parameters<typeof publishJsRedox>[0],
  source: PublishedFiles["source"],
  output: PublishedFiles["output"],
  report: PublishedFiles["report"],
) => ({
  schema: "rea-js-redox-publication/v1",
  source: {
    path: input.sourcePath,
    sha256: input.source.sha256,
    bytes: input.source.bytes.length,
    published_path: source.path,
  },
  output: {
    path: output.path,
    sha256: input.output.sha256,
    bytes: input.output.bytes.length,
  },
  report: {
    path: report.path,
    sha256: input.reportFile.sha256,
    bytes: input.reportFile.bytes.length,
  },
  engine: {
    path: input.engine.configuredCommand,
    resolved_path: input.engine.command,
    sha256: input.engine.sha256,
    bytes: input.engine.bytes,
    version: input.version,
    audited_source_revision: JS_REDOX_RELEASE.revision,
    executed_source_revision: null,
  },
  resource_limiter: {
    path: input.limiter.configuredCommand,
    resolved_path: input.limiter.command,
    sha256: input.limiter.sha256,
    bytes: input.limiter.bytes,
    runs: {
      version: limiterRunManifest(input.limiterRuns.version),
      execution: limiterRunManifest(input.limiterRuns.execution),
    },
  },
  options: { max_iterations: input.maxIterations },
});

const limiterRunManifest = (run: JsRedoxLimiterRunIdentity) => ({
  snapshot_path: run.snapshotPath,
  snapshot_sha256: run.snapshotSha256,
  snapshot_bytes: run.snapshotBytes,
  arguments: [...run.arguments],
});

const buildResult = (
  input: Parameters<typeof publishJsRedox>[0],
  files: PublishedFiles,
) => {
  return javascriptDeobfuscationResultSchema.parse({
    source: {
      path: input.sourcePath,
      sha256: input.source.sha256,
      bytes: input.source.bytes.length,
      published_copy: files.source,
    },
    options: { max_iterations: input.maxIterations },
    status:
      input.output.sha256 === input.source.sha256 ? "unchanged" : "changed",
    output: files.output,
    report: files.report,
    manifest: files.manifest,
    diagnostics: jsonObjectSchema.parse(files.diagnostics),
    proof: {
      input_sha256: input.report.input_sha256,
      output_sha256: input.output.sha256,
    },
    analysis_input: {
      input_path: join(input.tree.outputRoot, "deobfuscated"),
      format: "directory",
    },
    runtime_execution: "not-performed",
    limitations: [...JS_REDOX_LIMITATIONS],
  });
};

const publishCommandDiagnostics = async (
  tree: SafeOutputTree,
  name: "version" | "execution",
  snapshot: ProviderProcessSnapshot,
  retainedOutput: ProviderProcessRetainedOutput,
  signal?: AbortSignal,
) => ({
  exit_code: snapshot.exitCode ?? null,
  exit_signal: snapshot.signal ?? null,
  truncated: snapshot.diagnosticTruncated ?? false,
  stdout: {
    ...(await writePublished(
      tree,
      `diagnostics/${name}.stdout.txt`,
      retainedOutput.stdout,
      signal,
    )),
    observed_bytes: snapshot.stdout.observedBytes,
  },
  stderr: {
    ...(await writePublished(
      tree,
      `diagnostics/${name}.stderr.txt`,
      retainedOutput.stderr,
      signal,
    )),
    observed_bytes: snapshot.stderr.observedBytes,
  },
});

const writePublished = async (
  tree: SafeOutputTree,
  relativePath: string,
  bytes: Buffer,
  signal?: AbortSignal,
) => {
  const written = await tree.write(
    relativePath,
    Readable.from([bytes]),
    { sha256: sha256(bytes), bytes: bytes.length },
    signal,
  );
  return {
    path: join(tree.outputRoot, written.relativePath),
    sha256: written.sha256,
    bytes: written.bytesWritten,
  };
};

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");
