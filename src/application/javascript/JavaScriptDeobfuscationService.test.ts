import { createHash } from "node:crypto";
import {
  link,
  mkdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it, onTestFinished, vi } from "vitest";

import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import {
  JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS,
  type JavaScriptDeobfuscationResult,
} from "../../domain/javascript/javascriptDeobfuscation.js";
import { err, ok } from "../../domain/result.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { JavaScriptDeobfuscationService } from "./JavaScriptDeobfuscationService.js";

const artifactBytes = Buffer.from("fixture");
const file = {
  path: "/tmp/source.js",
  sha256: createHash("sha256").update(artifactBytes).digest("hex"),
  bytes: artifactBytes.length,
};
const provider = {
  id: "fixture-deobfuscator",
  name: "Fixture deobfuscator",
  version: "1",
} as const;
const validSubject = {
  path: file.path,
  sha256: file.sha256,
  format: "javascript" as const,
};
const validExecution = (returned: JavaScriptDeobfuscationResult) =>
  createAnalysisExecution(returned, provider, { subject: validSubject });
const result = (outputRoot = "/tmp/out"): JavaScriptDeobfuscationResult => {
  const artifact = (relativePath: string) => ({
    path: join(outputRoot, relativePath),
    sha256: file.sha256,
    bytes: file.bytes,
  });
  return {
    source: { ...file, published_copy: artifact("inputs/source.js") },
    options: { max_iterations: 16 },
    status: "unchanged",
    output: artifact("deobfuscated/source.js"),
    report: artifact("reports/js-redox.json"),
    manifest: artifact("manifest.json"),
    proof: {
      input_sha256: file.sha256,
      output_sha256: file.sha256,
    },
    analysis_input: {
      input_path: join(outputRoot, "deobfuscated"),
      format: "directory",
    },
    runtime_execution: "not-performed",
    limitations: [],
  };
};

const diagnostics = (outputRoot: string) => {
  const artifact = (relativePath: string) => ({
    path: join(outputRoot, relativePath),
    sha256: file.sha256,
    bytes: file.bytes,
    observed_bytes: file.bytes,
  });
  return {
    version: {
      exit_code: 0,
      exit_signal: null,
      truncated: false,
      stdout: artifact("diagnostics/version.stdout.txt"),
      stderr: artifact("diagnostics/version.stderr.txt"),
    },
    execution: {
      exit_code: 0,
      exit_signal: null,
      truncated: false,
      stdout: artifact("diagnostics/execution.stdout.txt"),
      stderr: artifact("diagnostics/execution.stderr.txt"),
    },
  };
};

const materializeResult = async (
  returned: JavaScriptDeobfuscationResult,
): Promise<void> => {
  const diagnosticFiles =
    returned.diagnostics === undefined
      ? []
      : [
          returned.diagnostics.version.stdout.path,
          returned.diagnostics.version.stderr.path,
          returned.diagnostics.execution.stdout.path,
          returned.diagnostics.execution.stderr.path,
        ];
  const files = [
    returned.source.published_copy.path,
    returned.output.path,
    returned.report.path,
    returned.manifest.path,
    ...diagnosticFiles,
  ];
  for (const path of files) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, artifactBytes);
  }
  await mkdir(returned.analysis_input.input_path, { recursive: true });
};

const serviceForResult = (
  returned: JavaScriptDeobfuscationResult,
  materialize = false,
): JavaScriptDeobfuscationService =>
  new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      if (materialize) await materializeResult(returned);
      return ok({ execution: validExecution(returned) });
    },
  });

const invokeService = (
  service: JavaScriptDeobfuscationService,
  outputDirectory: string,
  maxIterations?: number,
) =>
  service.deobfuscate({
    path: file.path,
    output_directory: outputDirectory,
    ...(maxIterations === undefined ? {} : { max_iterations: maxIterations }),
  });

it("keeps provider cleanup live when physical verification rejects saved bytes", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-provider-cleanup-",
  );
  const outputRoot = join(root, "out");
  const returned = result(outputRoot);
  const cleanup = new ProviderCleanupError(
    "fixture-deobfuscator",
    ["published-output-tree"],
    { cleanup: "fixture" },
    { operation: "deobfuscate_javascript_source" },
  );
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      await writeFile(returned.output.path, "corrupt-after-publication");
      return ok({ execution: validExecution(returned), cleanup });
    },
  });
  onTestFinished(async () => service.close());

  const response = await invokeService(service, outputRoot);
  if (response.ok) throw new Error("expected physical verification failure");
  expect(projectAnalysisError(response.error).code).toBe("cleanup_incomplete");
  expect(response.error.cleanupResources).toContain("published-output-tree");

  cleanup.resolveCleanup();
  expect(response.error.cleanupIncomplete).toBe(false);
  expect(response.error.cleanupResources).toEqual([]);
  expect(projectAnalysisError(response.error).code).toBe("unreadable_output");
});

it.each(["changed", "unchanged"] as const)(
  "rejects %s status that contradicts source/output digests",
  async (status) => {
    const returned = result();
    returned.status = status;
    if (status === "unchanged") {
      returned.output = { ...returned.output, sha256: "b".repeat(64) };
    }
    const service = serviceForResult(returned);
    const response = await invokeService(service, "/tmp/out");
    if (response.ok) throw new Error("expected status binding rejection");
    expect(response.error._tag).toBe("AnalysisOutputError");
  },
);
it.each([64, 15])(
  "rejects provider options=%s for a requested bound of one",
  async (maximum) => {
    const returned = result();
    returned.options.max_iterations = maximum;
    const service = serviceForResult(returned);
    const response = await invokeService(service, "/tmp/out", 1);
    if (response.ok) throw new Error("expected iteration binding rejection");
    expect(response.error._tag).toBe("AnalysisOutputError");
  },
);
it.each([
  { ...file, sha256: "b".repeat(64) },
  { ...file, bytes: file.bytes + 1 },
])("rejects a published source copy with mismatched metadata", async (copy) => {
  const returned = result();
  returned.source.published_copy = copy;
  const service = serviceForResult(returned);
  const response = await invokeService(service, "/tmp/out");
  if (response.ok) throw new Error("expected published source mismatch");
  expect(response.error._tag).toBe("AnalysisOutputError");
});
it("preserves provider failures", async () => {
  const failure = new AnalysisCapabilityUnavailableError(
    "js-redox",
    "deobfuscate_javascript_source",
    "fixture unavailable",
  );
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => err(failure),
  });
  expect(await invokeService(service, "/tmp/out")).toEqual(err(failure));
});

it("accepts canonical provider paths beneath a symlinked output parent", async () => {
  const root = await createTestTempDirectory("rea-js-service-output-link-");
  const canonicalParent = join(root, "canonical");
  const aliasParent = join(root, "alias");
  await mkdir(canonicalParent);
  await symlink(canonicalParent, aliasParent);
  const selectedOutput = join(aliasParent, "out");
  const canonicalOutput = join(await realpath(aliasParent), "out");
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      const returned = result(canonicalOutput);
      await materializeResult(returned);
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, selectedOutput);
  if (!response.ok) throw response.error;
  expect(response.value.subject?.format).toBe("javascript");
});

it("binds symlink-dotdot output semantics before provider execution", async () => {
  const root = await createTestTempDirectory("rea-js-service-output-dotdot-");
  const canonicalParent = join(root, "canonical");
  const child = join(canonicalParent, "child");
  const alias = join(root, "alias");
  await mkdir(child, { recursive: true });
  await symlink(child, alias);
  const selectedOutput = `${alias}/../out`;
  const canonicalOutput = join(canonicalParent, "out");
  let providerOutput: string | undefined;
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async (request) => {
      expect(Object.isFrozen(request)).toBe(true);
      providerOutput = request.output_directory;
      const returned = result(canonicalOutput);
      await materializeResult(returned);
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, selectedOutput);
  if (!response.ok) throw response.error;
  expect(providerOutput).toBe(canonicalOutput);
  expect(response.value.parameters).toMatchObject({
    output_directory: selectedOutput,
  });
});

it("carries normalized result limitations into Evidence", async () => {
  const root = await createTestTempDirectory("rea-js-service-limitations-");
  const output = join(root, "out");
  const returned = result(output);
  returned.limitations = ["provider-normalized caveat"];
  const service = serviceForResult(returned, true);
  const response = await invokeService(service, output);
  if (!response.ok) throw response.error;
  expect(response.value.limitations).toContain("provider-normalized caveat");
});

it("accepts a schema-valid result bound to JavaScript Evidence", async () => {
  const root = await createTestTempDirectory("rea-js-service-valid-");
  const output = join(root, "out");
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      const returned = result(output);
      await materializeResult(returned);
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, output);
  if (!response.ok) throw new Error("expected valid deobfuscation Evidence");
  if (response.value.subject === null)
    throw new Error("expected deobfuscation Evidence subject");
  expect(response.value.subject.format).toBe("javascript");
});

it.each([
  "invalid-result",
  "missing-subject",
  "subject-mismatch",
  "subject-format-mismatch",
  "proof-output-mismatch",
])("rejects %s returned across the provider boundary", async (mode) => {
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () =>
      ok({
        execution: createAnalysisExecution(
          mode === "invalid-result"
            ? {}
            : mode === "proof-output-mismatch"
              ? {
                  ...result(),
                  proof: {
                    ...result().proof,
                    output_sha256: "b".repeat(64),
                  },
                }
              : result(),
          provider,
          mode === "missing-subject"
            ? {}
            : {
                subject: {
                  path: mode === "subject-mismatch" ? "/wrong.js" : file.path,
                  sha256: file.sha256,
                  format:
                    mode === "subject-format-mismatch"
                      ? ("pe" as const)
                      : ("javascript" as const),
                },
              },
        ),
      }),
  });
  const response = await invokeService(service, "/tmp/out");
  if (response.ok) throw new Error("expected invalid provider output");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it.each([
  "source-copy",
  "output",
  "report",
  "manifest",
  "analysis-input",
] as const)("rejects a relative returned %s path", async (field) => {
  const returned = result();
  switch (field) {
    case "source-copy":
      returned.source.published_copy.path = "out/inputs/source.js";
      break;
    case "output":
      returned.output.path = "out/deobfuscated/source.js";
      break;
    case "report":
      returned.report.path = "out/reports/js-redox.json";
      break;
    case "manifest":
      returned.manifest.path = "out/manifest.json";
      break;
    case "analysis-input":
      returned.analysis_input.input_path = "out/deobfuscated";
      break;
  }
  const service = serviceForResult(returned);
  const response = await invokeService(service, "/tmp/out");
  if (response.ok) throw new Error("expected relative provider path rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("rejects an analysis handoff that does not name the transformed file directory", async () => {
  const returned = result();
  returned.analysis_input.input_path = "/tmp/out/inputs";
  const service = serviceForResult(returned);
  const response = await invokeService(service, "/tmp/out");
  if (response.ok) throw new Error("expected analysis handoff rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it.each(["path", "output_directory"])(
  "rejects relative %s before invoking the provider",
  async (field) => {
    let invoked = false;
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () => {
        invoked = true;
        return ok({ execution: createAnalysisExecution(result(), provider) });
      },
    });
    const response = await service.deobfuscate({
      path: file.path,
      output_directory: "/tmp/out",
      [field]: "relative.js",
    });
    expect(invoked).toBe(false);
    if (response.ok) throw new Error("expected invalid path");
    expect(response.error._tag).toBe("AnalysisInputError");
  },
);

it("returns a typed input error when the output parent is unavailable", async () => {
  const root = await createTestTempDirectory("rea-js-service-missing-parent-");
  let invoked = false;
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      invoked = true;
      return ok({ execution: createAnalysisExecution(result(), provider) });
    },
  });
  const response = await service.deobfuscate({
    path: file.path,
    output_directory: join(root, "missing", "out"),
  });
  expect(invoked).toBe(false);
  if (response.ok) throw new Error("expected invalid output parent");
  expect(response.error._tag).toBe("AnalysisInputError");
  expect(response.error).toMatchObject({
    issues: [expect.objectContaining({ path: ["output_directory"] })],
  });
});

it("rejects returned artifact paths that traverse an output-tree symlink", async () => {
  const root = await createTestTempDirectory("rea-js-service-returned-link-");
  const output = join(root, "out");
  const external = join(root, "external");
  await mkdir(external);
  const returned = result(output);
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async (request) => {
      await materializeResult(returned);
      await writeFile(join(external, "source.js"), "fixture");
      await symlink(external, join(request.output_directory, "escape"));
      returned.output.path = join(
        request.output_directory,
        "escape",
        "source.js",
      );
      returned.analysis_input.input_path = join(
        request.output_directory,
        "escape",
      );
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected symlink traversal rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("rejects provider results whose advertised artifacts do not exist", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-missing-artifact-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await mkdir(output, { recursive: true });
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected nonexistent artifact rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("rejects diagnostic artifact paths outside the selected output tree", async () => {
  const root = await createTestTempDirectory("rea-js-service-diagnostic-path-");
  const output = join(root, "out");
  const external = join(root, "external-version-stdout.txt");
  const returned = result(output);
  returned.diagnostics = diagnostics(output);
  returned.diagnostics.version.stdout.path = external;
  const service = serviceForResult(returned, true);
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected diagnostic path rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("derives shipped-artifact locations and drops untrusted provider raw results", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-provider-metadata-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const external = join(root, "untrusted.txt");
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      return ok({
        execution: createAnalysisExecution(returned, provider, {
          rawResult: { untrusted_path: external },
          locations: [{ kind: "artifact-path", path: external }],
          subject: {
            path: file.path,
            sha256: file.sha256,
            format: "javascript",
          },
        }),
      });
    },
  });
  const response = await invokeService(service, output);
  if (!response.ok) throw response.error;
  expect(response.value.raw_result).toBeNull();
  expect(response.value.locations).toEqual([
    { kind: "artifact-path", path: file.path },
    { kind: "artifact-path", path: returned.output.path },
    { kind: "artifact-path", path: returned.report.path },
  ]);
});

it.each([
  {
    name: "nonzero exit",
    mutate: (returned: JavaScriptDeobfuscationResult) => {
      if (returned.diagnostics === undefined)
        throw new Error("missing diagnostics");
      returned.diagnostics.execution.exit_code = 23;
    },
  },
  {
    name: "observed bytes below retained bytes",
    mutate: (returned: JavaScriptDeobfuscationResult) => {
      if (returned.diagnostics === undefined)
        throw new Error("missing diagnostics");
      returned.diagnostics.execution.stdout.observed_bytes =
        returned.diagnostics.execution.stdout.bytes - 1;
    },
  },
  {
    name: "untruncated missing bytes",
    mutate: (returned: JavaScriptDeobfuscationResult) => {
      if (returned.diagnostics === undefined)
        throw new Error("missing diagnostics");
      returned.diagnostics.execution.stdout.observed_bytes =
        returned.diagnostics.execution.stdout.bytes + 1;
    },
  },
])("rejects inconsistent normalized diagnostics: $name", async ({ mutate }) => {
  const root = await createTestTempDirectory("rea-js-service-bad-diagnostics-");
  const output = join(root, "out");
  const returned = result(output);
  returned.diagnostics = diagnostics(output);
  mutate(returned);
  const service = serviceForResult(returned, true);
  const response = await invokeService(service, output);
  if (response.ok)
    throw new Error("expected inconsistent diagnostics rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("observes cancellation after provider success before physical path verification", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-post-provider-abort-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const controller = new AbortController();
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      controller.abort("fixture cancellation");
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await service.deobfuscate(
    { path: file.path, output_directory: output },
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected cancellation");
  expect(response.error._tag).toBe("AnalysisCancelledError");
  expect(response.error.cause).toBe("fixture cancellation");
  expect(response.error.partialObservation).toEqual(
    expect.objectContaining({
      authority: "shipped-artifact",
      confidence: "derived",
    }),
  );
});

it("does not let post-publication cancellation hide invalid saved bytes", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-post-provider-invalid-abort-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const controller = new AbortController();
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      await writeFile(returned.output.path, "corrupted after publication");
      controller.abort("cancelled after corrupt publication");
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await service.deobfuscate(
    { path: file.path, output_directory: output },
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected physical verification failure");
  expect(response.error._tag).toBe("AnalysisOutputError");
  expect(response.error.partialObservation).toBeUndefined();
});

it("preserves the exact reason of a request cancelled before admission", async () => {
  const reason = Object.freeze({ kind: "fixture-cancellation", nonce: 17 });
  const controller = new AbortController();
  controller.abort(reason);
  let invoked = false;
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      invoked = true;
      throw new Error("provider must not run for pre-cancelled work");
    },
  });
  const response = await service.deobfuscate(
    { path: file.path, output_directory: "/tmp/out" },
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected cancellation");
  expect(response.error._tag).toBe("AnalysisCancelledError");
  expect(response.error.cause).toBe(reason);
  expect(invoked).toBe(false);
});

it("returns typed cancellation instead of throwing for work admitted after close", async () => {
  let invoked = false;
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      invoked = true;
      throw new Error("closed service must not invoke provider");
    },
  });
  await service.close();
  const response = await invokeService(service, "/tmp/out");
  if (response.ok) throw new Error("expected closed-service cancellation");
  expect(response.error._tag).toBe("AnalysisCancelledError");
  expect(invoked).toBe(false);
});

it("drains an admitted request through artifact verification before close completes", async () => {
  const root = await createTestTempDirectory("rea-js-service-close-race-");
  const output = join(root, "out");
  const returned = result(output);
  let releaseProvider!: () => void;
  const providerGate = new Promise<void>((resolve) => {
    releaseProvider = resolve;
  });
  let reportProviderStarted!: () => void;
  const providerStarted = new Promise<void>((resolve) => {
    reportProviderStarted = resolve;
  });
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      reportProviderStarted();
      await providerGate;
      await materializeResult(returned);
      return ok({ execution: validExecution(returned) });
    },
    close: async () => undefined,
  });

  const operation = invokeService(service, output);
  await providerStarted;
  let closeCompleted = false;
  const closing = service.close().then(() => {
    closeCompleted = true;
  });
  await Promise.resolve();
  expect(closeCompleted).toBe(false);

  releaseProvider();
  const response = await operation;
  if (!response.ok) throw response.error;
  await closing;
  expect(closeCompleted).toBe(true);
  expect(response.value.subject?.format).toBe("javascript");
});

it.each([
  [
    "published source",
    (returned: JavaScriptDeobfuscationResult) =>
      returned.source.published_copy.path,
  ],
  ["output", (returned: JavaScriptDeobfuscationResult) => returned.output.path],
  ["report", (returned: JavaScriptDeobfuscationResult) => returned.report.path],
  [
    "manifest",
    (returned: JavaScriptDeobfuscationResult) => returned.manifest.path,
  ],
])(
  "rejects %s bytes that disagree with provider metadata",
  async (_name, selectedPath) => {
    const root = await createTestTempDirectory("rea-js-service-byte-binding-");
    const output = join(root, "out");
    const returned = result(output);
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () => {
        await materializeResult(returned);
        await writeFile(selectedPath(returned), "tampered");
        return ok({ execution: validExecution(returned) });
      },
    });
    const response = await invokeService(service, output);
    if (response.ok) throw new Error("expected physical artifact mismatch");
    expect(response.error._tag).toBe("AnalysisOutputError");
  },
);

it("rejects an oversized published artifact using a service-owned role ceiling", async () => {
  const root = await createTestTempDirectory("rea-js-service-role-ceiling-");
  const output = join(root, "out");
  const returned = result(output);
  const oversized = Buffer.alloc(
    JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.manifestBytes + 1,
    0x61,
  );
  returned.manifest.bytes = oversized.length;
  returned.manifest.sha256 = createHash("sha256")
    .update(oversized)
    .digest("hex");
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      await writeFile(returned.manifest.path, oversized);
      return ok({ execution: validExecution(returned) });
    },
  });

  const response = await invokeService(service, output);
  if (response.ok)
    throw new Error("expected service artifact ceiling rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("rejects distinct artifact roles that alias the same verified file", async () => {
  const root = await createTestTempDirectory("rea-js-service-role-alias-");
  const output = join(root, "out");
  const returned = result(output);
  returned.report = { ...returned.output };
  returned.manifest = { ...returned.output };
  const service = serviceForResult(returned, true);
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected artifact-role alias rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("rejects distinct artifact role paths backed by the same hard-linked file", async () => {
  const root = await createTestTempDirectory("rea-js-service-role-hardlink-");
  const output = join(root, "out");
  const returned = result(output);
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      const reportPath = returned.report.path;
      await rm(reportPath);
      await link(returned.output.path, reportPath);
      returned.report = { ...returned.output, path: reportPath };
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected hard-linked role rejection");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("retains an earlier completed-read cleanup lease when a later artifact read fails", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-read-cleanup-then-failure-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const service = serviceForResult(returned, true);
  const originalClose = OwnedFileHandle.prototype.close;
  let denyOneClose = true;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      if (denyOneClose) {
        denyOneClose = false;
        await rm(returned.output.path);
        throw new Error("fixture earlier verification close denied");
      }
      return originalClose.call(this);
    });
  onTestFinished(async () => {
    close.mockRestore();
    await service.close();
  });

  const response = await invokeService(service, output);
  if (response.ok)
    throw new Error(
      "expected later artifact read failure with retained cleanup",
    );
  expect(response.error).toMatchObject({
    _tag: "AnalysisOutputError",
    cleanupIncomplete: true,
    cleanupOnly: false,
  });
  expect(response.error.cleanupResources.length).toBeGreaterThan(0);
  expect(response.error.partialObservation).toBeUndefined();

  close.mockRestore();
  await service.close();
  expect(response.error.cleanupIncomplete).toBe(false);
  expect(response.error.cleanupResources).toEqual([]);
});

it("retains verified Evidence when descriptor cleanup fails after a completed read", async () => {
  const root = await createTestTempDirectory("rea-js-service-read-cleanup-");
  const output = join(root, "out");
  const returned = result(output);
  const service = serviceForResult(returned, true);
  const originalClose = OwnedFileHandle.prototype.close;
  let denyOneClose = true;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(function (this: OwnedFileHandle) {
      if (denyOneClose) {
        denyOneClose = false;
        return Promise.reject(new Error("fixture verification close denied"));
      }
      return originalClose.call(this);
    });
  onTestFinished(async () => {
    close.mockRestore();
    await service.close();
  });

  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected verification cleanup failure");
  expect(response.error).toMatchObject({
    _tag: "AnalysisOutputError",
    cleanupIncomplete: true,
    cleanupOnly: true,
    partialObservation: {
      authority: "shipped-artifact",
      confidence: "derived",
    },
  });
  expect(response.error.cleanupResources.length).toBeGreaterThan(0);

  close.mockRestore();
  await service.close();
  expect(response.error.cleanupIncomplete).toBe(false);
  expect(response.error.cleanupResources).toEqual([]);
});

it("keeps late cancellation primary while verified descriptor cleanup remains live", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-cancelled-read-cleanup-",
  );
  const output = join(root, "out");
  const returned = result(output);
  const reason = Object.freeze({ kind: "late-cancel-with-cleanup", nonce: 91 });
  const controller = new AbortController();
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      controller.abort(reason);
      return ok({ execution: validExecution(returned) });
    },
  });
  const originalClose = OwnedFileHandle.prototype.close;
  let denyOneClose = true;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(function (this: OwnedFileHandle) {
      if (denyOneClose) {
        denyOneClose = false;
        return Promise.reject(
          new Error("fixture cancelled verification close denied"),
        );
      }
      return originalClose.call(this);
    });
  onTestFinished(async () => {
    close.mockRestore();
    await service.close();
  });

  const response = await service.deobfuscate(
    { path: file.path, output_directory: output },
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected cancellation with cleanup");
  expect(response.error).toMatchObject({
    _tag: "AnalysisCancelledError",
    cause: reason,
    cleanupIncomplete: true,
    partialObservation: {
      authority: "shipped-artifact",
      confidence: "derived",
    },
  });
  expect(response.error.cleanupResources.length).toBeGreaterThan(0);
  expect(response.error.secondaryFailures).toEqual([
    expect.objectContaining({
      _tag: "AnalysisOutputError",
      cleanupOnly: true,
      cleanupIncomplete: true,
    }),
  ]);
  expect(projectAnalysisError(response.error)).toMatchObject({
    code: "cleanup_incomplete",
    category: "cancelled",
    details: {
      cleanup: "incomplete",
      execution_failure: "cancelled",
      partial_observation: {
        authority: "shipped-artifact",
        confidence: "derived",
      },
    },
  });

  close.mockRestore();
  await service.close();
  expect(response.error.cleanupIncomplete).toBe(false);
  expect(response.error.cleanupResources).toEqual([]);
});

it("rejects diagnostic bytes that disagree with provider metadata", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-diagnostic-bytes-",
  );
  const output = join(root, "out");
  const returned = result(output);
  returned.diagnostics = diagnostics(output);
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      if (returned.diagnostics === undefined)
        throw new Error("missing diagnostics");
      await writeFile(returned.diagnostics.execution.stderr.path, "tampered");
      return ok({ execution: validExecution(returned) });
    },
  });
  const response = await invokeService(service, output);
  if (response.ok) throw new Error("expected diagnostic byte mismatch");
  expect(response.error._tag).toBe("AnalysisOutputError");
});

it("snapshots the provider subject exactly once before filesystem verification", async () => {
  const root = await createTestTempDirectory(
    "rea-js-service-subject-snapshot-",
  );
  const output = join(root, "out");
  const returned = result(output);
  let subjectReads = 0;
  const goodSubject = {
    path: file.path,
    sha256: file.sha256,
    format: "javascript" as const,
  };
  const badSubject = { ...goodSubject, sha256: "f".repeat(64) };
  const service = new JavaScriptDeobfuscationService({
    deobfuscate: async () => {
      await materializeResult(returned);
      const execution = createAnalysisExecution(returned, provider, {
        subject: goodSubject,
      });
      Object.defineProperty(execution, "subject", {
        configurable: true,
        enumerable: true,
        get: () => {
          subjectReads += 1;
          return subjectReads === 1 ? goodSubject : badSubject;
        },
      });
      return ok({ execution });
    },
  });
  const response = await invokeService(service, output);
  if (!response.ok) throw response.error;
  expect(subjectReads).toBe(1);
  expect(response.value.subject?.digest.sha256).toBe(file.sha256);
});
