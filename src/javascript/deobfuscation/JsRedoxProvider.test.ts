import {
  access,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";

const itLinuxX64 = it.skipIf(
  process.platform !== "linux" || process.arch !== "x64",
);

import {
  assertDeobfuscationCleanup,
  deobfuscationFixture,
} from "../../../tests/fixtures/javascript-deobfuscation/provider.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { JS_REDOX_LIMITS } from "./JsRedoxRelease.js";
import { javascriptDeobfuscationResultSchema } from "../../domain/javascript/javascriptDeobfuscation.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";

const deferred = <T>() => {
  let resolve: (value: T) => void = () => {};
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
};

type DeobfuscationFixture = Awaited<ReturnType<typeof deobfuscationFixture>>;

const deobfuscationRequest = (
  fixture: DeobfuscationFixture,
  outputDirectory = fixture.output,
  maxIterations = 16,
) => ({
  path: fixture.path,
  output_directory: outputDirectory,
  max_iterations: maxIterations,
});

const runFixture = (fixture: Parameters<typeof deobfuscationRequest>[0]) =>
  fixture.service.deobfuscate(deobfuscationRequest(fixture));

const fixtureFor = async (...args: Parameters<typeof deobfuscationFixture>) => {
  const fixture = await deobfuscationFixture(...args);
  onTestFinished(async () => fixture.provider.close?.());
  return fixture;
};

const expectRolledBack = async (
  fixture: DeobfuscationFixture,
): Promise<void> => {
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await assertDeobfuscationCleanup(fixture.launches);
};

itLinuxX64(
  "settles a queued cancellation without waiting for the active predecessor",
  async () => {
    const firstLaunchStarted = deferred<void>();
    const releaseFirstLaunch = deferred<void>();
    let blockFirstLaunch = true;
    const fixture = await fixtureFor(
      "normal",
      'const table = ["hello", "world"];\nconsole.log(table[0] + " " + table[1]);\n',
      {},
      "selected.js",
      {
        beforeLaunch: async () => {
          if (!blockFirstLaunch) return;
          blockFirstLaunch = false;
          firstLaunchStarted.resolve();
          await releaseFirstLaunch.promise;
        },
      },
    );

    const first = fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    await firstLaunchStarted.promise;

    const reason = Object.freeze({ kind: "queued-cancel", nonce: 41 });
    const controller = new AbortController();
    const second = fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, `${fixture.output}-second`, 16),
      { signal: controller.signal },
    );
    controller.abort(reason);

    const cancelled = await second;
    if (cancelled.ok) throw new Error("expected queued cancellation");
    expect(cancelled.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(cancelled.error.cause).toBe(reason);
    expect(fixture.launches).toHaveLength(0);

    releaseFirstLaunch.resolve();
    const completed = await first;
    if (!completed.ok) throw completed.error;
    expect(fixture.launches).toHaveLength(2);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "settles cancellation while its serialized turn retries earlier cleanup",
  async () => {
    const retryStarted = deferred<void>();
    const releaseRetry = deferred<void>();
    const fixture = await deobfuscationFixture();
    const originalClose = OwnedFileHandle.prototype.close;
    let failedInitialClose = false;
    let blockedRetry = false;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        if (fixture.launches.length > 0 && !failedInitialClose) {
          failedInitialClose = true;
          throw new Error("fixture initial descriptor close denied");
        }
        if (failedInitialClose && !blockedRetry) {
          blockedRetry = true;
          retryStarted.resolve();
          await releaseRetry.promise;
        }
        return originalClose.call(this);
      });
    onTestFinished(async () => {
      close.mockRestore();
      releaseRetry.resolve();
      await fixture.provider.close?.();
    });

    const first = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    if (first.ok) throw new Error("expected retained cleanup failure");
    expect(first.error.cleanupIncomplete).toBe(true);
    const launchesBeforeRetry = fixture.launches.length;

    const reason = Object.freeze({ kind: "cleanup-wait-cancel", nonce: 57 });
    const controller = new AbortController();
    const second = fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output + "-second", 16),
      { signal: controller.signal },
    );
    await retryStarted.promise;
    const third = fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output + "-third", 16),
    );
    controller.abort(reason);

    const cancelled = await second;
    if (cancelled.ok) throw new Error("expected cleanup-wait cancellation");
    expect(cancelled.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(cancelled.error.cause).toBe(reason);
    expect(fixture.launches).toHaveLength(launchesBeforeRetry);
    await Promise.resolve();
    expect(fixture.launches).toHaveLength(launchesBeforeRetry);

    releaseRetry.resolve();
    const completed = await third;
    if (!completed.ok) throw completed.error;
    expect(fixture.launches).toHaveLength(launchesBeforeRetry + 2);
    expect(first.error.cleanupIncomplete).toBe(false);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "publishes source, proof report and safe rewritten JavaScript through the owned-process boundary",
  async () => {
    const fixture = await fixtureFor();
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
      max_iterations: 16,
    });
    if (!response.ok) throw response.error;
    if (response.value.subject === null)
      throw new Error("expected deobfuscation Evidence subject");
    const normalized = javascriptDeobfuscationResultSchema.parse(
      response.value.normalized_result,
    );
    expect(response.value).toMatchObject({
      operation: "deobfuscate_javascript_source",
      provider: { id: "js-redox", version: "0.1.1" },
      normalized_result: {
        status: "changed",
        runtime_execution: "not-performed",
        proof: {
          input_sha256: response.value.subject.digest.sha256,
          output_sha256: normalized.output.sha256,
        },
      },
    });
    await expect(
      readFile(`${fixture.output}/deobfuscated/source.js`, "utf8"),
    ).resolves.toContain('console.log("hello world")');
    await expect(
      access(`${fixture.output}/manifest.json`),
    ).resolves.toBeUndefined();
    const manifest = JSON.parse(
      await readFile(`${fixture.output}/manifest.json`, "utf8"),
    ) as { report: { path: string } };
    const report = JSON.parse(await readFile(manifest.report.path, "utf8"));
    expect(report).toMatchObject({
      schema: "js-safe-deobfuscate/v1",
      transforms: { static_array_lookup: 2, constant_fold: 1 },
      runtime_semantics_preserved_by_design: true,
    });
    expect(fixture.engineSnapshots).toHaveLength(2);
    expect(new Set(fixture.engineSnapshots.map(({ path }) => path)).size).toBe(
      2,
    );
    expect(fixture.engineSnapshots[0]?.path).not.toBe(fixture.command);
    expect(fixture.engineSnapshots[0]?.bytes.toString("utf8")).toBe(
      "#!/bin/sh\nexit 0\n",
    );
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64.each([
  "bad-digest",
  "bad-input-digest",
  "bad-analysis-digest",
  "bad-iterations",
  "bad-changed",
  "unsafe-static",
  "formatted",
  "unsafe-semantics",
])(
  "rejects a proof report with %s without retaining a publication",
  async (mode) => {
    const fixture = await fixtureFor(mode);
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected proof mismatch");
    expect(response.error._tag).toBe("AnalysisOutputError");
    await expectRolledBack(fixture);
  },
);

itLinuxX64.each([false, true])(
  "preserves configured engine symlinks and rejects retargeting=%s",
  async (retarget) => {
    const root = await createTestTempDirectory("rea-redox-selection-");
    const canonical = join(root, "engine");
    const replacement = join(root, "replacement");
    const selected = join(root, "current");
    await writeFile(canonical, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(replacement, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await symlink(canonical, selected);
    const fixture = await fixtureFor(
      retarget ? "engine-retarget" : "normal",
      undefined,
      {
        REA_JS_REDOX_COMMAND: selected,
        REA_DEOBFUSCATION_ENGINE_LINK: selected,
        REA_DEOBFUSCATION_ENGINE_REPLACEMENT: replacement,
      },
    );
    const response = await runFixture(fixture);
    if (retarget) {
      if (response.ok) throw new Error("expected engine selection mismatch");
      expect(response.error._tag).toBe("AnalysisOutputError");
      await expect(access(fixture.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } else {
      if (!response.ok) throw response.error;
      const result = javascriptDeobfuscationResultSchema.parse(
        response.value.normalized_result,
      );
      expect(
        JSON.parse(await readFile(result.manifest.path, "utf8")).engine,
      ).toMatchObject({ path: selected, resolved_path: canonical });
    }
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "publishes large diagnostics without expanding the inline result",
  async () => {
    const fixture = await fixtureFor("large-diagnostics");
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    expect(Buffer.byteLength(JSON.stringify(response.value))).toBeLessThan(
      20_000,
    );
    const result = javascriptDeobfuscationResultSchema.parse(
      response.value.normalized_result,
    );
    const manifest = JSON.parse(await readFile(result.manifest.path, "utf8"));
    expect(manifest.diagnostics.execution.stdout.bytes).toBe(6 * 1024 * 1024);
    expect(
      await readFile(manifest.diagnostics.execution.stdout.path, "utf8"),
    ).toBe("x".repeat(6 * 1024 * 1024));
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "retains verified Evidence while published-tree cleanup remains live",
  async () => {
    const fixture = await fixtureFor();
    const originalCommit = SafeOutputTree.prototype.commit;
    const rollback = vi.spyOn(SafeOutputTree.prototype, "rollback");
    vi.spyOn(SafeOutputTree.prototype, "commit").mockImplementationOnce(
      async function (this: SafeOutputTree) {
        await originalCommit.call(this);
        throw new Error("fixture directory-handle close failure");
      },
    );
    onTestFinished(() => {
      vi.restoreAllMocks();
    });
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected retained provider cleanup");
    expect(rollback).not.toHaveBeenCalled();
    expect(response.error).toMatchObject({
      _tag: "AnalysisOutputError",
      cleanupOnly: true,
      cleanupIncomplete: true,
      partialObservation: {
        authority: "shipped-artifact",
        confidence: "derived",
      },
    });
    expect(response.error.cleanupResources.length).toBeGreaterThan(0);
    expect(JSON.stringify(response.error.partialObservation)).not.toContain(
      "provider cleanup remains incomplete",
    );

    await fixture.service.close();
    expect(response.error.cleanupIncomplete).toBe(false);
    expect(response.error.cleanupResources).toEqual([]);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "snapshots the admitted resource limiter before launching it",
  async () => {
    const root = await createTestTempDirectory("rea-redox-limiter-");
    const limiter = join(root, "prlimit");
    await writeFile(limiter, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const fixture = await fixtureFor(
      "replace-limiter-before-launch",
      undefined,
      { REA_JAVASCRIPT_PRLIMIT_COMMAND: limiter },
    );
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    expect(await readFile(limiter, "utf8")).toBe("replacement executable");
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "creates its private runtime beneath the selected TMPDIR",
  async () => {
    const selectedTemp = await createTestTempDirectory(
      "rea-redox-selected-tmp-",
    );
    const fixture = await fixtureFor("normal", undefined, {
      TMPDIR: selectedTemp,
    });
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    expect(fixture.launches[0]?.cwd).toContain(selectedTemp);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "uses the canonical Linux default when TMPDIR is blank",
  async () => {
    const fixture = await fixtureFor("normal", undefined, {
      TMPDIR: "   ",
    });
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    const canonicalDefault = await realpath("/tmp");
    expect(fixture.launches[0]?.cwd).toMatch(
      new RegExp(
        `^${canonicalDefault.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}/rea-js-redox-`,
      ),
    );
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "preserves trailing whitespace in a nonempty TMPDIR path",
  async () => {
    const root = await createTestTempDirectory("rea-redox-selected-tmp-space-");
    const selectedTemp = join(root, "runtime-parent ");
    await mkdir(selectedTemp);
    const fixture = await fixtureFor("normal", undefined, {
      TMPDIR: selectedTemp,
    });
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    const canonicalParent = await realpath(selectedTemp);
    expect(fixture.launches[0]?.cwd).toMatch(
      new RegExp(
        `^${canonicalParent.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}/rea-js-redox-`,
      ),
    );
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "canonicalizes symlink-dotdot TMPDIR before owning a private runtime",
  async () => {
    const root = await createTestTempDirectory(
      "rea-redox-selected-tmp-dotdot-",
    );
    const canonicalParent = join(root, "canonical");
    const child = join(canonicalParent, "child");
    const alias = join(root, "alias");
    await mkdir(child, { recursive: true });
    await symlink(child, alias);
    const fixture = await fixtureFor("normal", undefined, {
      TMPDIR: `${alias}/..`,
    });
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    expect(fixture.launches[0]?.cwd).toMatch(
      new RegExp(
        `^${canonicalParent.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}/rea-js-redox-`,
      ),
    );
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "classifies an unusable selected TMPDIR as capability unavailable",
  async () => {
    const root = await createTestTempDirectory("rea-redox-missing-tmp-");
    const fixture = await fixtureFor("normal", undefined, {
      TMPDIR: join(root, "missing"),
    });
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected TMPDIR capability failure");
    expect(response.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    if (!(response.error instanceof AnalysisCapabilityUnavailableError))
      throw new Error("expected capability-unavailable error");
    expect(response.error.userMessage).toContain("Set TMPDIR");
    expect(fixture.launches).toHaveLength(0);
  },
);

itLinuxX64(
  "classifies the proof report byte ceiling as a capacity constraint",
  async () => {
    const fixture = await fixtureFor("report-overflow");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected report capacity failure");
    expect(response.error).toBeInstanceOf(AnalysisResourceConstraintError);
    if (!(response.error instanceof AnalysisResourceConstraintError))
      throw new Error("expected capacity constraint");
    expect(response.error.reportedLimits).toMatchObject({
      report_bytes_ceiling: JS_REDOX_LIMITS.reportBytes,
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "preserves the exact caller reason when cancelling an active owned command",
  async () => {
    const controller = new AbortController();
    const reason = Object.freeze({ kind: "active-command-cancel", nonce: 72 });
    const fixture = await fixtureFor(
      "slow-both",
      undefined,
      {},
      "selected.js",
      {
        afterLaunch: (phase) => {
          if (phase === "version") controller.abort(reason);
        },
      },
    );

    const response = await fixture.service.deobfuscate(
      deobfuscationRequest(fixture),
      { signal: controller.signal },
    );
    if (response.ok) throw new Error("expected active-command cancellation");
    expect(response.error._tag).toBe("AnalysisCancelledError");
    expect(response.error.cause).toBe(reason);
    await expectRolledBack(fixture);
  },
);

itLinuxX64("preserves cancellation during publication I/O", async () => {
  const fixture = await fixtureFor();
  const controller = new AbortController();
  const reason = Object.freeze({ kind: "publication-cancel", nonce: 73 });
  const originalWrite = SafeOutputTree.prototype.write;
  vi.spyOn(SafeOutputTree.prototype, "write").mockImplementationOnce(
    async function (this: SafeOutputTree, ...args) {
      controller.abort(reason);
      return originalWrite.apply(this, args);
    },
  );
  onTestFinished(() => {
    vi.restoreAllMocks();
  });
  const response = await fixture.service.deobfuscate(
    deobfuscationRequest(fixture),
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected cancellation");
  expect(response.error._tag).toBe("AnalysisCancelledError");
  expect(response.error.cause).toBe(reason);
  await expectRolledBack(fixture);
});

itLinuxX64(
  "shares one wall deadline across the version and transformation launches",
  async () => {
    const fixture = await fixtureFor("slow-both");
    const limits = JS_REDOX_LIMITS as { timeoutMs: number };
    const originalTimeout = limits.timeoutMs;
    limits.timeoutMs = 1_000;
    onTestFinished(() => {
      limits.timeoutMs = originalTimeout;
    });
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected shared deadline timeout");
    expect(response.error._tag).toBe("AnalysisTimeoutError");
    expect(fixture.launches.length).toBeGreaterThanOrEqual(1);
    expect(fixture.launches.length).toBeLessThanOrEqual(2);
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "charges limiter binding against the shared wall deadline",
  async () => {
    const fixture = await fixtureFor();
    const limits = JS_REDOX_LIMITS as { timeoutMs: number };
    const originalTimeout = limits.timeoutMs;
    limits.timeoutMs = 1;
    onTestFinished(() => {
      limits.timeoutMs = originalTimeout;
    });
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected setup-charged deadline timeout");
    expect(response.error._tag).toBe("AnalysisTimeoutError");
    expect(fixture.launches).toHaveLength(0);
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "rejects transformed JavaScript that is not valid UTF-8",
  async () => {
    const fixture = await fixtureFor("invalid-output-utf8");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected malformed output rejection");
    expect(response.error._tag).toBe("AnalysisOutputError");
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "rejects a relative resource-limiter override before launch",
  async () => {
    const fixture = await fixtureFor("normal", undefined, {
      REA_JAVASCRIPT_PRLIMIT_COMMAND: "prlimit",
    });
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected relative limiter rejection");
    expect(response.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(fixture.launches).toHaveLength(0);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

itLinuxX64(
  "observes cancellation immediately before output publication",
  async () => {
    const fixture = await fixtureFor();
    const controller = new AbortController();
    const reason = Object.freeze({ kind: "precommit-cancel", nonce: 74 });
    const originalClose = PrivateRuntimeRoot.prototype.close;
    vi.spyOn(PrivateRuntimeRoot.prototype, "close").mockImplementationOnce(
      async function (this: PrivateRuntimeRoot) {
        await originalClose.call(this);
        controller.abort(reason);
      },
    );
    onTestFinished(() => {
      vi.restoreAllMocks();
    });
    const response = await fixture.service.deobfuscate(
      deobfuscationRequest(fixture),
      { signal: controller.signal },
    );
    if (response.ok) throw new Error("expected pre-commit cancellation");
    expect(response.error._tag).toBe("AnalysisCancelledError");
    expect(response.error.cause).toBe(reason);
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "clears a returned cleanup warning when its retained artifact handle later closes",
  async () => {
    const fixture = await deobfuscationFixture();
    let denyClose = true;
    const originalClose = OwnedFileHandle.prototype.close;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(function (this: OwnedFileHandle) {
        if (denyClose) {
          denyClose = false;
          return Promise.reject(new Error("fixture descriptor close denied"));
        }
        return originalClose.call(this);
      });
    onTestFinished(async () => {
      close.mockRestore();
      await fixture.provider.close?.();
    });

    const first = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    if (first.ok) throw new Error("expected retained artifact cleanup failure");
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources.length).toBeGreaterThan(0);

    close.mockRestore();
    await fixture.provider.close?.();
    expect(first.error.cleanupIncomplete).toBe(false);
    expect(first.error.cleanupResources).toEqual([]);
  },
);

itLinuxX64(
  "keeps a mixed cleanup error live until every retained owner closes",
  async () => {
    const fixture = await deobfuscationFixture();
    let denyArtifactClose = true;
    const originalClose = OwnedFileHandle.prototype.close;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(function (this: OwnedFileHandle) {
        if (denyArtifactClose && fixture.launches.length > 0) {
          denyArtifactClose = false;
          return Promise.reject(new Error("fixture descriptor close denied"));
        }
        return originalClose.call(this);
      });
    const originalRollback = SafeOutputTree.prototype.rollback;
    let deniedRollbacks = 2;
    const rollback = vi
      .spyOn(SafeOutputTree.prototype, "rollback")
      .mockImplementation(async function (this: SafeOutputTree) {
        if (deniedRollbacks > 0) {
          deniedRollbacks -= 1;
          throw new Error("fixture output-tree rollback denied");
        }
        return originalRollback.call(this);
      });
    onTestFinished(async () => {
      close.mockRestore();
      rollback.mockRestore();
      await fixture.provider.close?.();
    });

    const first = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    if (first.ok) throw new Error("expected mixed cleanup failure");
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources).toContain(fixture.output);
    expect(first.error.cleanupResources.length).toBeGreaterThan(1);

    close.mockRestore();
    await expect(fixture.provider.close?.()).rejects.toMatchObject({
      cleanupIncomplete: true,
    });
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources).toEqual([fixture.output]);

    rollback.mockRestore();
    await fixture.provider.close?.();
    expect(first.error.cleanupIncomplete).toBe(false);
    expect(first.error.cleanupResources).toEqual([]);
  },
);

itLinuxX64(
  "retries an output tree even while artifact cleanup remains persistently blocked",
  async () => {
    const fixture = await deobfuscationFixture();
    let allowArtifactClose = false;
    const originalClose = OwnedFileHandle.prototype.close;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(function (this: OwnedFileHandle) {
        if (!allowArtifactClose && fixture.launches.length > 0)
          return Promise.reject(
            new Error("fixture persistent descriptor close denied"),
          );
        return originalClose.call(this);
      });
    const originalRollback = SafeOutputTree.prototype.rollback;
    let rollbackAttempts = 0;
    const rollback = vi
      .spyOn(SafeOutputTree.prototype, "rollback")
      .mockImplementation(async function (this: SafeOutputTree) {
        rollbackAttempts += 1;
        if (rollbackAttempts === 1)
          throw new Error("fixture transient output-tree rollback denied");
        return originalRollback.call(this);
      });
    onTestFinished(async () => {
      allowArtifactClose = true;
      close.mockRestore();
      rollback.mockRestore();
      await fixture.provider.close?.();
    });

    const first = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    if (first.ok) throw new Error("expected mixed cleanup failure");
    expect(first.error.cleanupResources).toContain(fixture.output);
    expect(rollbackAttempts).toBe(1);

    const launchesBeforeRetry = fixture.launches.length;
    const second = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, `${fixture.output}-second`, 16),
    );
    if (second.ok)
      throw new Error("expected retained admission cleanup failure");
    expect(second.error.cleanupIncomplete).toBe(true);
    expect(fixture.launches).toHaveLength(launchesBeforeRetry);
    expect(rollbackAttempts).toBe(2);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources).not.toContain(fixture.output);

    allowArtifactClose = true;
    close.mockRestore();
    await fixture.provider.close?.();
    expect(first.error.cleanupIncomplete).toBe(false);
    expect(first.error.cleanupResources).toEqual([]);
  },
);

itLinuxX64(
  "retries a private runtime even while output-tree cleanup remains blocked",
  async () => {
    const fixture = await deobfuscationFixture("bad-digest");
    const originalRollback = SafeOutputTree.prototype.rollback;
    let allowTreeRollback = false;
    const rollback = vi
      .spyOn(SafeOutputTree.prototype, "rollback")
      .mockImplementation(function (this: SafeOutputTree) {
        if (!allowTreeRollback)
          return Promise.reject(
            new Error("fixture persistent tree rollback denied"),
          );
        return originalRollback.call(this);
      });
    const originalRuntimeClose = PrivateRuntimeRoot.prototype.close;
    let denyInitialRuntimeClose = true;
    const runtimeClose = vi
      .spyOn(PrivateRuntimeRoot.prototype, "close")
      .mockImplementation(function (this: PrivateRuntimeRoot) {
        if (denyInitialRuntimeClose) {
          denyInitialRuntimeClose = false;
          return Promise.reject(
            new Error("fixture initial runtime close denied"),
          );
        }
        return originalRuntimeClose.call(this);
      });
    onTestFinished(async () => {
      allowTreeRollback = true;
      rollback.mockRestore();
      runtimeClose.mockRestore();
      await fixture.provider.close?.();
    });

    const first = await fixture.provider.deobfuscate(
      deobfuscationRequest(fixture, fixture.output, 16),
    );
    if (first.ok)
      throw new Error("expected retained tree/runtime cleanup failure");
    const retainedRuntime = fixture.launches[0]?.cwd;
    if (retainedRuntime === undefined)
      throw new Error("expected retained runtime");
    expect(first.error.cleanupResources).toContain(fixture.output);
    expect(first.error.cleanupResources).toContain(retainedRuntime);
    await expect(access(retainedRuntime)).resolves.toBeUndefined();

    await expect(fixture.provider.close?.()).rejects.toMatchObject({
      cleanupIncomplete: true,
    });
    await expect(access(retainedRuntime)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(access(fixture.output)).resolves.toBeUndefined();
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources).toContain(fixture.output);
    expect(first.error.cleanupResources).not.toContain(retainedRuntime);

    allowTreeRollback = true;
    rollback.mockRestore();
    await fixture.provider.close?.();
    expect(first.error.cleanupIncomplete).toBe(false);
    expect(first.error.cleanupResources).toEqual([]);
  },
);

itLinuxX64(
  "retries the independent output tree while a retained process blocks only its runtime",
  async () => {
    const fixture = await fixtureFor();
    const stop = vi
      .spyOn(ProviderProcessSupervisor.prototype, "stop")
      .mockResolvedValueOnce({
        status: "incomplete",
        reason: "fixture retained version owner",
      })
      .mockResolvedValueOnce({
        status: "incomplete",
        reason: "fixture retained version owner on retry",
      });
    const originalRollback = SafeOutputTree.prototype.rollback;
    let rollbackAttempts = 0;
    const rollback = vi
      .spyOn(SafeOutputTree.prototype, "rollback")
      .mockImplementation(async function (this: SafeOutputTree) {
        rollbackAttempts += 1;
        if (rollbackAttempts === 1)
          throw new Error("fixture initial output-tree rollback denied");
        return originalRollback.call(this);
      });
    onTestFinished(() => {
      stop.mockRestore();
      rollback.mockRestore();
    });

    const first = await runFixture(fixture);
    if (first.ok) throw new Error("expected retained cleanup failure");
    expect(first.error).toMatchObject({
      _tag: "ProviderAdapterError",
      cleanupIncomplete: true,
      diagnostics: {
        cleanup_failures: expect.arrayContaining([
          expect.stringContaining(
            "fixture initial output-tree rollback denied",
          ),
        ]),
      },
    });
    expect(fixture.launches).toHaveLength(1);
    expect(rollbackAttempts).toBe(1);
    const retainedRuntime = fixture.launches[0]?.cwd;
    if (retainedRuntime === undefined)
      throw new Error("expected retained private runtime");
    await expect(access(retainedRuntime)).resolves.toBeUndefined();
    await expect(access(fixture.output)).resolves.toBeUndefined();

    const second = await runFixture(fixture);
    if (second.ok) throw new Error("expected retained process cleanup failure");
    expect(rollbackAttempts).toBe(2);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(access(retainedRuntime)).resolves.toBeUndefined();
    expect(first.error.cleanupIncomplete).toBe(true);
    expect(first.error.cleanupResources).not.toContain(fixture.output);
    expect(first.error.cleanupResources).toContain(retainedRuntime);
    expect(fixture.launches).toHaveLength(1);

    const third = await runFixture(fixture);
    if (!third.ok) throw third.error;
    expect(fixture.launches).toHaveLength(3);
    await expect(access(retainedRuntime)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(first.error.cleanupIncomplete).toBe(false);
    expect(first.error.cleanupResources).toEqual([]);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "retains bounded process diagnostics for a nonzero engine exit",
  async () => {
    const fixture = await fixtureFor("nonzero");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected engine failure");
    expect(response.error).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      diagnostics: {
        configured_executable: fixture.command,
        exit_code: 23,
        signal: null,
      },
      capturedOutput: {
        stdout: "fixture stdout diagnostic\n",
        stderr: "fixture stderr diagnostic\n",
        exit_code: 23,
        signal: null,
        truncated: false,
      },
    });
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "bounds failed transform diagnostics before error projection",
  async () => {
    const fixture = await fixtureFor("nonzero-large-diagnostics");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected noisy transform failure");
    expect(response.error._tag).toBe("ProviderAdapterError");
    const stdout = response.error.diagnostics?.stdout;
    const stderr = response.error.diagnostics?.stderr;
    expect(stdout).toMatchObject({
      text_truncated: true,
      bytes: 256 * 1024,
      retained_bytes: 256 * 1024,
    });
    expect(stderr).toMatchObject({
      text_truncated: true,
      bytes: 256 * 1024,
      retained_bytes: 256 * 1024,
    });
    if (typeof stdout !== "object" || stdout === null || Array.isArray(stdout))
      throw new Error("expected structured stdout diagnostics");
    if (typeof stderr !== "object" || stderr === null || Array.isArray(stderr))
      throw new Error("expected structured stderr diagnostics");
    expect(String(stdout.text).length).toBeLessThanOrEqual(4_096);
    expect(String(stderr.text).length).toBeLessThanOrEqual(4_096);
    expect(
      JSON.stringify(projectAnalysisError(response.error)).length,
    ).toBeLessThan(20_000);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64(
  "executes a harmless fingerprinted engine snapshot through the real util-linux limiter",
  async (context) => {
    try {
      await access("/usr/bin/prlimit");
    } catch {
      context.skip();
      return;
    }
    const root = await createTestTempDirectory("rea-redox-real-limiter-");
    const command = join(root, "harmless-engine");
    const source = join(root, "selected.js");
    await writeFile(source, "const value = 1;\n");
    await writeFile(
      command,
      [
        "#!/bin/sh",
        'if [ "$1" = "--version" ]; then echo "jsvm-lift 0.1.1"; exit 0; fi',
        'cp -- "$1" "$2"',
        'digest=$(sha256sum "$1" | cut -d " " -f1)',
        'printf \'{"schema":"js-safe-deobfuscate/v1","source_mode":"auto","input":"%s","input_sha256":"%s","output_sha256":"%s","analysis_source_sha256":"%s","changed":false,"iterations":0,"transforms":{},"arithmetic_state_proofs":[],"static_alias_installer_calls":[],"safe_static_only":true,"presentation_formatted":false,"runtime_semantics_preserved_by_design":true}\\n\' "$1" "$digest" "$digest" "$digest" > "$4"',
      ].join("\n") + "\n",
      { mode: 0o700 },
    );
    const { JsRedoxProvider } = await import("./JsRedoxProvider.js");
    const provider = new JsRedoxProvider({
      ...process.env,
      REA_JS_REDOX_COMMAND: command,
    });
    onTestFinished(() => provider.close());
    const response = await provider.deobfuscate({
      path: source,
      output_directory: join(root, "output"),
      max_iterations: 1,
    });
    if (!response.ok) throw response.error;
    const result = javascriptDeobfuscationResultSchema.parse(
      response.value.execution.result,
    );
    expect(result).toMatchObject({
      status: "unchanged",
      proof: {
        input_sha256: result.source.sha256,
        output_sha256: result.output.sha256,
      },
    });
  },
);

itLinuxX64(
  "rebuilds the transform executable from retained bytes after a mutating version probe",
  async () => {
    const fixture = await fixtureFor("replace-version-snapshot");
    const response = await runFixture(fixture);
    if (!response.ok) throw response.error;
    expect(new Set(fixture.engineSnapshots.map(({ path }) => path)).size).toBe(
      2,
    );
    expect(
      fixture.engineSnapshots.map(({ bytes }) => bytes.toString("utf8")),
    ).toEqual(["#!/bin/sh\nexit 0\n", "#!/bin/sh\nexit 0\n"]);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

itLinuxX64("cancels at commit entry without publishing output", async () => {
  const fixture = await fixtureFor();
  const controller = new AbortController();
  const originalCommit = SafeOutputTree.prototype.commit;
  vi.spyOn(SafeOutputTree.prototype, "commit").mockImplementationOnce(
    async function (this: SafeOutputTree, signal?: AbortSignal) {
      controller.abort();
      await originalCommit.call(this, signal);
    },
  );
  onTestFinished(() => {
    vi.restoreAllMocks();
  });
  const response = await fixture.service.deobfuscate(
    { path: fixture.path, output_directory: fixture.output },
    { signal: controller.signal },
  );
  if (response.ok) throw new Error("expected commit cancellation");
  expect(response.error._tag).toBe("AnalysisCancelledError");
  await expectRolledBack(fixture);
});

itLinuxX64(
  "bounds failed version-probe diagnostics by UTF-8 bytes",
  async () => {
    const fixture = await fixtureFor("version-nonzero-multibyte");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected failed version probe");
    expect(response.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(response.error.capturedOutput).toMatchObject({
      exit_code: 23,
      truncated: true,
    });
    const stderr = response.error.capturedOutput?.stderr;
    if (typeof stderr !== "string")
      throw new Error("expected bounded version-probe stderr");
    expect(Buffer.byteLength(stderr, "utf8")).toBeLessThanOrEqual(4_096);
    expect(Buffer.byteLength(stderr, "utf8")).toBe(4_095);
    await expectRolledBack(fixture);
  },
);

itLinuxX64(
  "retains observed version and stderr when a successful probe reports an unsupported version",
  async () => {
    const fixture = await fixtureFor("wrong-version");
    const response = await runFixture(fixture);
    if (response.ok) throw new Error("expected unsupported version");
    expect(response.error).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      diagnostics: {
        observed_version: "9.9.9",
        configured_executable: fixture.command,
      },
      capturedOutput: {
        stdout: "jsvm-lift 9.9.9\n",
        stderr: "unsupported engine diagnostic\n",
        truncated: false,
      },
    });
    await expectRolledBack(fixture);
  },
);

itLinuxX64.each([
  ["diagnostic-overflow", "capacity"],
  ["cpu-signal", "cpu"],
  ["file-signal", "file-size"],
])("classifies %s as a %s resource observation", async (mode, resource) => {
  const fixture = await fixtureFor(mode);
  const response = await fixture.service.deobfuscate({
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (response.ok) throw new Error("expected resource refusal");
  expect(response.error).toMatchObject({
    _tag: "AnalysisResourceConstraintError",
    resource,
  });
  expect(response.error.diagnostics).toHaveProperty("exit_signal");
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await assertDeobfuscationCleanup(fixture.launches);
});

itLinuxX64.each([
  ["entry.mjs", "module", "source.mjs"],
  ["entry.cjs", "commonjs", "source.cjs"],
  [".mjs", "module", "source.mjs"],
  [".cjs", "commonjs", "source.cjs"],
] as const)(
  "preserves explicit %s source mode through producer proof and analysis handoff",
  async (sourceFileName, sourceMode, publishedFileName) => {
    const fixture = await deobfuscationFixture(
      "normal",
      "const marker = 1;\n",
      {},
      sourceFileName,
    );
    onTestFinished(async () => fixture.service.close());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
      max_iterations: 1,
    });
    if (!response.ok) throw response.error;
    const normalized = javascriptDeobfuscationResultSchema.parse(
      response.value.normalized_result,
    );
    expect(normalized.output.path).toBe(
      join(fixture.output, "deobfuscated", publishedFileName),
    );
    const report = JSON.parse(await readFile(normalized.report.path, "utf8"));
    expect(report.source_mode).toBe(sourceMode);
  },
);
