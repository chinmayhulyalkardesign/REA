import { Cli } from "incur";
import { expect, it, onTestFinished, vi } from "vitest";

import { registerJavaScriptDeobfuscationCommands } from "../../../src/cli/javascriptDeobfuscationCommands.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { AnalysisOutputError } from "../../../src/domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { ok } from "../../../src/domain/result.js";
import { silentLogger } from "../../../src/logger.js";
import { SafeOutputTree } from "../../../src/artifacts/SafeOutputTree.js";
import {
  assertDeobfuscationCleanup,
  deobfuscationFixture,
} from "../../fixtures/javascript-deobfuscation/provider.js";

const serveJson = async (
  name: string,
  service: Parameters<typeof registerJavaScriptDeobfuscationCommands>[3],
  path = "/tmp/input.js",
  outputDirectory = "/tmp/output",
): Promise<unknown> => {
  const cli = Cli.create(name, { sync: false });
  registerJavaScriptDeobfuscationCommands(cli, silentLogger, {}, service);
  let stdout = "";
  await cli.serve(
    [
      "deobfuscate-javascript-source",
      path,
      outputDirectory,
      "--format",
      "json",
    ],
    {
      stdout: (text) => {
        stdout += text;
      },
      exit: () => {},
    },
  );
  return JSON.parse(stdout);
};

it("retains completed deobfuscation Evidence when final close fails", async () => {
  const evidence = createEvidence(
    { path: "/tmp/input.js", sha256: "a".repeat(64), format: "javascript" },
    { id: "js-redox", name: "Fixture js-redox", version: "0.1.1" },
    {
      operation: "deobfuscate_javascript_source",
      parameters: {},
      result: { status: "unchanged" },
      confidence: "derived",
    },
  );
  const response = await serveJson("javascript-deobfuscation-cleanup-test", {
    deobfuscate: async () => ok(evidence),
    close: async () => {
      throw new ProviderCleanupError(
        "js-redox",
        ["js-redox artifact handles"],
        { reason: "cleanup retry failed" },
        { operation: "deobfuscate_javascript_source" },
      );
    },
  });

  expect(response).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: ["js-redox artifact handles"],
      partial_observation: { evidence_id: evidence.evidence_id },
    },
  });
});

it("returns completed deobfuscation Evidence when final close resolves cleanup-only failure", async () => {
  const evidence = createEvidence(
    { path: "/tmp/input.js", sha256: "b".repeat(64), format: "javascript" },
    { id: "js-redox", name: "Fixture js-redox", version: "0.1.1" },
    {
      operation: "deobfuscate_javascript_source",
      parameters: {},
      result: { status: "unchanged" },
      confidence: "derived",
    },
  );
  const failure = new AnalysisOutputError(
    "deobfuscate_javascript_source",
    "verified artifact descriptor cleanup remains incomplete",
    {
      cleanup: {
        reason: "fixture retained verification descriptor",
        resources: ["fixture-verification-descriptor"],
      },
      partialObservation: evidence,
      cleanupOnly: true,
    },
  );
  const response = await serveJson(
    "javascript-deobfuscation-cleanup-resolved-test",
    {
      deobfuscate: async () => ({ ok: false as const, error: failure }),
      close: async () => {
        failure.resolveCleanup();
      },
    },
  );

  expect(response).toMatchObject({
    evidence_id: evidence.evidence_id,
    operation: "deobfuscate_javascript_source",
    authority: "shipped-artifact",
    confidence: "derived",
  });
  expect(failure.cleanupIncomplete).toBe(false);
});

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "emits clean Evidence after final close resolves published-tree cleanup",
  async () => {
    const fixture = await deobfuscationFixture();
    onTestFinished(async () => {
      vi.restoreAllMocks();
      await fixture.service.close();
    });
    const originalCommit = SafeOutputTree.prototype.commit;
    vi.spyOn(SafeOutputTree.prototype, "commit").mockImplementationOnce(
      async function (this: SafeOutputTree) {
        await originalCommit.call(this);
        throw new Error("fixture transient published-tree close failure");
      },
    );
    const response = await serveJson(
      "javascript-deobfuscation-cleanup-real-test",
      fixture.service,
      fixture.path,
      fixture.output,
    );
    expect(response).toMatchObject({
      operation: "deobfuscate_javascript_source",
      authority: "shipped-artifact",
      confidence: "derived",
    });
    expect(JSON.stringify(response)).not.toContain(
      "provider cleanup remains incomplete",
    );
    expect(JSON.stringify(response)).not.toContain("cleanup_incomplete");
    await assertDeobfuscationCleanup(fixture.launches);
  },
);
