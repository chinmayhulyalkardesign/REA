import { createHash } from "node:crypto";
import { join } from "node:path";
import { expect, it } from "vitest";

import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { OwnedCommandFailure } from "../../process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { executeJsRedox, type JsRedoxEngine } from "./JsRedoxExecution.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

it("preserves cleanup ownership on a failed version probe", async () => {
  const root = await createTestTempDirectory("rea-redox-version-owner-");
  const output = join(root, "output");
  const tree = await SafeOutputTree.create(output);
  const executable = Buffer.from("#!/bin/sh\nexit 0\n");
  const sourceBytes = Buffer.from("const value = 1;\n");
  const owner = {} as unknown as ProviderProcessSupervisor;
  const failure = new OwnedCommandFailure(
    "process",
    "version probe failed with incomplete cleanup",
    null,
    "fixture cleanup incomplete",
    undefined,
    ["fixture-version-worker"],
    owner,
  );
  const engine: JsRedoxEngine = {
    configuredCommand: "/fixture/js-redox",
    command: "/fixture/js-redox",
    sha256: sha256(executable),
    bytes: executable.length,
    executable,
    limiter: {
      configuredCommand: "/usr/bin/prlimit",
      command: "/usr/bin/prlimit",
      sha256: sha256(executable),
      bytes: executable.length,
      executable,
    },
  };

  try {
    await expect(
      executeJsRedox({
        request: {
          path: "/fixture/source.js",
          output_directory: output,
          max_iterations: 1,
        },
        engine,
        source: { bytes: sourceBytes, sha256: sha256(sourceBytes) },
        runtimePath: root,
        tree,
        run: async () => {
          throw failure;
        },
      }),
    ).rejects.toBe(failure);
  } finally {
    await tree.rollback();
  }
});
