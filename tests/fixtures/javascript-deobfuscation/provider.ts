import { access, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";

import { JavaScriptDeobfuscationService } from "../../../src/application/javascript/JavaScriptDeobfuscationService.js";
import { createJavaScriptDeobfuscationProvider } from "../../../src/composition/javascriptDeobfuscation.js";
import {
  prlimitArgumentVector,
  readLinuxResourceLimits,
} from "../../../src/process/LinuxResourceLimits.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { JS_REDOX_LIMITS } from "../../../src/javascript/deobfuscation/JsRedoxRelease.js";
import { createTestTempDirectory } from "../temporaryDirectory.js";

/** Exercise the production provider boundary while replacing only the external producer bytes. */
export const deobfuscationFixture = async (
  mode = "normal",
  source = 'const table = ["hello", "world"];\nconsole.log(table[0] + " " + table[1]);\n',
  environment: Readonly<NodeJS.ProcessEnv> = {},
  sourceFileName = "selected.js",
  hooks: {
    readonly beforeLaunch?: (
      phase: "version" | "transform",
    ) => Promise<void> | void;
    readonly afterLaunch?: (
      phase: "version" | "transform",
      pid: number | undefined,
    ) => Promise<void> | void;
  } = {},
) => {
  const root = await createTestTempDirectory("rea-js-redox-fixture-");
  const path = join(root, sourceFileName);
  await writeFile(path, source);
  const command = join(root, "fixture-js-redox");
  await writeFile(command, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const configuredLimiter =
    environment.REA_JAVASCRIPT_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
  const limiterBytes = isAbsolute(configuredLimiter)
    ? await readFile(configuredLimiter)
    : undefined;
  const launches: { cwd: string | undefined; pid: number | undefined }[] = [];
  const engineSnapshots: { path: string; bytes: Buffer }[] = [];
  const provider = createJavaScriptDeobfuscationProvider(
    { ...process.env, REA_JS_REDOX_COMMAND: command, ...environment },
    async (options) => {
      const separator = options.arguments.indexOf("--");
      const enginePath = options.arguments[separator + 1];
      if (enginePath === undefined)
        throw new Error("js-redox fixture launch omitted engine path");
      if (mode === "replace-limiter-before-launch")
        await writeFile(configuredLimiter, "replacement executable");
      if (limiterBytes === undefined)
        throw new Error("fixture launched with an invalid limiter selection");
      expect(dirname(options.command)).toBe(options.cwd);
      expect(basename(options.command)).toMatch(/^prlimit-/u);
      expect(await readFile(options.command)).toEqual(limiterBytes);
      const limits = await readLinuxResourceLimits({
        address_space_bytes: JS_REDOX_LIMITS.addressSpaceBytes,
        file_bytes: JS_REDOX_LIMITS.outputBytes,
        cpu_seconds: JS_REDOX_LIMITS.cpuSeconds,
      });
      expect(options.arguments.slice(0, separator + 2)).toEqual(
        prlimitArgumentVector(limits, enginePath),
      );
      const phase = options.arguments.slice(separator + 2).includes("--version")
        ? "version"
        : "transform";
      await hooks.beforeLaunch?.(phase);
      expect(enginePath).toBe(join(options.cwd!, `deobfuscate-safe-${phase}`));
      engineSnapshots.push({
        path: enginePath,
        bytes: await readFile(enginePath),
      });
      const start = separator + 2;
      const signalFixture = mode === "file-signal";
      const child = await spawnOwnedProviderProcess({
        ...options,
        command: signalFixture ? "/bin/sh" : process.execPath,
        expectedCommand: null,
        arguments: signalFixture
          ? ["-c", "kill -s XFSZ $$"]
          : [
              fileURLToPath(new URL("./producer.mjs", import.meta.url)),
              ...options.arguments.slice(start),
            ],
        env: {
          ...options.env,
          REA_DEOBFUSCATION_FIXTURE_MODE: mode,
          REA_DEOBFUSCATION_PRIVATE_ENGINE: enginePath,
        },
      });
      launches.push({ cwd: options.cwd, pid: child.process.pid });
      await hooks.afterLaunch?.(phase, child.process.pid);
      return child;
    },
  );
  return {
    provider,
    service: new JavaScriptDeobfuscationService(provider),
    path,
    output: join(root, "output"),
    command,
    launches,
    engineSnapshots,
  };
};

export const assertDeobfuscationCleanup = async (
  launches: Awaited<ReturnType<typeof deobfuscationFixture>>["launches"],
): Promise<void> => {
  for (const launch of launches) {
    const pid = launch.pid;
    if (pid !== undefined)
      expect(() => process.kill(-pid, 0)).toThrowError(
        expect.objectContaining({ code: "ESRCH" }),
      );
    if (launch.cwd !== undefined)
      await expect(access(launch.cwd)).rejects.toMatchObject({
        code: "ENOENT",
      });
  }
};
