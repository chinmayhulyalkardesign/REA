import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished } from "vitest";

import { AdbProvider } from "../../../src/adb/AdbProvider.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const hostPathsFixture = async () => {
  const root = await createTestTempDirectory("rea-adb-host-paths-");
  const physical = join(root, "physical");
  await mkdir(join(physical, "nested"), { recursive: true });
  await symlink(join(physical, "nested"), join(root, "alias"));
  const binary = join(root, "fake-adb.mjs");
  await writeFile(
    binary,
    `#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
if (args[0] === 'version') {
  console.log('Android Debug Bridge version 1.0.41\\nVersion 34.0.5-fixture');
} else if (args[2] === 'push' || args[2] === 'install') {
  writeFileSync(process.argv[1] + '.consumed', readFileSync(args[3]));
  console.log('Success');
} else if (args[2] === 'pull') {
  writeFileSync(args[4], 'pulled payload');
} else if (args[2] === 'shell' && args[3] === 'test') {
  process.exitCode = 1;
} else {
  process.exitCode = 127;
}
`,
    { mode: 0o700 },
  );
  return { root, physical, binary, environment: { REA_ADB_PATH: binary } };
};

for (const operation of ["push_adb_file", "install_adb_package"] as const) {
  cliTest.skipIf(process.platform === "win32")(
    `${operation} selects the filesystem input through a symlink before .. in CLI and MCP`,
    async ({ cli }) => {
      const { root, physical, binary, environment } = await hostPathsFixture();
      const selected = `${root}/alias/../payload.apk`;
      const intended = "selected payload";
      await writeFile(join(physical, "payload.apk"), intended);
      await writeFile(join(root, "payload.apk"), "wrong sibling");
      const push = operation === "push_adb_file";
      const input = {
        serial: "emulator-5554",
        ...(push
          ? {
              local_path: selected,
              device_path: "/data/local/tmp/payload.apk",
              overwrite: false,
            }
          : { apk_path: selected, replace: false }),
      };
      const arguments_ = push
        ? [
            "push-adb-file",
            input.serial,
            selected,
            "/data/local/tmp/payload.apk",
          ]
        : ["install-adb-package", input.serial, selected];
      const output = await cli.run({
        arguments: [...arguments_, "--json"],
        environment,
      });
      expect(output.exitCode, output.stdout).toBe(0);
      const harness = await createApplicationMcpHarness({
        serverOptions: { adbDeviceAnalysis: new AdbProvider({ environment }) },
      });
      onTestFinished(() => harness.close());
      const schemas = await advertisedMcpToolSchemas(harness.client, operation);
      const expected = {
        [push ? "local_path" : "apk_path"]: selected,
        bytes: Buffer.byteLength(intended),
        sha256: createHash("sha256").update(intended).digest("hex"),
      };
      expect(parseEvidence(output.json).normalized_result).toMatchObject(
        expected,
      );
      expect(parseEvidence(output.json).parameters).toMatchObject(input);
      expect(await readFile(binary + ".consumed", "utf8")).toBe(intended);
      const response = await harness.client.callTool(
        { name: schemas.name, arguments: input },
        { toolDefinition: schemas.toolDefinition },
      );
      expect(response.isError).not.toBe(true);
      expect(
        schemas.ajv.validate(schemas.outputSchema, response.structuredContent),
      ).toBe(true);
      expect(
        parseEvidence(response.structuredContent).normalized_result,
      ).toMatchObject(expected);
      expect(
        parseEvidence(response.structuredContent).parameters,
      ).toMatchObject(input);
      expect(await readFile(binary + ".consumed", "utf8")).toBe(intended);
      expect(await readFile(join(root, "payload.apk"), "utf8")).toBe(
        "wrong sibling",
      );
    },
  );
}

cliTest.skipIf(process.platform === "win32")(
  "pull-adb-file publishes in the filesystem-selected output directory through a symlink before ..",
  async ({ cli }) => {
    const { root, physical, environment } = await hostPathsFixture();
    const selected = `${root}/alias/../downloads`;
    const output = await cli.run({
      arguments: [
        "pull-adb-file",
        "emulator-5554",
        "/data/local/tmp/payload.bin",
        "--output-directory",
        selected,
        "--json",
      ],
      environment,
    });
    expect(output.exitCode, output.stdout).toBe(0);
    expect(
      await readFile(join(physical, "downloads/payload.bin"), "utf8"),
    ).toBe("pulled payload");
    expect(parseEvidence(output.json).normalized_result).toMatchObject({
      local_path: join(physical, "downloads/payload.bin"),
    });
    expect(parseEvidence(output.json).parameters).toMatchObject({
      output_directory: selected,
    });
    await expect(lstat(join(root, "downloads"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);
