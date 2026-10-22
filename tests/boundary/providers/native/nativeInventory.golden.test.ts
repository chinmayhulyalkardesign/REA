import { realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import {
  CPU,
  fatImage,
  machoImage,
} from "../../../../src/artifacts/apple/MachoImage.fixture.js";
import { err, ok } from "../../../../src/domain/result.js";
import {
  NativeCommandFailure,
  type NativeCommandCapture,
  type NativeCommandOptions,
  type NativeCommandRunner,
} from "../../../../src/native/CommandRunner.js";
import { inspectSignatureSchema } from "../../../../src/domain/native/nativeInspection.js";
import { NativeMacOSProvider } from "../../../../src/native/NativeMacOSProvider.js";
import { parseOtoolLoadCommands } from "../../../../src/native/parsers/otool.js";
import { parseDyldSymbols } from "../../../../src/native/parsers/dyldInfo.js";
import {
  NativeFixtureRunner as FixtureRunner,
  nativeFixture as fixture,
  nativeMachoTarget as machoTarget,
  nativeMachoTargetForFile,
  withOtoolMachHeader,
} from "../../../fixtures/nativeCommands.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const signatureTarget = async (
  signedArchitecture: "arm64" | "arm64e" = "arm64",
) => {
  const target = await signatureTargetFile(signedArchitecture);
  return target;
};

/** The same two-slice file classified as a universal container. */
const universalSignatureTarget = async (
  signedArchitecture: "arm64" | "arm64e" = "arm64",
) => {
  const { format: _format, ...target } =
    await signatureTargetFile(signedArchitecture);
  return {
    ...target,
    format: "mach-o-universal" as const,
    universalSlice: { offset: 0, size: 0 },
  };
};

const signatureTargetFile = async (
  signedArchitecture: "arm64" | "arm64e" = "arm64",
) => {
  const path = join(
    await createTestTempDirectory("rea-native-inventory-"),
    "fixture",
  );
  await writeFile(
    path,
    fatImage(
      [CPU.x86_64, CPU[signedArchitecture]].map((cpu) => ({
        cpu,
        bytes: machoImage({ cpu }),
      })),
    ),
  );
  return nativeMachoTargetForFile(path);
};

it("distinguishes a codesign execution failure from an observed unsigned artifact", async () => {
  for (const kind of ["missing", "unsigned"] as const) {
    const fixtureOutput = await fixture(`dyld-inventory/codesign-${kind}.txt`);
    const client = new NativeMacOSProvider(
      {},
      {
        async run(tool, arguments_) {
          const output =
            kind === "unsigned"
              ? `${arguments_.at(-1)}: code object is not signed at all\n`
              : fixtureOutput;
          const capture = await new FixtureRunner({ codesign: output }, 1).run(
            tool,
            arguments_,
          );
          if (!capture.ok || kind !== "unsigned") return capture;
          return ok({
            ...capture.value,
            stdout: "",
            stderr: output,
            stdoutBytes: 0,
            stderrBytes: Buffer.byteLength(output),
          });
        },
      },
      "darwin",
    ).createClient(await signatureTarget());
    const execution = await client.execute("inspect_signature", {});
    if (kind === "missing")
      expect(execution).toMatchObject({
        ok: false,
        error: { _tag: "ProviderAdapterError" },
      });
    else {
      expect(execution.ok).toBe(true);
      if (execution.ok)
        expect(execution.value.result).toMatchObject({ signed: false });
    }
  }
});

it("reports unsigned slices when a universal Mach-O has mixed signatures", async () => {
  const signedFixture = await fixture("codesign.txt");
  const unsigned = await fixture("dyld-inventory/codesign-unsigned.txt");
  const entitlements = await fixture("entitlements.xml");
  for (const signedArchitecture of ["arm64", "arm64e"] as const) {
    const signed = signedFixture.replace(
      /^Format=.*$/mu,
      `Format=Mach-O universal (x86_64 ${signedArchitecture})`,
    );
    const client = new NativeMacOSProvider(
      {},
      signatureRunner({ signed, unsigned, entitlements, unsignedHeader: true }),
      "darwin",
    ).createClient(await signatureTarget(signedArchitecture));

    const execution = await client.execute("inspect_signature", {});

    expect(execution.ok).toBe(true);
    if (!execution.ok) continue;
    expect(execution.value.result).toMatchObject({
      signed: true,
      identifier: "com.example.fixture",
      designated_requirement: null,
      entitlements: { "com.apple.security.app-sandbox": true },
      limitations: expect.arrayContaining([
        "Partial signature coverage: aggregate signing metadata describes codesign’s default slice; Mach-O slices have mixed signing states.",
        "Unsigned Mach-O slices: x86_64.",
        "The aggregate designated requirement is unavailable because Mach-O slices have mixed signing states.",
      ]),
      provenance: expect.arrayContaining([
        expect.objectContaining({
          command: [
            "/usr/bin/codesign",
            "-d",
            "-a",
            "x86_64",
            "--verbose=4",
            "$ARTIFACT",
          ],
          exit: { code: 1, signal: null },
        }),
        expect.objectContaining({
          command: expect.arrayContaining(["-a", signedArchitecture]),
          exit: { code: 0, signal: null },
        }),
      ]),
    });
  }
});

it("names the described slice and the differently signed slices of a signed universal Mach-O", async () => {
  // Real captures: the arm64 slice (codesign's default here) has the hardened
  // runtime and disable-library-validation; the x86_64 slice has neither and
  // carries get-task-allow under another identifier.
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      entitlements: await load("entitlements-aggregate.xml"),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          entitlements: await load("entitlements-x86_64.xml"),
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: await load("entitlements-arm64.xml"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const result = execution.value.result as {
    limitations: string[];
    provenance: { command: string[]; exit: { code: number | null } }[];
  };
  expect(result).toMatchObject({
    signed: true,
    identifier: "com.example.armslice",
    cdhashes: ["133d589374281103e27b32ee243781884bc41413"],
    hardened_runtime: true,
    entitlements: { "com.apple.security.cs.disable-library-validation": true },
  });
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      "Signature fields describe the arm64 slice that codesign displayed by default; other signed slices: x86_64 (CDHash 269615ed3412eb7a8c0945e51c76355412db4b12).",
      `Mach-O slices signed differently from the arm64 slice: x86_64 (identifier "com.example.x86slice"; hardened runtime off; entitlements "com.apple.security.cs.disable-library-validation" absent, "com.apple.security.get-task-allow": true).`,
      "designated_requirement covers the whole file and names CDHashes of other slices (x86_64 269615ed3412eb7a8c0945e51c76355412db4b12); cdhashes lists only the described slice.",
    ]),
  );
  expect(
    result.limitations.filter((text) => text.includes("Unsigned Mach-O")),
  ).toEqual([]);
  const commands = result.provenance.map(({ command }) =>
    command.slice(1, -1).join(" "),
  );
  expect(commands).toEqual([
    "-d --verbose=4",
    "-d -r-",
    "-d --entitlements :-",
    "-d -a x86_64 --verbose=4",
    // Only the slice that differs from the aggregate is asked for entitlements.
    "-d -a x86_64 --entitlements :-",
    "-d -a arm64 --verbose=4",
  ]);
  expect(result.provenance.every(({ exit }) => exit.code === 0)).toBe(true);
});

it("adds only the described-slice note when every slice is signed alike", async () => {
  // Ad hoc signing a universal file gives every slice the same identifier
  // and flags, as `codesign -s -` does; only the CDHashes differ.
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const aggregate = await load("aggregate.txt");
  const alike = (await load("slice-x86_64.txt"))
    .replace(/^Identifier=.*$/mu, "Identifier=com.example.armslice")
    .replace(
      /^CodeDirectory .*$/mu,
      /^CodeDirectory .*$/mu.exec(aggregate)?.[0] ?? "",
    );
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate,
      requirements: await load("requirements.txt"),
      entitlements: await load("entitlements-aggregate.xml"),
      slices: {
        x86_64: {
          display: alike,
          entitlements: await load("entitlements-aggregate.xml"),
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: await load("entitlements-arm64.xml"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toContain(
    "Signature fields describe the arm64 slice that codesign displayed by default; other signed slices: x86_64 (CDHash 269615ed3412eb7a8c0945e51c76355412db4b12).",
  );
  expect(limitations.some((text) => text.includes("signed differently"))).toBe(
    false,
  );
});

it("names signed slices when codesign's default slice is unsigned", async () => {
  // codesign's default slice (x86_64 here) is unsigned, so the aggregate
  // display says "not signed at all" and has no Format line. lipo names the
  // exact slices: the target only knows the arm64 CPU family, but the
  // signed slice is arm64e.x1, which codesign -a accepts by that name.
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  // codesign frames the unsigned verdict with the exact snapshot path.
  const unsignedFor = (snapshot: string) =>
    `${snapshot}: code object is not signed at all\n`;
  const armDisplay = (await load("slice-arm64.txt")).replace(
    "Format=Mach-O thin (arm64)",
    "Format=Mach-O thin (arm64e.x1)",
  );
  const runner: NativeCommandRunner = {
    run(tool: string, arguments_: readonly string[], options) {
      const architectureIndex = arguments_.indexOf("-a");
      const architecture =
        architectureIndex < 0 ? null : arguments_[architectureIndex + 1];
      const lipo = tool === "lipo";
      const signedSlice = architecture === "arm64e.x1";
      const stdout = lipo ? "x86_64 arm64e.x1\n" : "";
      const stderr = lipo
        ? ""
        : signedSlice
          ? armDisplay
          : unsignedFor(arguments_.at(-1) ?? "");
      const exitCode = lipo || signedSlice ? 0 : 1;
      const capture: NativeCommandCapture = {
        tool,
        executable: `/usr/bin/${tool}`,
        executableSha256: "a".repeat(64),
        toolVersion: null,
        versionReason: "fixture",
        arguments: [...arguments_],
        stdout,
        stderr,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        exitCode,
        signal: null,
      };
      return Promise.resolve(
        exitCode === 0 || options.acceptNonZero === true
          ? ok(capture)
          : err(new NativeCommandFailure(tool, "nonzero-exit", exitCode)),
      );
    },
  };
  const client = new NativeMacOSProvider({}, runner, "darwin").createClient(
    await universalSignatureTarget("arm64"),
  );

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const result = execution.value.result as {
    signed: boolean;
    limitations: string[];
    provenance: { command: string[]; exit: { code: number | null } }[];
  };
  expect(result.signed).toBe(false);
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      "Artifact is not signed.",
      "Unsigned Mach-O slices: x86_64.",
      `Mach-O slices signed although codesign's default slice is unsigned: arm64e.x1 (identifier "com.example.armslice"; team identifier not set; authorities none; CDHash 133d589374281103e27b32ee243781884bc41413; hardened runtime on); signed is false for the default slice and their entitlements were not reported.`,
    ]),
  );
  // A fully unsigned file is not "mixed"; that wording needs a signed slice.
  expect(
    result.limitations.filter((text) => text.includes("mixed signing")),
  ).toHaveLength(2);
  expect(
    result.provenance.map(({ command }) =>
      command
        .map((part, index) => (index === 0 ? part.split("/").at(-1) : part))
        .slice(0, -1)
        .join(" "),
    ),
  ).toEqual([
    "codesign -d --verbose=4",
    "codesign -d -r-",
    "codesign -d --entitlements :-",
    "lipo -archs",
    "codesign -d -a x86_64 --verbose=4",
    "codesign -d -a arm64e.x1 --verbose=4",
  ]);
});

it("falls back to the target's CPU families when lipo is unavailable", async () => {
  const unsignedFor = (snapshot: string) =>
    `${snapshot}: code object is not signed at all\n`;
  const armDisplay = await fixture("codesign-universal-signed/slice-arm64.txt");
  const runner: NativeCommandRunner = {
    run(tool: string, arguments_: readonly string[], options) {
      if (tool === "lipo")
        return Promise.resolve(
          err(new NativeCommandFailure(tool, "unavailable", null)),
        );
      const architecture = arguments_[arguments_.indexOf("-a") + 1];
      const signedSlice = arguments_.includes("-a") && architecture === "arm64";
      const stderr = signedSlice
        ? armDisplay
        : unsignedFor(arguments_.at(-1) ?? "");
      const exitCode = signedSlice ? 0 : 1;
      const capture: NativeCommandCapture = {
        tool,
        executable: `/usr/bin/${tool}`,
        executableSha256: "a".repeat(64),
        toolVersion: null,
        versionReason: "fixture",
        arguments: [...arguments_],
        stdout: "",
        stderr,
        stdoutBytes: 0,
        stderrBytes: Buffer.byteLength(stderr),
        exitCode,
        signal: null,
      };
      return Promise.resolve(
        exitCode === 0 || options.acceptNonZero === true
          ? ok(capture)
          : err(new NativeCommandFailure(tool, "nonzero-exit", exitCode)),
      );
    },
  };
  const client = new NativeMacOSProvider({}, runner, "darwin").createClient(
    await universalSignatureTarget("arm64"),
  );

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { signed, limitations } = execution.value.result as {
    signed: boolean;
    limitations: string[];
  };
  expect(signed).toBe(false);
  expect(limitations).toEqual(
    expect.arrayContaining([
      "lipo is unavailable, so slice names come from the target's CPU families; variants such as arm64e.x1 are not distinguished.",
      "Unsigned Mach-O slices: x86_64.",
      expect.stringMatching(
        /^Mach-O slices signed although codesign's default slice is unsigned: arm64 /u,
      ),
    ]),
  );
});

it("compares entitlement integers beyond the exact range by their digits", async () => {
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const plist = (digits: string) =>
    `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.example.limit</key><integer>${digits}</integer></dict></plist>`;
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      // Both literals round to the same JavaScript number.
      entitlements: plist("9007199254740992"),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          entitlements: plist("9007199254740993"),
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: plist("9007199254740992"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toEqual(
    expect.arrayContaining([
      expect.stringMatching(
        /^Mach-O slices signed differently from the arm64 slice: x86_64 \(identifier "com\.example\.x86slice"; hardened runtime off; entitlements "com\.example\.limit": \{"\$plist_type":"integer","decimal":"9007199254740993"\} \(described slice \{"\$plist_type":"integer","decimal":"9007199254740992"\}\)\)\.$/u,
      ),
    ]),
  );
});

it("treats a cut-off entitlements plist as unavailable, not as none", async () => {
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      entitlements: await load("entitlements-aggregate.xml"),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          // An XML header without the closing tag: present, but cut off.
          entitlements:
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/>',
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: await load("entitlements-arm64.xml"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toEqual(
    expect.arrayContaining([
      "Entitlements of the x86_64 slice: the entitlements plist is cut off before its closing tag; entitlements are unavailable.",
      "Entitlements could not be read for Mach-O slices: x86_64.",
    ]),
  );
  expect(limitations.some((text) => text.includes("entitlements none"))).toBe(
    false,
  );
});

it("reports a data entitlement against a dictionary shaped like its wrapper as different", async () => {
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const plist = (body: string) =>
    `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.example.blob</key>${body}</dict></plist>`;
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      // A dictionary shaped exactly like the projection's data wrapper
      // projects to the same JSON as a real <data> value.
      entitlements: plist(
        "<dict><key>$plist_type</key><string>data</string><key>base64</key><string>AQID</string></dict>",
      ),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          entitlements: plist("<data>AQID</data>"),
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: plist(
            "<dict><key>$plist_type</key><string>data</string><key>base64</key><string>AQID</string></dict>",
          ),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toEqual(
    expect.arrayContaining([
      expect.stringMatching(
        /^Mach-O slices signed differently from the arm64 slice: x86_64 \(identifier "com\.example\.x86slice"; hardened runtime off; entitlements same projected values, but the plist value types differ/u,
      ),
    ]),
  );
});

it("does not read an echoed file name as the unsigned verdict", async () => {
  // The snapshot's file name says "not signed at all"; codesign echoes it in
  // front of a different diagnostic, so the slice must stay unclassified.
  const directory = await createTestTempDirectory("rea-native-inventory-");
  const path = join(directory, "not signed at all");
  await writeFile(
    path,
    fatImage(
      [CPU.x86_64, CPU.arm64].map((cpu) => ({
        cpu,
        bytes: machoImage({ cpu }),
      })),
    ),
  );
  const target = await nativeMachoTargetForFile(path);
  const aggregate = await fixture("codesign-universal-signed/aggregate.txt");
  const armDisplay = await fixture("codesign-universal-signed/slice-arm64.txt");
  const requirements = await fixture(
    "codesign-universal-signed/requirements.txt",
  );
  const entitlements = await fixture(
    "codesign-universal-signed/entitlements-aggregate.xml",
  );
  const runner: NativeCommandRunner = {
    run(tool: string, arguments_: readonly string[], options) {
      const architectureIndex = arguments_.indexOf("-a");
      const architecture =
        architectureIndex < 0 ? null : arguments_[architectureIndex + 1];
      const snapshot = arguments_.at(-1) ?? "";
      const stdout = arguments_.includes("-r-")
        ? requirements
        : arguments_.includes("--entitlements")
          ? entitlements
          : "";
      const failing = architecture === "x86_64";
      const stderr = failing
        ? `${snapshot}: invalid or unsupported format\n`
        : stdout === ""
          ? architecture === "arm64"
            ? armDisplay
            : aggregate
          : "";
      const exitCode = failing ? 1 : 0;
      const capture: NativeCommandCapture = {
        tool,
        executable: `/usr/bin/${tool}`,
        executableSha256: "a".repeat(64),
        toolVersion: null,
        versionReason: "fixture",
        arguments: [...arguments_],
        stdout,
        stderr,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        exitCode,
        signal: null,
      };
      return Promise.resolve(
        exitCode === 0 || options.acceptNonZero === true
          ? ok(capture)
          : err(new NativeCommandFailure(tool, "nonzero-exit", exitCode)),
      );
    },
  };
  const client = new NativeMacOSProvider({}, runner, "darwin").createClient(
    target,
  );

  const execution = await client.execute("inspect_signature", {});

  // A slice query that fails for another reason is a failure that keeps the
  // facts collected so far; it is never read as the unsigned verdict.
  expect(execution).toMatchObject({
    ok: false,
    error: { _tag: "ProviderAdapterError" },
  });
  if (execution.ok) return;
  const partial = inspectSignatureSchema.parse(
    execution.error.partialObservation,
  );
  expect(partial.limitations).toEqual(
    expect.arrayContaining([expect.stringContaining("did not complete")]),
  );
  expect(
    partial.limitations.some((text) =>
      text.startsWith("Unsigned Mach-O slices"),
    ),
  ).toBe(false);
});

it("keeps a non-default slice's undecodable entitlements unobserved", async () => {
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      entitlements: await load("entitlements-aggregate.xml"),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          // A plist element that is not closed: present, but not decodable.
          entitlements:
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key></plist>',
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: await load("entitlements-arm64.xml"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toEqual(
    expect.arrayContaining([
      expect.stringMatching(
        /^Entitlements of the x86_64 slice: the entitlements plist could not be decoded/u,
      ),
      "Entitlements could not be read for Mach-O slices: x86_64.",
      // The comparison names what differs and says nothing about entitlements.
      `Mach-O slices signed differently from the arm64 slice: x86_64 (identifier "com.example.x86slice"; hardened runtime off).`,
    ]),
  );
  expect(limitations.some((text) => text.includes("entitlements none"))).toBe(
    false,
  );
});

it("keeps the result when a non-default slice's entitlements hold data or prototype keys", async () => {
  const load = (name: string) => fixture(`codesign-universal-signed/${name}`);
  const dataEntitlements =
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/><key>com.example.blob</key><data>AQID</data><key>__proto__</key><true/></dict></plist>';
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await load("aggregate.txt"),
      requirements: await load("requirements.txt"),
      entitlements: await load("entitlements-aggregate.xml"),
      slices: {
        x86_64: {
          display: await load("slice-x86_64.txt"),
          entitlements: dataEntitlements,
        },
        arm64: {
          display: await load("slice-arm64.txt"),
          entitlements: await load("entitlements-arm64.xml"),
        },
      },
    }),
    "darwin",
  ).createClient(await signatureTarget("arm64"));

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const { limitations } = execution.value.result as { limitations: string[] };
  expect(limitations).toEqual(
    expect.arrayContaining([
      expect.stringMatching(
        /^Entitlements of the x86_64 slice: .*__proto__.*$/u,
      ),
      'Mach-O slices signed differently from the arm64 slice: x86_64 (identifier "com.example.x86slice"; hardened runtime off; entitlements "com.apple.security.cs.disable-library-validation" absent, "com.apple.security.get-task-allow": true, "com.example.blob": {"$plist_type":"data","base64":"AQID"}).',
    ]),
  );
});

it("adds no slice note for a signed thin Mach-O", async () => {
  // codesign reports a thin format, so no slice is queried even though the
  // target lists two architectures; sliceRunner rejects any `-a` query.
  const client = new NativeMacOSProvider(
    {},
    sliceRunner({
      aggregate: await fixture("codesign.txt"),
      requirements: '# designated => identifier "com.example.fixture"\n',
      entitlements: await fixture("entitlements.xml"),
      slices: {},
    }),
    "darwin",
  ).createClient(
    await nativeMachoTargetForFile(
      await (async () => {
        const path = join(
          await createTestTempDirectory("rea-native-inventory-"),
          "thin",
        );
        await writeFile(path, machoImage({ cpu: CPU.arm64 }));
        return path;
      })(),
    ),
  );

  const execution = await client.execute("inspect_signature", {});

  if (!execution.ok) throw execution.error;
  const result = execution.value.result as {
    limitations: string[];
    provenance: { command: string[] }[];
  };
  expect(result.limitations.some((text) => /slice/iu.test(text))).toBe(false);
  expect(result.provenance).toHaveLength(3);
});

it("rejects nonzero supplemental codesign output that is not an unsigned observation", async () => {
  const signed = await fixture("codesign.txt");
  const entitlements = await fixture("entitlements.xml");
  const client = new NativeMacOSProvider(
    {},
    signatureRunner({
      signed,
      unsigned: "/private/fixture: invalid or unsupported format\n",
      entitlements,
    }),
    "darwin",
  ).createClient(await signatureTarget());

  const execution = await client.execute("inspect_signature", {});

  expect(execution).toMatchObject({
    ok: false,
    error: { _tag: "ProviderAdapterError" },
  });
});

it.each([
  "extra diagnostic",
  "foreign executable",
  "slice diagnostic",
  "later slice diagnostic",
])("rejects an unsigned response with %s", async (kind) => {
  const signed = (await fixture("codesign.txt")).replace(
    /^Format=.*$/mu,
    "Format=Mach-O universal (x86_64 arm64)",
  );
  const replay = signatureRunner({
    signed,
    unsigned: "code object is not signed at all",
    entitlements: await fixture("entitlements.xml"),
    unsignedHeader: true,
  });
  const runner: NativeCommandRunner = {
    async run(tool, args, options) {
      const result = await replay.run(tool, args, options);
      if (!result.ok) return result;
      if (kind === "later slice diagnostic") {
        if (!args.includes("arm64")) return result;
        const stderr = "later architecture probe failed\n";
        return ok({
          ...result.value,
          exitCode: 1,
          stderr,
          stderrBytes: Buffer.byteLength(stderr),
        });
      }
      if (result.value.exitCode === 0) return result;
      const isSlice = args.includes("-a");
      if ((kind === "slice diagnostic") !== isSlice) return result;
      const stderr =
        kind === "foreign executable"
          ? result.value.stderr.replace(
              /^Executable=.*\n/u,
              "Executable=/foreign/program\n",
            )
          : `${result.value.stderr}additional codesign failure\n`;
      return ok({
        ...result.value,
        stderr,
        stderrBytes: Buffer.byteLength(stderr),
      });
    },
  };
  const result = await new NativeMacOSProvider({}, runner, "darwin")
    .createClient(await signatureTarget())
    .execute("inspect_signature", {});
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "ProviderAdapterError" },
  });
  if (kind.endsWith("slice diagnostic") && !result.ok) {
    const partial = inspectSignatureSchema.parse(
      result.error.partialObservation,
    );
    expect(partial).toMatchObject({
      signed: true,
      identifier: "com.example.fixture",
      entitlements: { "com.apple.security.app-sandbox": true },
      designated_requirement: null,
      limitations: expect.arrayContaining([
        expect.stringContaining("Partial signature coverage"),
        expect.stringContaining("did not complete"),
      ]),
    });
    expect(partial.provenance).toHaveLength(
      kind === "later slice diagnostic" ? 5 : 4,
    );
    expect(partial.provenance[0]?.command).toContain("--verbose=4");
    expect(partial.provenance[1]?.command).toContain("-r-");
    expect(partial.provenance[2]?.command).toContain("--entitlements");
    if (kind === "later slice diagnostic") {
      expect(partial.limitations).toEqual(
        expect.arrayContaining([
          "Unsigned Mach-O slices: x86_64.",
          "The aggregate designated requirement is unavailable because Mach-O slices have mixed signing states.",
        ]),
      );
      expect(partial.provenance[4]).toMatchObject({
        command: expect.arrayContaining(["-a", "arm64"]),
        exit: { code: 1, signal: null },
      });
    }
    expect(partial.provenance[3]).toMatchObject({
      command: expect.arrayContaining(["-a", "x86_64"]),
      exit: { code: 1, signal: null },
    });
  }
});

it("retains native inventory facts from captured Apple tool output", async () => {
  const outputs: Record<string, string> = {};
  for (const tool of ["lipo", "otool", "nm", "dwarfdump", "vtool"])
    outputs[tool] = await fixture(`dyld-inventory/${tool}.txt`);
  outputs.otool = withOtoolMachHeader(outputs.otool ?? "");
  outputs["dyld_info:-imports"] = await fixture("dyld-inventory/imports.txt");
  const exportsOutput = await fixture("dyld-inventory/exports.txt");
  outputs["dyld_info:-exports"] = exportsOutput;
  const client = new NativeMacOSProvider(
    {},
    new FixtureRunner(outputs),
    "darwin",
  ).createClient(machoTarget("/private/fixture"));
  const execution = await client.execute("inspect_macho", {});
  if (!execution.ok) throw execution.error;
  expect(execution.value.result).toMatchObject({
    imports: {
      items: [
        { name: "_puts", address: null, source: "libSystem" },
        {
          name: "_fixture_weak",
          address: null,
          source: "<weak-def-coalesce>",
        },
      ],
    },
    exports: {
      items: expect.arrayContaining([
        expect.objectContaining({
          name: "_fixture_export",
          address: "0x100000468",
        }),
        expect.objectContaining({
          name: "_fixture_weak",
          address: "0x100000460",
          weak: true,
        }),
        expect.objectContaining({
          name: "_fixture_absolute",
          address: "0x42",
        }),
      ]),
    },
  });
  expect(
    parseDyldSymbols(await fixture("dyld-imports.txt"), "imports"),
  ).toEqual([
    {
      name: "__Block_copy",
      address: null,
      weak: null,
      reexport: null,
      source: "libSystem",
    },
    {
      name: "_objc_bp_assist_cfg_np",
      address: null,
      weak: true,
      reexport: null,
      source: "libSystem",
    },
  ]);
  expect(
    parseDyldSymbols(
      await fixture("dyld-inventory/library-reexports.txt"),
      "exports",
    ),
  ).toEqual([
    {
      name: "__ZNKSt10bad_typeid4whatEv",
      address: null,
      weak: null,
      reexport: true,
      source: "libc++abi",
    },
  ]);
  expect(parseDyldSymbols(exportsOutput, "exports")).toContainEqual({
    name: "_fixture_export",
    address: null,
    weak: null,
    reexport: false,
    source: null,
  });
});

it("reports a renamed re-export once under its exported name", async () => {
  const client = new NativeMacOSProvider(
    {},
    new FixtureRunner({
      "dyld_info:-exports": await fixture(
        "dyld-inventory/renamed-reexports.txt",
      ),
      nm: "_foo_renamed\n_own\n",
    }),
    "darwin",
  ).createClient(machoTarget("/private/fixture"));
  const execution = await client.execute("inspect_macho", {});
  if (!execution.ok) throw execution.error;
  expect(execution.value.result).toMatchObject({
    exports: {
      items: [
        {
          name: "_foo_renamed",
          address: null,
          weak: null,
          reexport: true,
          source: "libfoo",
        },
        { name: "_own", reexport: false, source: null },
      ],
      limitations: [
        "Merged nm/dyld_info results may be incomplete for stripped binaries.",
        "Renamed re-exports are listed under their exported name; the source library's symbol name is not reported.",
      ],
    },
  });
});

it("splits re-export rows at the source library", () => {
  // dyld_info -exports rows for synthetic dylibs: a source symbol named
  // `operator()`, and a library whose install name contains ` from `.
  expect(
    parseDyldSymbols(
      [
        "[re-export] _call_renamed (operator() from libfoo)",
        "[re-export] _g (from lib from foo)",
        "[re-export] _nested (from lib (from foo))",
      ].join("\n"),
      "exports",
      null,
      new Set(["_call_renamed", "_g", "_nested"]),
    ),
  ).toEqual([
    {
      name: "_call_renamed",
      address: null,
      weak: null,
      reexport: true,
      source: "libfoo",
      sourceSymbol: "operator()",
    },
    {
      name: "_g",
      address: null,
      weak: null,
      reexport: true,
      source: "lib from foo",
    },
    {
      name: "_nested",
      address: null,
      weak: null,
      reexport: true,
      source: "lib (from foo)",
    },
  ]);
});

it("retains symbol names containing spaces in dyld inventory rows", () => {
  expect(
    parseDyldSymbols("  0x0000  _entry with space  (from fixture)", "imports"),
  ).toEqual([
    {
      name: "_entry with space",
      address: null,
      weak: null,
      reexport: null,
      source: "fixture",
    },
  ]);
  expect(
    parseDyldSymbols(
      "  offset symbol\n  0x00000348  _entry with space",
      "exports",
      "0x0",
    ),
  ).toEqual([
    {
      name: "_entry with space",
      address: "0x348",
      weak: null,
      reexport: false,
      source: null,
    },
  ]);
  expect(
    parseDyldSymbols("[re-export] _entry with space (from fixture)", "exports"),
  ).toEqual([
    {
      name: "_entry with space",
      address: null,
      weak: null,
      reexport: true,
      source: "fixture",
    },
  ]);
  expect(
    parseDyldSymbols("0x123 _weak with space [weak-def]", "exports"),
  ).toEqual([
    {
      name: "_weak with space",
      address: "0x123",
      weak: true,
      reexport: false,
      source: null,
    },
  ]);
});

it("preserves numeric-looking segment and section identifiers from otool", () => {
  const parsed = parseOtoolLoadCommands(
    withOtoolMachHeader(`Load command 0
      cmd LC_SEGMENT_64
  cmdsize 152
  segname 0001
   vmaddr 0x0000000000004000
   vmsize 0x0000000000004000
  fileoff 16384
 filesize 16384
  maxprot 0x00000003
 initprot 0x00000003
   nsects 1
    flags 0x4
Section
  sectname 0002
   segname 0001
      addr 0x0000000000004000
      size 0x0000000000000008
    offset 16384
     align 2^0 (1)
    reloff 0
    nreloc 0
     flags 0x00000000
 reserved1 0
 reserved2 0
`),
  );
  expect(parsed.segments[0]).toMatchObject({
    name: "0001",
    file_offset: 16384,
    sections: [{ segment: "0001", name: "0002", size: 8 }],
  });
});

/** Answer codesign per slice: `-a <arch>` selects that slice's captures. */
const sliceRunner = (outputs: {
  readonly aggregate: string;
  readonly requirements: string;
  readonly entitlements: string;
  readonly slices: Readonly<
    Record<string, { readonly display: string; readonly entitlements: string }>
  >;
}): NativeCommandRunner => ({
  run(tool: string, arguments_: readonly string[]) {
    const architectureIndex = arguments_.indexOf("-a");
    const slice =
      architectureIndex < 0
        ? undefined
        : outputs.slices[arguments_[architectureIndex + 1] ?? ""];
    if (architectureIndex >= 0 && slice === undefined)
      throw new Error(`unexpected slice query: ${arguments_.join(" ")}`);
    const stdout = arguments_.includes("-r-")
      ? outputs.requirements
      : arguments_.includes("--entitlements")
        ? (slice?.entitlements ?? outputs.entitlements)
        : "";
    const stderr = stdout === "" ? (slice?.display ?? outputs.aggregate) : "";
    return Promise.resolve(
      ok({
        tool,
        executable: `/usr/bin/${tool}`,
        executableSha256: "a".repeat(64),
        toolVersion: null,
        versionReason: "fixture",
        arguments: [...arguments_],
        stdout,
        stderr,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        exitCode: 0,
        signal: null,
      } satisfies NativeCommandCapture),
    );
  },
});

const signatureRunner = (outputs: {
  readonly signed: string;
  readonly unsigned: string;
  readonly entitlements: string;
  readonly unsignedHeader?: boolean;
}): NativeCommandRunner => ({
  async run(
    tool: string,
    arguments_: readonly string[],
    options: NativeCommandOptions,
  ) {
    const architectureIndex = arguments_.indexOf("-a");
    const architecture =
      architectureIndex < 0 ? null : arguments_[architectureIndex + 1];
    const selectedResponse = arguments_.includes("-r-")
      ? { output: outputs.unsigned, exitCode: 1 }
      : arguments_.includes("--entitlements")
        ? { output: outputs.entitlements, exitCode: 0 }
        : architecture === "x86_64"
          ? { output: outputs.unsigned, exitCode: 1 }
          : { output: outputs.signed, exitCode: 0 };
    const response =
      selectedResponse.exitCode !== 0 &&
      selectedResponse.output.includes("code object is not signed at all")
        ? {
            ...selectedResponse,
            output: `${outputs.unsignedHeader ? `Executable=${await realpath(arguments_.at(-1)!)}\n` : ""}${arguments_.at(-1)}: code object is not signed at all\n`,
          }
        : selectedResponse;
    const capture: NativeCommandCapture = {
      tool,
      executable: `/usr/bin/${tool}`,
      executableSha256: "a".repeat(64),
      toolVersion: null,
      versionReason: "fixture",
      arguments: [...arguments_],
      // Entitlements XML is printed to stdout; diagnostics to stderr.
      ...(response.exitCode === 0 && arguments_.includes("--entitlements")
        ? {
            stdout: response.output,
            stderr: "",
            stdoutBytes: Buffer.byteLength(response.output),
            stderrBytes: 0,
          }
        : {
            stdout: "",
            stderr: response.output,
            stdoutBytes: 0,
            stderrBytes: Buffer.byteLength(response.output),
          }),
      exitCode: response.exitCode,
      signal: null,
    };
    return Promise.resolve(
      response.exitCode === 0 || options.acceptNonZero === true
        ? ok(capture)
        : err(
            new NativeCommandFailure(tool, "nonzero-exit", response.exitCode),
          ),
    );
  },
});

it.each([
  "/tmp/Load command 12/plugin.dylib",
  "@rpath/plugin-Load command 34.dylib",
])(
  "keeps load-command-looking text inside native install names: %s",
  (installName) => {
    const parsed = parseOtoolLoadCommands(
      withOtoolMachHeader(`Load command 0
          cmd LC_ID_DYLIB
      cmdsize 80
         name ${installName} (offset 24)
   time stamp 2 Thu Jan  1 00:00:02 1970
      current version 3.2.1
compatibility version 1.0.0
Load command 1
          cmd LC_UUID
      cmdsize 24
         uuid 01234567-89AB-CDEF-0123-456789ABCDEF
`),
    );
    expect(parsed.commands.map(({ index, kind }) => ({ index, kind }))).toEqual(
      [
        { index: 0, kind: "LC_ID_DYLIB" },
        { index: 1, kind: "LC_UUID" },
      ],
    );
    expect(parsed.commands[0]?.fields.name).toBe(`${installName} (offset 24)`);
    expect(parsed.dependencies).toEqual([]);
    expect(parsed.uuid).toBe("01234567-89AB-CDEF-0123-456789ABCDEF");
  },
);
it.each(["weak-def", "absolute", "literal suffix"])(
  "preserves an nm-proven export name ending in [%s]",
  (suffix) => {
    const name = `symbol [${suffix}]`;
    expect(
      parseDyldSymbols(
        `offset symbol\n0x120 ${name}`,
        "exports",
        "0x1000",
        new Set([name]),
      ),
    ).toEqual([
      { name, address: "0x1120", weak: null, reexport: false, source: null },
    ]);
  },
);

it("keeps true weak annotations when nm establishes the unannotated name", () => {
  expect(
    parseDyldSymbols(
      "0x120 _weak [weak-def]",
      "exports",
      null,
      new Set(["_weak"]),
    ),
  ).toEqual([
    {
      name: "_weak",
      address: "0x120",
      weak: true,
      reexport: false,
      source: null,
    },
  ]);
});

it("leaves an ambiguous short and literal name to the caller's nm inventory", () => {
  expect(
    parseDyldSymbols(
      "0x120 symbol [weak-def]",
      "exports",
      null,
      new Set(["symbol", "symbol [weak-def]"]),
    ),
  ).toEqual([]);
});

it("retains unmatched re-export rows when the known export inventory is incomplete", () => {
  expect(
    parseDyldSymbols(
      "[re-export] _g (from libfoo)",
      "exports",
      null,
      new Set(["_own"]),
    ),
  ).toEqual([
    {
      name: "_g",
      address: null,
      weak: null,
      reexport: true,
      source: "libfoo",
    },
  ]);
});

it("retains annotation parsing without nm name evidence", () => {
  expect(parseDyldSymbols("0x120 _weak [weak-def]", "exports")).toEqual([
    {
      name: "_weak",
      address: "0x120",
      weak: true,
      reexport: false,
      source: null,
    },
  ]);
});

/** Replay fixtures, answering nm by whether its dyld-info pass is disabled. */
const symbolTableRunner = (
  outputs: Readonly<Record<string, string>>,
  nm: { readonly symbolTable: string; readonly withDyldInfo: string },
) => {
  const nmArguments: (readonly string[])[] = [];
  const replay = (output: string) =>
    new FixtureRunner({ ...outputs, nm: output });
  const runner: NativeCommandRunner = {
    run: (tool, arguments_) => {
      if (tool !== "nm") return replay("").run(tool, arguments_);
      nmArguments.push(arguments_);
      return replay(
        arguments_.includes("--no-dyldinfo") ? nm.symbolTable : nm.withDyldInfo,
      ).run(tool, arguments_);
    },
  };
  return { runner, nmArguments };
};

/** nm arguments in provenance, which records the artifact operand as a placeholder. */
const nmCommands = (result: unknown) =>
  (result as { provenance: { tool: string; command: string[] }[] }).provenance
    .filter(({ tool }) => tool === "nm")
    .map(({ command }) => [...command.slice(1, -1), "/private/fixture"]);

it("reads exports from the symbol table without llvm-nm's dyld-info pass", async () => {
  const names = await fixture("dyld-inventory/nm.txt");
  const { runner, nmArguments } = symbolTableRunner(
    { "dyld_info:-exports": await fixture("dyld-inventory/exports.txt") },
    { symbolTable: names, withDyldInfo: names },
  );
  const execution = await new NativeMacOSProvider({}, runner, "darwin")
    .createClient(machoTarget("/private/fixture"))
    .execute("inspect_macho", {});
  if (!execution.ok) throw execution.error;
  expect(nmArguments).toEqual([
    ["-gjU", "--no-dyldinfo", "-arch", "arm64", "/private/fixture"],
  ]);
  expect(nmCommands(execution.value.result)).toEqual(nmArguments);
});

it("reruns nm with its dyld-info pass when a stripped symbol table omits trie exports", async () => {
  const trieNames = await fixture("dyld-inventory/stripped-swift-nm.txt");
  const { runner, nmArguments } = symbolTableRunner(
    {
      "dyld_info:-exports": await fixture(
        "dyld-inventory/stripped-swift-exports.txt",
      ),
    },
    { symbolTable: "", withDyldInfo: trieNames },
  );
  const execution = await new NativeMacOSProvider({}, runner, "darwin")
    .createClient(machoTarget("/private/fixture"))
    .execute("inspect_macho", {});
  if (!execution.ok) throw execution.error;
  const rerun = ["-gjU", "-arch", "arm64", "/private/fixture"];
  expect(nmArguments).toEqual([
    ["-gjU", "--no-dyldinfo", "-arch", "arm64", "/private/fixture"],
    rerun,
  ]);
  // Provenance names the nm run whose output the exports came from.
  expect(nmCommands(execution.value.result)).toEqual([rerun]);
  const exported = (
    execution.value.result as { exports: { items: { name: string }[] } }
  ).exports.items.map(({ name }) => name);
  expect(exported).toEqual(trieNames.trim().split("\n").sort());
});

it("reruns nm with its dyld-info pass when a dyld_info export row is unreadable", async () => {
  const names = await fixture("dyld-inventory/nm.txt");
  const exportsOutput = await fixture("dyld-inventory/exports.txt");
  const { runner, nmArguments } = symbolTableRunner(
    {
      "dyld_info:-exports": `${exportsOutput.trimEnd()}\n        <unrecognized export row>\n`,
    },
    { symbolTable: names, withDyldInfo: names },
  );
  const execution = await new NativeMacOSProvider({}, runner, "darwin")
    .createClient(machoTarget("/private/fixture"))
    .execute("inspect_macho", {});
  if (!execution.ok) throw execution.error;
  expect(nmArguments.map((arguments_) => arguments_.slice(0, 2))).toEqual([
    ["-gjU", "--no-dyldinfo"],
    ["-gjU", "-arch"],
  ]);
});
