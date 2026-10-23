import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const UNKNOWN_CASE =
  "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.";

const git = (root: string, args: readonly string[]) =>
  spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => !name.startsWith("GIT_"),
        ),
      ),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: join(root, ".git", "missing-global.config"),
      GIT_CONFIG_COUNT: "0",
    },
  });

const fixture = async (config: string) => {
  const root = await createTestTempDirectory("rea-reference-config-parsing-");
  const initialized = git(root, [
    "init",
    "--quiet",
    "--template=",
    "--initial-branch=main",
  ]);
  expect(initialized.status, initialized.stderr).toBe(0);
  for (const [path, content] of Object.entries({
    ".git/config": config,
    ".gitignore": "/generated/\n",
    "Generated/keep.ts": "export const rootSource = true;\n",
    "pkg/.gitignore": "generated/\n",
    "pkg/Generated/keep.ts": "export const nestedSource = true;\n",
    "visible.ts": "export const visible = true;\n",
  })) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
  return root;
};

const readInventory = async (root: string) => {
  const result = await importReferenceSource({
    root,
    caller: "git-config-parsing-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  return result.value;
};

const validConfigCases = [
  {
    name: "empty assignment",
    config: "[core]\nignoreCase =\n",
    expected: false,
  },
  {
    name: "quoted empty assignment",
    config: '[core]\nignoreCase = ""\n',
    expected: false,
  },
  {
    name: "empty assignment with comment",
    config: "[core]\nignoreCase = # false\n",
    expected: false,
  },
  {
    name: "quoted empty assignment with comment",
    config: '[core]\nignoreCase = ""# false\n',
    expected: false,
  },
  { name: "bare variable", config: "[core]\nignoreCase\n", expected: true },
  {
    name: "file-leading BOM",
    config: "\uFEFF[core]\nignoreCase = false\n",
    expected: false,
  },
  {
    name: "BOM inside quoted value",
    config: '[core]\nignoreCase = false\n[user]\nname = "\uFEFFauthor\uFEFF"\n',
    expected: false,
  },
  {
    name: "BOM inside unquoted value",
    config: "[core]\nignoreCase = false\n[user]\nname = \uFEFFauthor\uFEFF\n",
    expected: false,
  },
  {
    name: "CRLF and ASCII whitespace",
    config: '[core]\r\n\tignoreCase \t=\t "" \t\r\n',
    expected: false,
  },
  {
    name: "unquoted escaped backslash",
    config: "[core]\nignoreCase=false\n[user]\nname=valid\\\\q\n",
    expected: false,
  },
  {
    name: "unquoted newline, tab and backspace escapes",
    config: "[core]\nignoreCase=false\n[user]\nname=line\\nnext\\ttab\\bback\n",
    expected: false,
  },
  {
    name: "unquoted escaped quote",
    config: '[core]\nignoreCase=false\n[user]\nname=valid\\"quote\n',
    expected: false,
  },
  {
    name: "invalid escapes and quotes after value comments",
    config:
      '[core]\nignoreCase=false\n[user]\nname=valid # bad\\q "ignored\nemail="valid"; bad\\q\n',
    expected: false,
  },
  {
    name: "trailing backslash inside a value comment",
    config: "[core]\nignoreCase=false # ignored\\\n",
    expected: false,
  },
  {
    name: "trailing backslash inside a section comment",
    config: "[core] # ignored\\\nignoreCase=false\n",
    expected: false,
  },
  ...(
    [
      ["octal zero", "00", false],
      ["negative zero", "-0", false],
      ["positive zero", "+0", false],
      ["hexadecimal zero", "0x0", false],
      ["signed uppercase hexadecimal zero", "-0X00", false],
      ["kilobyte zero", "00k", false],
      ["megabyte zero", "0M", false],
      ["gigabyte zero", "+0x0G", false],
      ["long leading-zero integer", `${"0".repeat(256)}g`, false],
      ["decimal nonzero", "2", true],
      ["negative nonzero", "-1", true],
      ["positive nonzero", "+2", true],
      ["octal nonzero", "010", true],
      ["hexadecimal nonzero", "0Xf", true],
      ["kilobyte nonzero", "1K", true],
      ["negative megabyte nonzero", "-2m", true],
      ["gigabyte nonzero", "1g", true],
      ["scaled signed minimum", "-2g", true],
      ["signed maximum", "2147483647", true],
      ["signed minimum", "-2147483648", true],
      ["hexadecimal signed minimum", "-0x80000000", true],
      ["octal signed maximum", "017777777777", true],
      ["quoted leading space", '" 00"', false],
      ["decoded leading tab", '"\\t-0"', false],
      ["decoded leading newline", '"\\n0x0"', false],
    ] as const
  ).map(([name, value, expected]) => ({
    name: `numeric boolean: ${name}`,
    config: `[core]\nignoreCase = ${value}\n`,
    expected,
  })),
  {
    name: "numeric false worktree extension",
    config: "[core]\nignoreCase=false\n[extensions]\nworktreeConfig=-0k\n",
    expected: false,
  },
  ...(
    [
      ["unquoted then quoted fragment", 'fal"se"', false],
      ["quoted then unquoted fragment", '"fal"se', false],
      ["adjacent quoted fragments", '"f""a""l""s""e"', false],
      ["empty inner fragment", 'f""alse', false],
      ["empty leading fragment", '""false', false],
      ["empty trailing fragment", 'false""', false],
      ["empty adjacent fragments", '""""', false],
      ["split hexadecimal zero", '"0"x"0"', false],
      ["split signed unit zero", '"-"0"G"', false],
      ["quoted leading decoded tab", '"\\t"0', false],
      ["empty fragment before boundary whitespace", '"" 0', false],
      ["fragment before hash comment", 'fal"se" # ignored\\q "', false],
      ["fragment before semicolon comment", '"fal"se; ignored\\q', false],
      ["true fragments", 'tr"ue"', true],
    ] as const
  ).map(([name, value, expected]) => ({
    name: `quoted fragments: ${name}`,
    config: `[core]\nignoreCase = ${value}\n`,
    expected,
  })),
  ...[
    {
      name: "quoted comments in a mixed unrelated value",
      config: '[core]\nignoreCase=false\n[user]\nname=pre"#;value"post\n',
      expected: false,
    },
    {
      name: "escaped quote and backslash in mixed unrelated values",
      config:
        '[core]\nignoreCase=false\n[user]\nname=pre"escaped\\"quote"post\nemail=pre"escaped\\\\backslash"post\n',
      expected: false,
    },
  ],
];

describe.skipIf(process.platform === "win32")(
  "reference source Git config parsing",
  () => {
    it.each(validConfigCases)(
      "matches Git for $name",
      async ({ config, expected }) => {
        const root = await fixture(config);
        const configured = git(root, [
          "config",
          "--bool",
          "--get",
          "core.ignoreCase",
        ]);
        expect(configured.status, configured.stderr).toBe(0);
        expect(configured.stdout.trim()).toBe(String(expected));
        const traversed = git(root, [
          "ls-files",
          "--others",
          "--exclude-standard",
          "-z",
        ]);
        expect(traversed.status, traversed.stderr).toBe(0);
        const files = traversed.stdout.split("\0").filter(Boolean).sort();
        expect(files.includes("Generated/keep.ts")).toBe(!expected);
        expect(files.includes("pkg/Generated/keep.ts")).toBe(!expected);

        const graph = await readInventory(root);
        expect(graph.limitations).not.toContain(UNKNOWN_CASE);
        expect(
          graph.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path)
            .sort(),
        ).toEqual(files);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "reference source malformed Git config parsing",
  () => {
    it.each([
      {
        name: "BOM at the later variable",
        config: "[core]\n\uFEFFignoreCase = false\n",
      },
      {
        name: "BOM at the later section",
        config: '[core]\nignoreCase = false\n\uFEFF[user]\nname = "author"\n',
      },
      {
        name: "BOM at the assignment separator",
        config: "[core]\nignoreCase\uFEFF = false\n",
      },
      {
        name: "BOM at the section terminator",
        config: "[core\uFEFF]\nignoreCase = false\n",
      },
      {
        name: "BOM at the unquoted boolean suffix",
        config: "[core]\nignoreCase = false\uFEFF\n",
      },
      {
        name: "BOM at the quoted boolean suffix",
        config: '[core]\nignoreCase = "false"\uFEFF # comment\n',
      },
      {
        name: "unquoted unsupported escape",
        config: "[core]\nignoreCase=false\n[user]\nname=bad\\q\n",
      },
      {
        name: "unquoted escaped hash",
        config: "[core]\nignoreCase=false\n[user]\nname=bad\\#suffix\n",
      },
      {
        name: "unquoted escaped semicolon",
        config: "[core]\nignoreCase=false\n[user]\nname=bad\\;suffix\n",
      },
      {
        name: "decoded tab at the end of a boolean",
        config: "[core]\nignoreCase=false\\t\n",
      },
      ...(
        [
          ["positive overflow", "2147483648"],
          ["negative overflow", "-2147483649"],
          ["scaled positive overflow", "2g"],
          ["scaled negative overflow", "-3g"],
          ["hexadecimal overflow", "0x80000000"],
          ["octal overflow", "020000000000"],
          ["64-bit overflow", "9223372036854775808"],
          ["invalid octal digit", "08"],
          ["missing hexadecimal digits", "0x"],
          ["missing signed digits", "+"],
          ["unsupported radix prefix", "0o0"],
          ["fractional number", "1.0"],
          ["exponent notation", "1e0"],
          ["unsupported unit", "0t"],
          ["extra unit characters", "0kb"],
          ["quoted trailing space", '"0 "'],
          ["decoded trailing newline", '"0\\n"'],
          ["decoded leading backspace", '"\\b0"'],
          ["leading Unicode whitespace", '"\u00a00"'],
          ["whitespace without digits", '" "'],
        ] as const
      ).map(([name, value]) => ({
        name: `invalid numeric boolean: ${name}`,
        config: `[core]\nignoreCase = ${value}\n`,
      })),
      ...(
        [
          ["unterminated later fragment", 'fal"se'],
          ["unmatched final quote", '"false""'],
          ["quoted hash stays value data", 'false"#suffix"'],
          ["quoted semicolon stays value data", 'false";suffix"'],
          ["whitespace before empty fragment", '"false" ""'],
          ["numeric whitespace before empty fragment", '"0" ""'],
          ["quoted interior whitespace", 'fa" "lse'],
          ["decoded trailing tab fragment", '0"\\t"'],
          ["escaped quote stays value data", 'fal\\"se'],
          ["unsupported escape inside fragment", 'fal"\\q"se'],
        ] as const
      ).map(([name, value]) => ({
        name: `invalid quoted fragments: ${name}`,
        config: `[core]\nignoreCase = ${value}\n`,
      })),
    ])("retains uncertainty for $name", async ({ config }) => {
      const root = await fixture(config);
      const configured = git(root, [
        "config",
        "--bool",
        "--get",
        "core.ignoreCase",
      ]);
      expect(configured.status).toBe(128);
      const traversed = git(root, [
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
      ]);
      expect(traversed.status).toBe(128);

      const graph = await readInventory(root);
      expect(graph.limitations).toContain(UNKNOWN_CASE);
      expect(graph.entries.map(({ path }) => path)).toContain("visible.ts");
      for (const path of ["Generated", "pkg/Generated"])
        expect(graph.exclusions).toContainEqual(
          expect.objectContaining({
            path,
            reason: "project-ignored",
            pattern: path.startsWith("pkg/") ? "generated/" : "/generated/",
            policy_path: path.startsWith("pkg/")
              ? "pkg/.gitignore"
              : ".gitignore",
          }),
        );
    });
  },
);
