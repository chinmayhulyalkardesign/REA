import { describe, expect, it } from "vitest";

import {
  setupClientId,
  windowsMcpAddDelegation,
} from "../../../scripts/lib/windows-mcp-add.mjs";
import { execFileOutput } from "../../../src/process/ExecFileOutput.js";

describe("rea mcp add on Windows (#5811)", () => {
  it("changes nothing off Windows or for other commands", () => {
    expect(
      windowsMcpAddDelegation(["mcp", "add", "--agent", "codex"], "linux"),
    ).toBeUndefined();
    expect(windowsMcpAddDelegation(["mcp", "add"], "darwin")).toBeUndefined();
    expect(windowsMcpAddDelegation(["doctor"], "win32")).toBeUndefined();
    expect(windowsMcpAddDelegation(["mcp"], "win32")).toBeUndefined();
  });

  it("maps incur agent names to setup client ids", () => {
    expect(setupClientId("claude-code")).toBe("claude_code");
    expect(setupClientId("Gemini-CLI")).toBe("gemini_cli");
    expect(setupClientId("codex")).toBe("codex");
  });

  it("delegates --agent to setup --client with --yes and keeps --dry-run and output flags", () => {
    const result = windowsMcpAddDelegation(
      [
        "mcp",
        "add",
        "--agent",
        "claude-code",
        "--agent=codex",
        "--dry-run",
        "--json",
      ],
      "win32",
    );
    expect(result).toEqual({
      args: [
        "setup",
        "--client",
        "claude_code",
        "--client",
        "codex",
        "--yes",
        "--dry-run",
        "--json",
      ],
      note: expect.stringContaining("#5811"),
    });
  });

  it.each([
    [["mcp", "add", "--agent", "codex", "--no-global"], "--no-global"],
    [["mcp", "add", "--agent", "codex", "--command", "x --mcp"], "--command"],
    [["mcp", "add", "--agent", "codex", "-c", "x --mcp"], "--command"],
    [["mcp", "add"], "--agent <id>"],
  ])(
    "refuses what setup cannot honor instead of dropping it: %j",
    (args, expected) => {
      const result = windowsMcpAddDelegation(args, "win32");
      expect(result).toHaveProperty("refusal");
      if (result !== undefined && "refusal" in result)
        expect(result.refusal).toContain(expected);
    },
  );

  it.skipIf(process.platform !== "win32")(
    "plans a Codex registration through setup on a real Windows host without writing",
    async () => {
      const result = await execFileOutput(
        process.execPath,
        ["scripts/rea.mjs", "mcp", "add", "--agent", "codex", "--dry-run"],
        { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 },
      );
      expect(result.stderr).toContain("#5811");
      expect(result.stdout).toContain("status: planned");
      expect(result.stdout).toContain("configure_client:codex");
    },
  );
});
