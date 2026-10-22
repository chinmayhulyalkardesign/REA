import { describe, expect, it } from "vitest";
import {
  buildPythonBytecodeHeader,
  isPythonBytecode,
  parsePythonBytecodeHeader,
  resolveMagicFromVersion,
  resolvePythonVersion,
} from "./PythonBytecode.js";

describe("PythonBytecode", () => {
  it("detects valid Python bytecode magic bytes and framing", () => {
    // 3439 (0x0d6f) -> [0x6f, 0x0d, 0x0d, 0x0a]
    const py310 = Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]);
    expect(isPythonBytecode(py310)).toBe(true);

    const invalidFraming = Buffer.from([0x6f, 0x0d, 0x00, 0x00]);
    expect(isPythonBytecode(invalidFraming)).toBe(false);

    const tooShort = Buffer.from([0x6f, 0x0d]);
    expect(isPythonBytecode(tooShort)).toBe(false);
  });

  it("resolves Python release versions from magic numbers", () => {
    expect(resolvePythonVersion(62211)).toBe("2.7");
    expect(resolvePythonVersion(3379)).toBe("3.6");
    expect(resolvePythonVersion(3413)).toBe("3.8");
    expect(resolvePythonVersion(3439)).toBe("3.10");
    expect(resolvePythonVersion(3495)).toBe("3.11");
    expect(resolvePythonVersion(3531)).toBe("3.12");
    expect(resolvePythonVersion(3571)).toBe("3.13");
    expect(resolvePythonVersion(99999)).toBe("Python-magic-99999");
  });

  it("resolves magic numbers from version strings", () => {
    expect(resolveMagicFromVersion("2.7")).toBe(62211);
    expect(resolveMagicFromVersion("3.10")).toBe(3439);
    expect(resolveMagicFromVersion("3.10.12")).toBe(3439);
    expect(resolveMagicFromVersion("3.12.1")).toBe(3531);
    expect(resolveMagicFromVersion("nonexistent")).toBeNull();
  });

  it("builds and parses Python 2.7 bytecode headers (8 bytes)", () => {
    const timestamp = new Date(1600000000000);
    const header = buildPythonBytecodeHeader("2.7", { timestamp });
    expect(header.length).toBe(8);

    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe("2.7");
    expect(parsed?.magicNumber).toBe(62211);
    expect(parsed?.isHashBased).toBe(false);
    expect(parsed?.codeObjectOffset).toBe(8);
    expect(parsed?.timestamp?.getTime()).toBe(1600000000000);
  });

  it("builds and parses Python 3.6 bytecode headers (12 bytes)", () => {
    const timestamp = new Date(1600000000000);
    const header = buildPythonBytecodeHeader("3.6", {
      timestamp,
      sourceSize: 4096,
    });
    expect(header.length).toBe(12);

    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe("3.6");
    expect(parsed?.magicNumber).toBe(3379);
    expect(parsed?.isHashBased).toBe(false);
    expect(parsed?.sourceSize).toBe(4096);
    expect(parsed?.codeObjectOffset).toBe(12);
  });

  it("builds and parses Python 3.10 PEP 552 timestamp headers (16 bytes)", () => {
    const timestamp = new Date(1680000000000);
    const header = buildPythonBytecodeHeader(3439, {
      timestamp,
      sourceSize: 8192,
    });
    expect(header.length).toBe(16);

    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe("3.10");
    expect(parsed?.magicNumber).toBe(3439);
    expect(parsed?.isHashBased).toBe(false);
    expect(parsed?.sourceSize).toBe(8192);
    expect(parsed?.codeObjectOffset).toBe(16);
  });

  it("builds and parses Python 3.11 PEP 552 hash-based headers (16 bytes)", () => {
    const hash = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const header = buildPythonBytecodeHeader("3.11", {
      isHashBased: true,
      hashMode: "checked",
      hash,
    });
    expect(header.length).toBe(16);

    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe("3.11");
    expect(parsed?.magicNumber).toBe(3495);
    expect(parsed?.isHashBased).toBe(true);
    expect(parsed?.hashMode).toBe("checked");
    expect(parsed?.codeObjectOffset).toBe(16);
  });

  it("builds and parses Python 3.2 bytecode headers (8 bytes)", () => {
    const timestamp = new Date(1600000000000);
    const header = buildPythonBytecodeHeader("3.2", { timestamp });
    expect(header.length).toBe(8);

    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe("3.2");
    expect(parsed?.magicNumber).toBe(3180);
    expect(parsed?.codeObjectOffset).toBe(8);
  });

  it("rejects truncated headers that do not have the complete version-specific length", () => {
    // Only 4 bytes of Python 3.10 magic
    const onlyMagic = Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]);
    expect(parsePythonBytecodeHeader(onlyMagic)).toBeNull();

    // 12 bytes of Python 3.10 (needs 16 bytes)
    const partial310 = Buffer.alloc(12);
    onlyMagic.copy(partial310);
    expect(parsePythonBytecodeHeader(partial310)).toBeNull();

    // 6 bytes of Python 2.7 (needs 8 bytes)
    const partial27 = Buffer.from([0x03, 0xf3, 0x0d, 0x0a, 0x00, 0x00]);
    expect(parsePythonBytecodeHeader(partial27)).toBeNull();
  });

  it("builds and parses Python 3.14 bytecode headers", () => {
    expect(resolvePythonVersion(3627)).toBe("3.14");
    expect(resolveMagicFromVersion("3.14")).toBe(3627);
    const header = buildPythonBytecodeHeader("3.14", { sourceSize: 1024 });
    expect(header.length).toBe(16);
    const parsed = parsePythonBytecodeHeader(header);
    expect(parsed?.version).toBe("3.14");
    expect(parsed?.magicNumber).toBe(3627);
  });

  it("throws when building header for unknown or unsupported version string", () => {
    expect(() => buildPythonBytecodeHeader("unknown_version")).toThrow(
      /Unsupported or unknown Python bytecode version/,
    );
  });
});
