import zlib from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  extractPyInstallerEntries,
  findPyInstallerCookie,
  isPyInstallerBinary,
  parsePyInstallerArchive,
  parsePyzArchive,
  PYINSTALLER_MAGIC,
  PYZ_MAGIC,
} from "./PyInstallerExtractor.js";
import { isPythonBytecode } from "./PythonBytecode.js";

const marshalString = (text: string): Buffer => {
  const body = Buffer.from(text, "utf8");
  if (body.length <= 255 && body.every((byte) => byte < 0x80))
    return Buffer.concat([Buffer.from([0x7a, body.length]), body]);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(body.length);
  return Buffer.concat([Buffer.from([0x75]), length, body]);
};

const int32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(5);
  bytes[0] = 0x69;
  bytes.writeInt32LE(value, 1);
  return bytes;
};

const smallTuple = (items: readonly Buffer[]): Buffer =>
  Buffer.concat([Buffer.from([0x29, items.length]), ...items]);

const marshalPair = (
  name: string,
  typeCode: number,
  offset: number,
  length: number,
): Buffer =>
  smallTuple([
    marshalString(name),
    smallTuple([int32(typeCode), int32(offset), int32(length)]),
  ]);

const marshalList = (items: readonly Buffer[]): Buffer => {
  const count = Buffer.alloc(4);
  count.writeInt32LE(items.length, 0);
  return Buffer.concat([Buffer.from([0x5b]), count, ...items]);
};

const createMockPyzArchive = (): Buffer => {
  const pycMagic = Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]); // 3439 (Python 3.10)
  const codeObject = Buffer.from("PRINT_HELLO_WORLD_CODE_OBJECT_12345");
  const compressedMod = zlib.deflateSync(codeObject);

  const modOffset = 12;
  const modLen = compressedMod.length;

  // Build standard PyInstaller PYZ table: [ (name, (typeCode, offset, length)) ]
  const tocBuf = marshalList([marshalPair("app.engine", 0, modOffset, modLen)]);

  const tocOffset = 12 + compressedMod.length;

  const header = Buffer.alloc(12);
  PYZ_MAGIC.copy(header, 0);
  pycMagic.copy(header, 4);
  header.writeUInt32BE(tocOffset, 8);

  return Buffer.concat([header, compressedMod, tocBuf]);
};

const createMockPyInstallerBinary = (): Buffer => {
  const bootloaderPrefix = Buffer.alloc(256, 0x90); // 256 bytes dummy executable
  const pyzData = createMockPyzArchive();

  const scriptCode = Buffer.from("MAIN_ENTRY_POINT_CODE_OBJECT_DATA");
  const compressedScript = zlib.deflateSync(scriptCode);

  const dllData = Buffer.from("MOCK_PYTHON_RUNTIME_DLL_PAYLOAD");

  // Pack data inside CArchive
  let carchiveData = Buffer.alloc(0);

  // 1. PYZ entry
  const pyzOffset = carchiveData.length;
  carchiveData = Buffer.concat([carchiveData, pyzData]);

  // 2. Script entry (compressed)
  const scriptOffset = carchiveData.length;
  carchiveData = Buffer.concat([carchiveData, compressedScript]);

  // 3. DLL entry (uncompressed)
  const dllOffset = carchiveData.length;
  carchiveData = Buffer.concat([carchiveData, dllData]);

  // Build CArchive TOC
  const createTocEntry = (options: {
    readonly name: string;
    readonly typeFlag: string;
    readonly pkgOffset: number;
    readonly compressedLen: number;
    readonly uncompressedLen: number;
    readonly compressionFlag: number;
  }): Buffer => {
    const {
      name,
      typeFlag,
      pkgOffset,
      compressedLen,
      uncompressedLen,
      compressionFlag,
    } = options;
    const nameBytes = Buffer.from(`${name}\0`, "utf8");
    const structLen = 18 + nameBytes.length;
    const entry = Buffer.alloc(structLen);
    entry.writeUInt32BE(structLen, 0);
    entry.writeUInt32BE(pkgOffset, 4);
    entry.writeUInt32BE(compressedLen, 8);
    entry.writeUInt32BE(uncompressedLen, 12);
    entry.writeUInt8(compressionFlag, 16);
    entry.writeUInt8(typeFlag.charCodeAt(0), 17);
    nameBytes.copy(entry, 18);
    return entry;
  };

  const tocEntries = Buffer.concat([
    createTocEntry({
      name: "PYZ-00.pyz",
      typeFlag: "z",
      pkgOffset: pyzOffset,
      compressedLen: pyzData.length,
      uncompressedLen: pyzData.length,
      compressionFlag: 0,
    }),
    createTocEntry({
      name: "main.py",
      typeFlag: "s",
      pkgOffset: scriptOffset,
      compressedLen: compressedScript.length,
      uncompressedLen: scriptCode.length,
      compressionFlag: 1,
    }),
    createTocEntry({
      name: "python310.dll",
      typeFlag: "b",
      pkgOffset: dllOffset,
      compressedLen: dllData.length,
      uncompressedLen: dllData.length,
      compressionFlag: 0,
    }),
  ]);

  const tocOffset = carchiveData.length;
  const tocLength = tocEntries.length;
  const pkgLength = carchiveData.length + tocLength + 88;

  // Build PyInstaller Cookie (88 bytes)
  const cookie = Buffer.alloc(88);
  PYINSTALLER_MAGIC.copy(cookie, 0);
  cookie.writeUInt32BE(pkgLength, 8);
  cookie.writeUInt32BE(tocOffset, 12);
  cookie.writeUInt32BE(tocLength, 16);
  cookie.writeInt32BE(310, 20); // Python 3.10
  Buffer.from("python310.dll\0", "ascii").copy(cookie, 24);

  return Buffer.concat([bootloaderPrefix, carchiveData, tocEntries, cookie]);
};

describe("PyInstallerExtractor - archive parsing", () => {
  it("detects PyInstaller cookie and extracts metadata", () => {
    const mockBinary = createMockPyInstallerBinary();
    expect(isPyInstallerBinary(mockBinary)).toBe(true);

    const cookie = findPyInstallerCookie(mockBinary);
    expect(cookie).not.toBeNull();
    expect(cookie?.pythonVersion).toBe(310);
    expect(cookie?.pythonLibName).toBe("python310.dll");
  });

  it("parses PYZ archive header and embedded modules", () => {
    const mockPyz = createMockPyzArchive();
    const pyz = parsePyzArchive(mockPyz);
    expect(pyz).not.toBeNull();
    expect(pyz?.pythonVersion).toBe("3.10");
    expect(pyz?.modules.length).toBe(1);
    expect(pyz?.modules[0]?.name).toBe("app.engine");
    expect(pyz?.modules[0]?.isPackage).toBe(false);
  });

  it("parses PyInstaller CArchive TOC structure", () => {
    const mockBinary = createMockPyInstallerBinary();
    const archive = parsePyInstallerArchive(mockBinary);
    expect(archive).not.toBeNull();
    expect(archive?.tocEntries.length).toBe(3);

    const names = archive?.tocEntries.map((e) => e.name);
    expect(names).toContain("PYZ-00.pyz");
    expect(names).toContain("main.py");
    expect(names).toContain("python310.dll");
    expect(archive?.embeddedPyz).toBeDefined();
    expect(archive?.embeddedPyz?.pythonVersion).toBe("3.10");
  });
});

describe("PyInstallerExtractor - entry extraction and safety limits", () => {
  it("extracts all entries and reconstructs valid .pyc bytecode files", () => {
    const mockBinary = createMockPyInstallerBinary();
    const extracted = extractPyInstallerEntries(mockBinary);
    expect(extracted.length).toBeGreaterThanOrEqual(3);

    // 1. Script entry point
    const script = extracted.find((f) => f.name === "main.py");
    expect(script).toBeDefined();
    expect(script?.kind).toBe("script");
    expect(script?.decompressed).toBe(true);
    // Bytecode header must be reconstructed!
    expect(isPythonBytecode(script!.data)).toBe(true);

    // 2. Extracted PYZ module
    const pyzMod = extracted.find((f) => f.name === "app/engine.pyc");
    expect(pyzMod).toBeDefined();
    expect(pyzMod?.kind).toBe("module");
    expect(pyzMod?.decompressed).toBe(true);
    expect(isPythonBytecode(pyzMod!.data)).toBe(true);
    expect(pyzMod?.pythonVersion).toBe("3.10");

    // 3. Binary DLL file
    const dll = extracted.find((f) => f.name === "python310.dll");
    expect(dll).toBeDefined();
    expect(dll?.kind).toBe("binary");
    expect(dll?.data.toString("utf8")).toBe("MOCK_PYTHON_RUNTIME_DLL_PAYLOAD");
  });

  it("handles tiny PYZ with huge tuple count gracefully without memory exhaustion", () => {
    // 17 bytes: valid header, tocOffset = 12, bytes: 28 ff ff ff ff (tuple count = 4294967295)
    const header = Buffer.alloc(12);
    PYZ_MAGIC.copy(header, 0);
    Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]).copy(header, 4);
    header.writeUInt32BE(12, 8);
    const malformed = Buffer.concat([
      header,
      Buffer.from([0x28, 0xff, 0xff, 0xff, 0xff]),
    ]);
    const pyz = parsePyzArchive(malformed);
    expect(pyz).not.toBeNull();
    expect(pyz?.modules).toEqual([]);
  });

  it("bounds decompression when uncompressedLength is smaller than expanded output", () => {
    const raw = Buffer.alloc(1024, 0x41);
    const compressed = zlib.deflateSync(raw);

    // Build binary with declared uncompressedLen = 10, but actual = 1024
    const cookie = Buffer.alloc(88);
    PYINSTALLER_MAGIC.copy(cookie, 0);

    const nameBytes = Buffer.from("bomb.py\0", "utf8");
    const structLen = 18 + nameBytes.length;
    const tocEntry = Buffer.alloc(structLen);
    tocEntry.writeUInt32BE(structLen, 0);
    tocEntry.writeUInt32BE(0, 4); // pkgOffset = 0
    tocEntry.writeUInt32BE(compressed.length, 8);
    tocEntry.writeUInt32BE(10, 12); // uncompressedLen = 10 (exceeded by 1024)
    tocEntry.writeUInt8(1, 16); // compressed
    tocEntry.writeUInt8("s".charCodeAt(0), 17);
    nameBytes.copy(tocEntry, 18);

    const carchiveData = compressed;
    const tocOffset = carchiveData.length;
    const tocLength = tocEntry.length;
    const pkgLength = carchiveData.length + tocLength + 88;

    cookie.writeUInt32BE(pkgLength, 8);
    cookie.writeUInt32BE(tocOffset, 12);
    cookie.writeUInt32BE(tocLength, 16);
    cookie.writeInt32BE(310, 20);

    const binary = Buffer.concat([carchiveData, tocEntry, cookie]);
    const extracted = extractPyInstallerEntries(binary);
    expect(extracted.length).toBe(1);
    expect(extracted[0]?.decompressed).toBe(false);
    expect(extracted[0]?.limitations[0]).toContain("Decompression error");
  });

  it("rejects non-string names in PYZ table to prevent expansion bombs", () => {
    const header = Buffer.alloc(12);
    PYZ_MAGIC.copy(header, 0);
    Buffer.from([0x6f, 0x0d, 0x0d, 0x0a]).copy(header, 4);
    header.writeUInt32BE(12, 8);

    // Marshal table containing a tuple with a nested list instead of string name:
    // [ ( [1, 2], (0, 12, 0) ) ]
    const table = Buffer.from([
      0x5b,
      0x01,
      0x00,
      0x00,
      0x00, // list of 1 element
      0x28,
      0x02,
      0x00,
      0x00,
      0x00, // tuple of 2 elements:
      0x5b,
      0x00,
      0x00,
      0x00,
      0x00, // element 0: empty list (not string!)
      0x28,
      0x03,
      0x00,
      0x00,
      0x00, // element 1: tuple of 3 integers:
      0xe9,
      0x00,
      0x00,
      0x00,
      0x00, // 0 (typeCode)
      0xe9,
      0x0c,
      0x00,
      0x00,
      0x00, // 12 (offset)
      0xe9,
      0x00,
      0x00,
      0x00,
      0x00, // 0 (length)
    ]);
    const pyz = parsePyzArchive(Buffer.concat([header, table]));
    expect(pyz).not.toBeNull();
    expect(pyz?.modules).toEqual([]);
  });

  it("charges failed or corrupt inflations against remaining budget", () => {
    // Construct mock binary with corrupt compressed entry
    const corruptData = Buffer.from("not_valid_deflate_data");
    const nameBytes = Buffer.from("corrupt.py\0", "utf8");
    const structLen = 18 + nameBytes.length;
    const entry = Buffer.alloc(structLen);
    entry.writeUInt32BE(structLen, 0);
    entry.writeUInt32BE(0, 4); // offset 0
    entry.writeUInt32BE(corruptData.length, 8);
    entry.writeUInt32BE(100, 12);
    entry.writeUInt8(1, 16); // compressionFlag = 1 (zlib)
    entry.writeUInt8("s".charCodeAt(0), 17);
    nameBytes.copy(entry, 18);

    const carchiveData = corruptData;
    const tocEntries = entry;
    const tocOffset = carchiveData.length;
    const tocLength = tocEntries.length;
    const pkgLength = carchiveData.length + tocLength + 88;

    const cookie = Buffer.alloc(88);
    PYINSTALLER_MAGIC.copy(cookie, 0);
    cookie.writeUInt32BE(pkgLength, 8);
    cookie.writeUInt32BE(tocOffset, 12);
    cookie.writeUInt32BE(tocLength, 16);
    cookie.writeInt32BE(310, 20);

    const mockBinary = Buffer.concat([carchiveData, tocEntries, cookie]);
    const extracted = extractPyInstallerEntries(mockBinary);
    expect(extracted).toHaveLength(1);
    expect(extracted[0]!.decompressed).toBe(false);
    expect(extracted[0]!.limitations[0]).toMatch(/Decompression error/);
  });
});
