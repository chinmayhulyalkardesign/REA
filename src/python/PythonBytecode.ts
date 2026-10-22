/**
 * Python bytecode (.pyc) format identification, header parsing, and metadata extraction.
 * Supports Python 2.7 through Python 3.13 (including PEP 552 hash-based pycs).
 */

export interface PythonBytecodeMetadata {
  readonly version: string;
  readonly magicNumber: number;
  readonly isHashBased: boolean;
  readonly hashMode?: "checked" | "unchecked" | undefined;
  readonly timestamp?: Date | undefined;
  readonly sourceSize?: number | undefined;
  readonly codeObjectOffset: number;
}

/** Python magic numbers mapped to human-readable version identifiers. */
const PYTHON_MAGIC_VERSIONS: Readonly<Record<number, string>> = {
  // Python 2.x
  62211: "2.7",
  62161: "2.6",
  62061: "2.5",
  62011: "2.4",

  // Python 3.x
  3000: "3.0",
  3141: "3.1",
  3180: "3.2",
  3230: "3.3",
  3310: "3.4",
  3350: "3.5",
  3379: "3.6",
  3394: "3.7",
  3413: "3.8",
  3425: "3.9",
  3439: "3.10",
  3495: "3.11",
  3531: "3.12",
  3571: "3.13",
  3627: "3.14",
};

/** Verify if bytes begin with valid Python bytecode magic and CRLF framing. */
export const isPythonBytecode = (bytes: Uint8Array): boolean => {
  if (bytes.length < 4) return false;
  // Pyc files end the 4-byte header prefix with \r\n (0x0d, 0x0a)
  if (bytes[2] !== 0x0d || bytes[3] !== 0x0a) return false;
  const magic = bytes[0]! | (bytes[1]! << 8);
  return (
    Object.hasOwn(PYTHON_MAGIC_VERSIONS, magic) ||
    (magic >= 3000 && magic <= 4000)
  );
};

/** Identify Python release version from raw magic number. */
export const resolvePythonVersion = (magic: number): string => {
  return PYTHON_MAGIC_VERSIONS[magic] ?? `Python-magic-${magic}`;
};

/**
 * Parse .pyc binary header and compute payload offset according to Python PEP 552.
 */
export const parsePythonBytecodeHeader = (
  bytes: Buffer,
): PythonBytecodeMetadata | null => {
  if (!isPythonBytecode(bytes)) return null;

  const magic = bytes.readUInt16LE(0);
  const version = resolvePythonVersion(magic);
  const [majorStr, minorStr] = version.split(".");
  const major = Number(majorStr);
  const minor = Number(minorStr);

  // Python 2.x and Python 3.0 to 3.2: 4-byte magic + 4-byte timestamp = 8 bytes
  if (major === 2 || (major === 3 && minor < 3)) {
    if (bytes.length < 8) return null;
    const timestampSec = bytes.readUInt32LE(4);
    return {
      version,
      magicNumber: magic,
      isHashBased: false,
      timestamp: new Date(timestampSec * 1000),
      codeObjectOffset: 8,
    };
  }

  // Python 3.3 to 3.6: 4-byte magic + 4-byte timestamp + 4-byte size = 12 bytes
  if (major === 3 && minor < 7) {
    if (bytes.length < 12) return null;
    const timestampSec = bytes.readUInt32LE(4);
    const sourceSize = bytes.readUInt32LE(8);
    return {
      version,
      magicNumber: magic,
      isHashBased: false,
      timestamp: new Date(timestampSec * 1000),
      sourceSize,
      codeObjectOffset: 12,
    };
  }

  // Python 3.7+ (PEP 552): 4-byte magic + 4-byte bitfield + 8-byte hash/timestamp + 4-byte size = 16 bytes
  if (bytes.length < 16) return null;
  const bitfield = bytes.readUInt32LE(4);
  const isHashBased = (bitfield & 0x01) !== 0;

  if (isHashBased) {
    const checkHash = (bitfield & 0x02) !== 0;
    return {
      version,
      magicNumber: magic,
      isHashBased: true,
      hashMode: checkHash ? "checked" : "unchecked",
      codeObjectOffset: 16,
    };
  }

  const timestampSec = bytes.readUInt32LE(8);
  const sourceSize = bytes.readUInt32LE(12);

  return {
    version,
    magicNumber: magic,
    isHashBased: false,
    timestamp: new Date(timestampSec * 1000),
    sourceSize,
    codeObjectOffset: 16,
  };
};

const VERSION_TO_MAGIC: Record<string, number> = Object.entries(
  PYTHON_MAGIC_VERSIONS,
).reduce<Record<string, number>>((acc, [magic, ver]) => {
  acc[ver] = Number(magic);
  return acc;
}, {});

/** Resolve magic number from Python version string (e.g., "3.10", "2.7", "3.11.2"). */
export const resolveMagicFromVersion = (version: string): number | null => {
  if (Object.hasOwn(VERSION_TO_MAGIC, version)) {
    return VERSION_TO_MAGIC[version]!;
  }
  const parts = version.split(".");
  if (parts.length >= 2) {
    const key = `${parts[0]}.${parts[1]}`;
    if (Object.hasOwn(VERSION_TO_MAGIC, key)) {
      return VERSION_TO_MAGIC[key]!;
    }
  }
  return null;
};

export interface PythonHeaderBuildOptions {
  readonly timestamp?: Date | undefined;
  readonly sourceSize?: number | undefined;
  readonly isHashBased?: boolean | undefined;
  readonly hashMode?: "checked" | "unchecked" | undefined;
  readonly hash?: Buffer | undefined;
}

/** Construct a compliant .pyc header for a target version or magic number. */
export const buildPythonBytecodeHeader = (
  versionOrMagic: number | string,
  options?: PythonHeaderBuildOptions,
): Buffer => {
  let magic: number;
  if (typeof versionOrMagic === "number") {
    magic = versionOrMagic;
  } else {
    const resolved = resolveMagicFromVersion(versionOrMagic);
    if (resolved === null) {
      throw new Error(
        `Unsupported or unknown Python bytecode version: ${versionOrMagic}`,
      );
    }
    magic = resolved;
  }
  const version = resolvePythonVersion(magic);
  const [majorStr, minorStr] = version.split(".");
  const major = Number(majorStr);
  const minor = Number(minorStr);

  const timestampSec = options?.timestamp
    ? Math.floor(options.timestamp.getTime() / 1000)
    : 0;
  const sourceSize = options?.sourceSize ?? 0;

  // Python 2.x and Python 3.0 to 3.2: 8 bytes
  if (major === 2 || (major === 3 && minor < 3)) {
    const header = Buffer.alloc(8);
    header.writeUInt16LE(magic, 0);
    header[2] = 0x0d;
    header[3] = 0x0a;
    header.writeUInt32LE(timestampSec, 4);
    return header;
  }

  // Python 3.3 to 3.6: 12 bytes
  if (major === 3 && minor < 7) {
    const header = Buffer.alloc(12);
    header.writeUInt16LE(magic, 0);
    header[2] = 0x0d;
    header[3] = 0x0a;
    header.writeUInt32LE(timestampSec, 4);
    header.writeUInt32LE(sourceSize, 8);
    return header;
  }

  // Python 3.7+ (PEP 552): 16 bytes
  const header = Buffer.alloc(16);
  header.writeUInt16LE(magic, 0);
  header[2] = 0x0d;
  header[3] = 0x0a;

  if (options?.isHashBased) {
    const bitfield = options.hashMode === "checked" ? 0x03 : 0x01;
    header.writeUInt32LE(bitfield, 4);
    if (options.hash && options.hash.length >= 8) {
      options.hash.copy(header, 8, 0, 8);
    }
    return header;
  }

  header.writeUInt32LE(0, 4);
  header.writeUInt32LE(timestampSec, 8);
  header.writeUInt32LE(sourceSize, 12);
  return header;
};
