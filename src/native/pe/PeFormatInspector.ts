import {
  calculateShannonEntropy,
  isLikelyPackedOrEncrypted,
} from "../ShannonEntropy.js";
import { parsePeRichHeader, type PeRichHeader } from "./PeRichHeaderParser.js";

export interface PeSectionInfo {
  readonly name: string;
  readonly virtualSize: number;
  readonly virtualAddress: number;
  readonly rawSize: number;
  readonly rawOffset: number;
  readonly characteristics: number;
  readonly entropy?: number | undefined;
  readonly isPackedOrEncrypted?: boolean | undefined;
  readonly isExecutable: boolean;
  readonly isWritable: boolean;
}

export interface PeDataDirectory {
  readonly name: string;
  readonly virtualAddress: number;
  readonly size: number;
}

export interface PeAuthenticodeInfo {
  readonly fileOffset: number;
  readonly size: number;
  readonly revision?: number | undefined;
  readonly certificateType?: number | undefined;
}

export interface PeFormatReport {
  readonly machine: string;
  readonly machineCode: number;
  readonly is64Bit: boolean;
  readonly numberOfSections: number;
  readonly timestamp: Date;
  readonly entryPointRva: number;
  readonly imageBase: bigint;
  readonly subsystem: string;
  readonly subsystemCode: number;
  readonly dllCharacteristics: readonly string[];
  readonly sections: readonly PeSectionInfo[];
  readonly dataDirectories: readonly PeDataDirectory[];
  readonly richHeader?: PeRichHeader | undefined;
  readonly authenticode?: PeAuthenticodeInfo | undefined;
  readonly overallEntropy: number;
}

const MACHINE_NAMES: Readonly<Record<number, string>> = {
  0x014c: "i386 (32-bit x86)",
  0x8664: "AMD64 (64-bit x86-64)",
  0x01c0: "ARM",
  0xaa64: "ARM64",
  0x0200: "IA64 (Intel Itanium)",
};

const SUBSYSTEM_NAMES: Readonly<Record<number, string>> = {
  1: "NATIVE",
  2: "WINDOWS_GUI",
  3: "WINDOWS_CUI (Console)",
  7: "POSIX_CUI",
  9: "WINDOWS_CE_GUI",
  10: "EFI_APPLICATION",
  11: "EFI_BOOT_SERVICE_DRIVER",
  12: "EFI_RUNTIME_DRIVER",
  14: "XBOX",
};

const DATA_DIRECTORY_NAMES = [
  "EXPORT",
  "IMPORT",
  "RESOURCE",
  "EXCEPTION",
  "CERTIFICATE",
  "BASE_RELOC",
  "DEBUG",
  "ARCHITECTURE",
  "GLOBAL_PTR",
  "TLS",
  "LOAD_CONFIG",
  "BOUND_IMPORT",
  "IAT",
  "DELAY_IMPORT",
  "CLR_RUNTIME_HEADER",
  "RESERVED",
] as const;

/** Decode section flags into semantic booleans. */
const isExecutableSection = (characteristics: number): boolean =>
  (characteristics & 0x20000000) !== 0; // IMAGE_SCN_MEM_EXECUTE

const isWritableSection = (characteristics: number): boolean =>
  (characteristics & 0x80000000) !== 0; // IMAGE_SCN_MEM_WRITE

const readSectionName = (header: Buffer): string => {
  return header.subarray(0, 8).toString("utf8").replace(/\0.*$/s, "");
};

/** Deep-inspect Windows PE executable (PE32 / PE32+) structures, entropy, and telemetry. */
const decodeDllCharacteristics = (dllCharValue: number): string[] => {
  const flags: string[] = [];
  if ((dllCharValue & 0x0020) !== 0) flags.push("HIGH_ENTROPY_VA");
  if ((dllCharValue & 0x0040) !== 0) flags.push("DYNAMIC_BASE (ASLR)");
  if ((dllCharValue & 0x0100) !== 0) flags.push("NX_COMPAT (DEP)");
  if ((dllCharValue & 0x0400) !== 0) flags.push("NO_SEH");
  if ((dllCharValue & 0x4000) !== 0) flags.push("GUARD_CF");
  return flags;
};

const parseDataDirectories = (
  buffer: Buffer,
  dirOffset: number,
  count: number,
  maxOffset: number,
): {
  directories: PeDataDirectory[];
  authenticode?: PeAuthenticodeInfo | undefined;
} => {
  const directories: PeDataDirectory[] = [];
  let certInfo: PeAuthenticodeInfo | undefined;
  const numDirs = Math.min(count, 16);

  for (let i = 0; i < numDirs; i += 1) {
    const entryOffset = dirOffset + i * 8;
    if (entryOffset + 8 > maxOffset || entryOffset + 8 > buffer.length) break;
    const va = buffer.readUInt32LE(entryOffset);
    const size = buffer.readUInt32LE(entryOffset + 4);
    const name = DATA_DIRECTORY_NAMES[i] ?? `DIR_${i}`;
    directories.push({ name, virtualAddress: va, size });

    if (i === 4 && va > 0 && size > 0 && va + size <= buffer.length) {
      const revision = size >= 8 ? buffer.readUInt16LE(va + 4) : undefined;
      const certType = size >= 8 ? buffer.readUInt16LE(va + 6) : undefined;
      certInfo = { fileOffset: va, size, revision, certificateType: certType };
    }
  }

  return { directories, authenticode: certInfo };
};

const MAX_TOTAL_SECTION_SCAN_BYTES = 64 * 1024 * 1024; // 64 MiB budget

const parseSections = (
  buffer: Buffer,
  sectionsOffset: number,
  numberOfSections: number,
): PeSectionInfo[] => {
  const sections: PeSectionInfo[] = [];
  const entropyCache = new Map<string, number>();
  let totalScannedBytes = 0;
  const safeSectionCount = Math.min(numberOfSections, 1024);

  for (let i = 0; i < safeSectionCount; i += 1) {
    const secOffset = sectionsOffset + i * 40;
    if (secOffset + 40 > buffer.length) break;

    const secBuf = buffer.subarray(secOffset, secOffset + 40);
    const name = readSectionName(secBuf);
    const virtualSize = secBuf.readUInt32LE(8);
    const virtualAddress = secBuf.readUInt32LE(12);
    const rawSize = secBuf.readUInt32LE(16);
    const rawOffset = secBuf.readUInt32LE(20);
    const characteristics = secBuf.readUInt32LE(36);

    const endOffset = Math.min(rawOffset + rawSize, buffer.length);
    const sectionBytes =
      rawOffset < buffer.length && endOffset >= rawOffset
        ? buffer.subarray(rawOffset, endOffset)
        : new Uint8Array(0);

    const rangeKey = `${rawOffset}:${sectionBytes.length}`;
    let entropy: number | undefined;
    const cached = entropyCache.get(rangeKey);
    if (cached !== undefined) {
      entropy = cached;
    } else if (
      totalScannedBytes + sectionBytes.length <=
      MAX_TOTAL_SECTION_SCAN_BYTES
    ) {
      entropy = calculateShannonEntropy(sectionBytes);
      totalScannedBytes += sectionBytes.length;
      entropyCache.set(rangeKey, entropy);
    } else {
      entropy = undefined;
    }

    const isPacked =
      entropy !== undefined ? isLikelyPackedOrEncrypted(entropy) : undefined;

    sections.push({
      name,
      virtualSize,
      virtualAddress,
      rawSize,
      rawOffset,
      characteristics,
      entropy: entropy !== undefined ? Number(entropy.toFixed(3)) : undefined,
      isPackedOrEncrypted: isPacked,
      isExecutable: isExecutableSection(characteristics),
      isWritable: isWritableSection(characteristics),
    });
  }

  return sections;
};

/** Deep-inspect Windows PE executable (PE32 / PE32+) structures, entropy, and telemetry. */
export const inspectPeFormat = (buffer: Buffer): PeFormatReport | null => {
  if (buffer.length < 64 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return null;
  }

  const peOffset = buffer.readUInt32LE(0x3c);
  if (
    peOffset + 24 > buffer.length ||
    buffer[peOffset] !== 0x50 ||
    buffer[peOffset + 1] !== 0x45 ||
    buffer[peOffset + 2] !== 0x00 ||
    buffer[peOffset + 3] !== 0x00
  ) {
    return null;
  }

  const fileHeaderOffset = peOffset + 4;
  const machineCode = buffer.readUInt16LE(fileHeaderOffset);
  const numberOfSections = buffer.readUInt16LE(fileHeaderOffset + 2);
  const timeDateStampSec = buffer.readUInt32LE(fileHeaderOffset + 4);
  const sizeOfOptionalHeader = buffer.readUInt16LE(fileHeaderOffset + 16);

  const optionalHeaderOffset = fileHeaderOffset + 20;
  if (
    sizeOfOptionalHeader < 2 ||
    optionalHeaderOffset + sizeOfOptionalHeader > buffer.length
  ) {
    return null;
  }

  const magic = buffer.readUInt16LE(optionalHeaderOffset);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const is64Bit = magic === 0x20b;

  const minRequiredOptSize = is64Bit ? 112 : 96;
  if (sizeOfOptionalHeader < minRequiredOptSize) return null;

  const entryPointRva = buffer.readUInt32LE(optionalHeaderOffset + 16);
  const imageBase = is64Bit
    ? buffer.readBigUInt64LE(optionalHeaderOffset + 24)
    : BigInt(buffer.readUInt32LE(optionalHeaderOffset + 28));

  const subsystemCode = buffer.readUInt16LE(optionalHeaderOffset + 68);
  const dllCharValue = buffer.readUInt16LE(optionalHeaderOffset + 70);
  const dllCharacteristics = decodeDllCharacteristics(dllCharValue);

  const numRvaAndSizesOffset = optionalHeaderOffset + (is64Bit ? 108 : 92);
  const numberOfRvaAndSizes = buffer.readUInt32LE(numRvaAndSizesOffset);
  const dirOffset = optionalHeaderOffset + (is64Bit ? 112 : 96);
  const optHeaderEnd = optionalHeaderOffset + sizeOfOptionalHeader;

  const { directories: dataDirectories, authenticode } = parseDataDirectories(
    buffer,
    dirOffset,
    numberOfRvaAndSizes,
    optHeaderEnd,
  );

  const sectionsOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sections = parseSections(buffer, sectionsOffset, numberOfSections);

  return {
    machine:
      MACHINE_NAMES[machineCode] ?? `Machine-0x${machineCode.toString(16)}`,
    machineCode,
    is64Bit,
    numberOfSections,
    timestamp: new Date(timeDateStampSec * 1000),
    entryPointRva,
    imageBase,
    subsystem: SUBSYSTEM_NAMES[subsystemCode] ?? `Subsystem-${subsystemCode}`,
    subsystemCode,
    dllCharacteristics,
    sections,
    dataDirectories,
    richHeader: parsePeRichHeader(buffer) ?? undefined,
    authenticode,
    overallEntropy: Number(calculateShannonEntropy(buffer).toFixed(3)),
  };
};
