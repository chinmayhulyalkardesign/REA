import { describe, expect, it } from "vitest";
import { inspectPeFormat } from "./PeFormatInspector.js";
import { parsePeRichHeader } from "./PeRichHeaderParser.js";

const createMockPeBinary = (): Buffer => {
  const buf = Buffer.alloc(2048, 0);

  // 1. DOS Header
  buf[0] = 0x4d; // 'M'
  buf[1] = 0x5a; // 'Z'
  const peOffset = 128;
  buf.writeUInt32LE(peOffset, 0x3c); // e_lfanew

  // 2. Rich Header in DOS stub (between 0x40 and peOffset)
  const xorKey = 0x12345678;
  const dansOffset = 0x50;
  const richOffset = 0x68; // 0x50 + 16 + 8 = 0x68 (exactly 1 record)

  // Write decrypted DanS and records, then XOR
  buf.writeUInt32LE(0x536e6144 ^ xorKey, dansOffset); // DanS
  buf.writeUInt32LE(0 ^ xorKey, dansOffset + 4); // padding 1
  buf.writeUInt32LE(0 ^ xorKey, dansOffset + 8); // padding 2
  buf.writeUInt32LE(0 ^ xorKey, dansOffset + 12); // padding 3

  // Record 1: prodId=0x0103 (VS 2019 Utc1920_C), build=29244, count=5
  const dword1 = ((0x0103 << 16) | 29244) ^ xorKey;
  const count = 5 ^ xorKey;
  buf.writeUInt32LE(dword1, dansOffset + 16);
  buf.writeUInt32LE(count, dansOffset + 20);

  // Write Rich marker and XOR key
  buf.writeUInt32LE(0x68636952, richOffset); // "Rich"
  buf.writeUInt32LE(xorKey, richOffset + 4);

  // 3. PE Signature
  buf.write("PE\0\0", peOffset, "ascii");

  // 4. COFF Header
  const coffOffset = peOffset + 4;
  buf.writeUInt16LE(0x8664, coffOffset); // AMD64 (x64)
  buf.writeUInt16LE(2, coffOffset + 2); // 2 sections
  buf.writeUInt32LE(1680000000, coffOffset + 4); // timestamp
  const optHeaderSize = 240;
  buf.writeUInt16LE(optHeaderSize, coffOffset + 16); // SizeOfOptionalHeader
  buf.writeUInt16LE(0x0022, coffOffset + 18); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // 5. Optional Header (PE32+ / 64-bit)
  const optOffset = coffOffset + 20;
  buf.writeUInt16LE(0x20b, optOffset); // Magic: PE32+
  buf.writeUInt32LE(0x1000, optOffset + 16); // AddressOfEntryPoint (RVA 0x1000)
  buf.writeBigUInt64LE(0x140000000n, optOffset + 24); // ImageBase (0x140000000)
  buf.writeUInt16LE(3, optOffset + 68); // Subsystem: Windows CUI (Console)
  buf.writeUInt16LE(0x0160, optOffset + 70); // DllCharacteristics: ASLR | DEP | HIGH_ENTROPY_VA

  // Write NumberOfRvaAndSizes at optOffset + 108
  buf.writeUInt32LE(16, optOffset + 108);

  // Data directories (Offset 112 into Optional Header for 64-bit)
  const rvaBase = optOffset + 112;
  // Security directory (index 4)
  const certOffset = 1024;
  const certSize = 64;
  buf.writeUInt32LE(certOffset, rvaBase + 4 * 8); // Raw file offset for certificate
  buf.writeUInt32LE(certSize, rvaBase + 4 * 8 + 4); // Size

  // Write mock WIN_CERTIFICATE structure at 1024
  buf.writeUInt32LE(certSize, certOffset); // dwLength
  buf.writeUInt16LE(0x0200, certOffset + 4); // wRevision = WIN_CERT_REVISION_2_0
  buf.writeUInt16LE(0x0002, certOffset + 6); // wCertificateType = PKCS_SIGNED_DATA

  // 6. Section Headers (2 sections: .text and .data)
  const secOffset = optOffset + optHeaderSize;

  // Section 1: .text
  buf.write(".text\0\0\0", secOffset, "ascii");
  buf.writeUInt32LE(0x1000, secOffset + 8); // VirtualSize
  buf.writeUInt32LE(0x1000, secOffset + 12); // VirtualAddress
  buf.writeUInt32LE(128, secOffset + 16); // SizeOfRawData
  const textRawOffset = 1200;
  buf.writeUInt32LE(textRawOffset, secOffset + 20); // PointerToRawData
  buf.writeUInt32LE(0x60000020, secOffset + 36); // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ

  // Put some machine code bytes in .text
  for (let i = 0; i < 128; i += 1) buf[textRawOffset + i] = 0x90; // NOPs

  // Section 2: .data
  const sec2Offset = secOffset + 40;
  buf.write(".data\0\0\0", sec2Offset, "ascii");
  buf.writeUInt32LE(0x1000, sec2Offset + 8);
  buf.writeUInt32LE(0x2000, sec2Offset + 12);
  buf.writeUInt32LE(64, sec2Offset + 16);
  buf.writeUInt32LE(1400, sec2Offset + 20);
  buf.writeUInt32LE(0xc0000040, sec2Offset + 36); // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

  return buf;
};

describe("PeFormatInspector", () => {
  it("rejects non-MZ files", () => {
    const invalid = Buffer.from("NOT_A_PE_FILE");
    expect(inspectPeFormat(invalid)).toBeNull();
  });

  it("parses PE headers, machine architecture, and subsystems", () => {
    const peBuf = createMockPeBinary();
    const report = inspectPeFormat(peBuf);
    expect(report).not.toBeNull();
    expect(report?.machine).toBe("AMD64 (64-bit x86-64)");
    expect(report?.is64Bit).toBe(true);
    expect(report?.numberOfSections).toBe(2);
    expect(report?.subsystem).toBe("WINDOWS_CUI (Console)");
    expect(report?.entryPointRva).toBe(0x1000);
    expect(report?.imageBase).toBe(0x140000000n);
  });

  it("decodes DllCharacteristics security mitigations", () => {
    const peBuf = createMockPeBinary();
    const report = inspectPeFormat(peBuf);
    expect(report?.dllCharacteristics).toContain("DYNAMIC_BASE (ASLR)");
    expect(report?.dllCharacteristics).toContain("NX_COMPAT (DEP)");
    expect(report?.dllCharacteristics).toContain("HIGH_ENTROPY_VA");
  });

  it("calculates section characteristics and Shannon entropy", () => {
    const peBuf = createMockPeBinary();
    const report = inspectPeFormat(peBuf);
    expect(report?.sections.length).toBe(2);

    const textSec = report?.sections[0];
    expect(textSec?.name).toBe(".text");
    expect(textSec?.isExecutable).toBe(true);
    expect(textSec?.isWritable).toBe(false);
    expect(textSec?.entropy).toBe(0); // 128 NOP bytes has 0 entropy!
    expect(textSec?.isPackedOrEncrypted).toBe(false);

    const dataSec = report?.sections[1];
    expect(dataSec?.name).toBe(".data");
    expect(dataSec?.isWritable).toBe(true);
  });

  it("extracts Authenticode digital certificate metadata", () => {
    const peBuf = createMockPeBinary();
    const report = inspectPeFormat(peBuf);
    expect(report?.authenticode).toBeDefined();
    expect(report?.authenticode?.fileOffset).toBe(1024);
    expect(report?.authenticode?.size).toBe(64);
    expect(report?.authenticode?.revision).toBe(0x0200);
    expect(report?.authenticode?.certificateType).toBe(0x0002);
  });

  it("parses Microsoft Rich Header and resolves VS compiler telemetry", () => {
    const peBuf = createMockPeBinary();
    const rich = parsePeRichHeader(peBuf);
    expect(rich).not.toBeNull();
    expect(rich?.records.length).toBe(1);

    const record = rich?.records[0];
    expect(record?.prodId).toBe(0x0103);
    expect(record?.vsVersion).toBe("VS 2019");
    expect(record?.toolName).toBe("Utc1920_C");
    expect(record?.count).toBe(5);
  });

  it("rejects short or invalid optional headers", () => {
    // 88 bytes with SizeOfOptionalHeader = 0
    const shortBuf = Buffer.alloc(88);
    shortBuf[0] = 0x4d; // MZ
    shortBuf[1] = 0x5a;
    shortBuf.writeUInt32LE(64, 0x3c); // e_lfanew = 64
    shortBuf.write("PE\0\0", 64, "ascii");
    // SizeOfOptionalHeader is 0
    expect(inspectPeFormat(shortBuf)).toBeNull();

    // Invalid magic
    const invalidMagicBuf = createMockPeBinary();
    const optOffset = 128 + 4 + 20; // 152 (peOffset is 128 in createMockPeBinary)
    invalidMagicBuf.writeUInt16LE(0x9999, optOffset);
    expect(inspectPeFormat(invalidMagicBuf)).toBeNull();
  });
});
