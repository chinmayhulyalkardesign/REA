/**
 * Pure TypeScript Java Class (.class) byte format analyzer.
 * Parses constant pool, access flags, interfaces, fields, methods, and attributes.
 */

export interface JvmMember {
  readonly name: string;
  readonly descriptor: string;
  readonly accessFlags: readonly string[];
  readonly codeLength?: number | undefined;
}

export interface JvmClassReport {
  readonly majorVersion: number;
  readonly minorVersion: number;
  readonly javaVersion: string;
  readonly thisClass: string;
  readonly superClass: string | null;
  readonly accessFlags: readonly string[];
  readonly interfaces: readonly string[];
  readonly fields: readonly JvmMember[];
  readonly methods: readonly JvmMember[];
  readonly sourceFile?: string | undefined;
}

const JAVA_VERSIONS: Readonly<Record<number, string>> = {
  45: "Java 1.1",
  46: "Java 1.2",
  47: "Java 1.3",
  48: "Java 1.4",
  49: "Java 5",
  50: "Java 6",
  51: "Java 7",
  52: "Java 8",
  53: "Java 9",
  54: "Java 10",
  55: "Java 11",
  56: "Java 12",
  57: "Java 13",
  58: "Java 14",
  59: "Java 15",
  60: "Java 16",
  61: "Java 17 (LTS)",
  62: "Java 18",
  63: "Java 19",
  64: "Java 20",
  65: "Java 21 (LTS)",
  66: "Java 22",
  67: "Java 23",
};

export const resolveJavaRelease = (majorVersion: number): string => {
  return JAVA_VERSIONS[majorVersion] ?? `Java (class format ${majorVersion})`;
};

export const decodeModifiedUtf8 = (bytes: Uint8Array): string => {
  let result = "";
  let i = 0;
  const len = bytes.length;
  while (i < len) {
    const b1 = bytes[i++]!;
    if ((b1 & 0x80) === 0) {
      result += String.fromCharCode(b1);
    } else if ((b1 & 0xe0) === 0xc0) {
      if (i >= len) throw new Error("Truncated modified UTF-8 sequence");
      const b2 = bytes[i++]!;
      const code = ((b1 & 0x1f) << 6) | (b2 & 0x3f);
      result += String.fromCharCode(code);
    } else if ((b1 & 0xf0) === 0xe0) {
      if (i + 1 >= len) throw new Error("Truncated modified UTF-8 sequence");
      const b2 = bytes[i++]!;
      const b3 = bytes[i++]!;
      const code = ((b1 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      result += String.fromCharCode(code);
    } else if ((b1 & 0xf8) === 0xf0) {
      if (i + 2 >= len) throw new Error("Truncated UTF-8 sequence");
      const b2 = bytes[i++]!;
      const b3 = bytes[i++]!;
      const b4 = bytes[i++]!;
      const cp =
        ((b1 & 0x07) << 18) |
        ((b2 & 0x3f) << 12) |
        ((b3 & 0x3f) << 6) |
        (b4 & 0x3f);
      result += String.fromCodePoint(cp);
    } else {
      throw new Error(`Invalid modified UTF-8 byte: 0x${b1.toString(16)}`);
    }
  }
  return result;
};

export const decodeAccessFlags = (
  flags: number,
  kind: "class" | "field" | "method",
): string[] => {
  const result: string[] = [];
  if ((flags & 0x0001) !== 0) result.push("public");
  if ((flags & 0x0002) !== 0) result.push("private");
  if ((flags & 0x0004) !== 0) result.push("protected");
  if ((flags & 0x0008) !== 0) result.push("static");
  if ((flags & 0x0010) !== 0) result.push("final");
  if (kind === "class" && (flags & 0x0020) !== 0) result.push("super");
  if (kind === "method" && (flags & 0x0020) !== 0) result.push("synchronized");
  if (kind === "field" && (flags & 0x0040) !== 0) result.push("volatile");
  if (kind === "method" && (flags & 0x0040) !== 0) result.push("bridge");
  if (kind === "field" && (flags & 0x0080) !== 0) result.push("transient");
  if (kind === "method" && (flags & 0x0080) !== 0) result.push("varargs");
  if (kind === "method" && (flags & 0x0100) !== 0) result.push("native");
  if (kind === "class" && (flags & 0x0200) !== 0) result.push("interface");
  if ((flags & 0x0400) !== 0) result.push("abstract");
  if (kind === "method" && (flags & 0x0800) !== 0) result.push("strictfp");
  if ((flags & 0x1000) !== 0) result.push("synthetic");
  if (kind === "class" && (flags & 0x2000) !== 0) result.push("annotation");
  if ((flags & 0x4000) !== 0) result.push("enum");
  return result;
};

class ClassByteCursor {
  private offset = 0;
  private readonly view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  has(n: number): boolean {
    return this.offset + n <= this.bytes.byteLength;
  }

  u1(): number {
    if (!this.has(1)) throw new Error("Unexpected EOF");
    return this.bytes[this.offset++]!;
  }

  u2(): number {
    if (!this.has(2)) throw new Error("Unexpected EOF");
    const val = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return val;
  }

  u4(): number {
    if (!this.has(4)) throw new Error("Unexpected EOF");
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  bytesSlice(len: number): Uint8Array {
    if (!this.has(len)) throw new Error("Unexpected EOF");
    const slice = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  skip(len: number): void {
    if (!this.has(len)) throw new Error("Unexpected EOF");
    this.offset += len;
  }
}

interface ConstantPoolMap {
  utf8(index: number): string;
  className(index: number): string;
}

const parseConstantPool = (
  cursor: ClassByteCursor,
  count: number,
): ConstantPoolMap => {
  const pool = new Map<number, unknown>();

  for (let i = 1; i < count; i += 1) {
    const tag = cursor.u1();
    if (tag === 1) {
      // UTF-8
      const len = cursor.u2();
      const raw = cursor.bytesSlice(len);
      pool.set(i, decodeModifiedUtf8(raw));
    } else if (tag === 3 || tag === 4) {
      // Integer, Float
      cursor.skip(4);
    } else if (tag === 5 || tag === 6) {
      // Long, Double
      cursor.skip(8);
      i += 1; // Long and double take two pool entries
    } else if (tag === 7) {
      // Class
      const nameIndex = cursor.u2();
      pool.set(i, { type: "class", nameIndex });
    } else if (tag === 8) {
      // String
      cursor.skip(2);
    } else if (tag === 9 || tag === 10 || tag === 11 || tag === 12) {
      // Fieldref, Methodref, InterfaceMethodref, NameAndType
      cursor.skip(4);
    } else if (tag === 15) {
      // MethodHandle
      cursor.skip(3);
    } else if (tag === 16 || tag === 19 || tag === 20) {
      // MethodType, Module, Package
      cursor.skip(2);
    } else if (tag === 17 || tag === 18) {
      // Dynamic, InvokeDynamic
      cursor.skip(4);
    } else {
      throw new Error(`Unsupported constant-pool tag: ${tag}`);
    }
  }

  return {
    utf8: (idx: number) => {
      const val = pool.get(idx);
      return typeof val === "string" ? val : "";
    },
    className: (idx: number) => {
      const val = pool.get(idx);
      if (val && typeof val === "object" && "nameIndex" in val) {
        const nameIdx = Number((val as { nameIndex: number }).nameIndex);
        const name = pool.get(nameIdx);
        return typeof name === "string" ? name : "";
      }
      return "";
    },
  };
};

const parseMembers = (
  cursor: ClassByteCursor,
  pool: ConstantPoolMap,
  kind: "field" | "method",
): JvmMember[] => {
  const count = cursor.u2();
  const members: JvmMember[] = [];

  for (let i = 0; i < count; i += 1) {
    const accessFlags = decodeAccessFlags(cursor.u2(), kind);
    const name = pool.utf8(cursor.u2());
    const descriptor = pool.utf8(cursor.u2());
    const attrCount = cursor.u2();

    let codeLength: number | undefined;
    for (let a = 0; a < attrCount; a += 1) {
      const attrName = pool.utf8(cursor.u2());
      const attrLen = cursor.u4();
      if (attrName === "Code" && attrLen >= 8) {
        // max_stack (u2) + max_locals (u2) + code_length (u4)
        cursor.skip(4);
        codeLength = cursor.u4();
        cursor.skip(attrLen - 8);
      } else {
        cursor.skip(attrLen);
      }
    }

    members.push({ name, descriptor, accessFlags, codeLength });
  }

  return members;
};

/** Parse Java .class bytes into structured class metadata. */
export const parseJvmClass = (bytes: Uint8Array): JvmClassReport | null => {
  if (bytes.length < 24) return null;

  try {
    const cursor = new ClassByteCursor(bytes);
    const magic = cursor.u4();
    if (magic !== 0xcafebabe) return null;

    const minorVersion = cursor.u2();
    const majorVersion = cursor.u2();
    const cpCount = cursor.u2();

    const pool = parseConstantPool(cursor, cpCount);

    const accessFlags = decodeAccessFlags(cursor.u2(), "class");
    const thisClass = pool.className(cursor.u2());
    const superIdx = cursor.u2();
    const superClass = superIdx > 0 ? pool.className(superIdx) : null;

    const ifaceCount = cursor.u2();
    const interfaces: string[] = [];
    for (let i = 0; i < ifaceCount; i += 1) {
      interfaces.push(pool.className(cursor.u2()));
    }

    const fields = parseMembers(cursor, pool, "field");
    const methods = parseMembers(cursor, pool, "method");

    // Attributes
    const attrCount = cursor.u2();
    let sourceFile: string | undefined;
    for (let i = 0; i < attrCount; i += 1) {
      const attrName = pool.utf8(cursor.u2());
      const attrLen = cursor.u4();
      if (attrName === "SourceFile" && attrLen === 2) {
        sourceFile = pool.utf8(cursor.u2());
      } else {
        cursor.skip(attrLen);
      }
    }

    return {
      majorVersion,
      minorVersion,
      javaVersion: resolveJavaRelease(majorVersion),
      thisClass,
      superClass,
      accessFlags,
      interfaces,
      fields,
      methods,
      sourceFile,
    };
  } catch {
    return null;
  }
};
