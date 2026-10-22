import { expect, it } from "vitest";

import { readCompressed } from "./ManagedMemberInspectorCore.js";
import { ManagedReaderFailure } from "./ManagedReaderFailure.js";

it.each([
  ["00", 0],
  ["7f", 0x7f],
  ["8080", 0x80],
  ["bfff", 0x3fff],
  ["c0004000", 0x4000],
  ["dfffffff", 0x1fff_ffff],
] as const)(
  "reads compressed integer %s without consuming adjacent bytes",
  (hex, value) => {
    const encoded = Buffer.from(hex, "hex");
    const bytes = Buffer.concat([
      Buffer.from([0xff]),
      encoded,
      Buffer.from([0xff]),
    ]);
    expect(readCompressed(bytes, 1)).toEqual({
      value,
      next: 1 + encoded.length,
    });
  },
);

it.each([
  ["", "truncated compressed integer"],
  ["80", "truncated compressed integer"],
  ["c00000", "truncated compressed integer"],
  ["e0", "reserved compressed integer"],
] as const)(
  "keeps the signature offset and typed failure for %s",
  (hex, detail) => {
    const bytes = Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from(hex, "hex"),
    ]);
    let failure: unknown;
    try {
      readCompressed(bytes, 2);
    } catch (cause) {
      failure = cause;
    }
    expect(failure).toBeInstanceOf(ManagedReaderFailure);
    expect(failure).toMatchObject({
      issue: { code: "invalid-blob", scope: "signature", offset: 2, detail },
    });
  },
);
