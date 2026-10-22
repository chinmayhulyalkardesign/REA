import { expect, it } from "vitest";

import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";

import {
  parseJsRedoxReport,
  validateJsRedoxReport,
} from "./JsRedoxProtocol.js";

it("rejects proof reports containing malformed UTF-8", () => {
  const report = {
    schema: "js-safe-deobfuscate/v1",
    source_mode: "auto",
    input: "/tmp/source.js",
    input_sha256: "a".repeat(64),
    output_sha256: "b".repeat(64),
    changed: true,
    iterations: 1,
    transforms: {},
    arithmetic_state_proofs: [],
    analysis_source_sha256: "b".repeat(64),
    static_alias_installer_calls: [],
    safe_static_only: true,
    presentation_formatted: false,
    runtime_semantics_preserved_by_design: true,
    note: "x",
  };
  const bytes = Buffer.from(JSON.stringify(report), "utf8");
  const marker = Buffer.from('"note":"x"', "utf8");
  const markerOffset = bytes.indexOf(marker);
  if (markerOffset < 0) throw new Error("fixture marker missing");
  bytes[markerOffset + marker.length - 2] = 0xff;
  expect(() => parseJsRedoxReport(bytes)).toThrowError(
    expect.objectContaining({ _tag: "AnalysisOutputError" }),
  );
});

it.each([
  { safe_static_only: false },
  { presentation_formatted: true },
  { runtime_semantics_preserved_by_design: false },
  { input_sha256: "0".repeat(64) },
  { analysis_source_sha256: "0".repeat(64) },
  { iterations: 2 },
  { changed: false },
  { source_mode: "module" },
])("rejects an invalid proof gate %j", (override) => {
  const report = {
    schema: "js-safe-deobfuscate/v1",
    source_mode: "auto",
    input: "/tmp/source.js",
    input_sha256: "a".repeat(64),
    output_sha256: "b".repeat(64),
    analysis_source_sha256: "b".repeat(64),
    changed: true,
    iterations: 1,
    transforms: {},
    arithmetic_state_proofs: [],
    static_alias_installer_calls: [],
    safe_static_only: true,
    presentation_formatted: false,
    runtime_semantics_preserved_by_design: true,
    ...override,
  };
  expect(() =>
    validateJsRedoxReport(
      parseJsRedoxReport(Buffer.from(JSON.stringify(report))),
      {
        inputSha256: "a".repeat(64),
        outputSha256: "b".repeat(64),
        changed: true,
        maxIterations: 1,
        sourceMode: "auto",
      },
    ),
  ).toThrowError(expect.objectContaining({ _tag: "AnalysisOutputError" }));
});

it("bounds incompatible proof-report diagnostics before public projection", () => {
  const transforms = Object.fromEntries(
    Array.from({ length: 4_000 }, (_, index) => [`bad_${index}`, -1]),
  );
  const report = {
    schema: "js-safe-deobfuscate/v1",
    source_mode: "auto",
    input: "/tmp/source.js",
    input_sha256: "a".repeat(64),
    output_sha256: "b".repeat(64),
    analysis_source_sha256: "b".repeat(64),
    changed: true,
    iterations: 1,
    transforms,
    arithmetic_state_proofs: [],
    static_alias_installer_calls: [],
    safe_static_only: true,
    presentation_formatted: false,
    runtime_semantics_preserved_by_design: true,
  };
  let failure: unknown;
  try {
    parseJsRedoxReport(Buffer.from(JSON.stringify(report)));
  } catch (cause: unknown) {
    failure = cause;
  }
  expect(failure).toBeInstanceOf(AnalysisOutputError);
  if (!(failure instanceof AnalysisOutputError))
    throw new Error("expected bounded proof output error");
  expect(Buffer.byteLength(failure.reason, "utf8")).toBeLessThanOrEqual(4_096);
  expect(failure.reason).toContain("more issue(s)");
  expect(
    Buffer.byteLength(JSON.stringify(projectAnalysisError(failure)), "utf8"),
  ).toBeLessThan(10_000);
  expect(failure.cause).toBeInstanceOf(Error);
});
