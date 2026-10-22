import { describe, expect, it } from "vitest";

import {
  auditEvidenceBundle,
  evidenceAuditFindingSchema,
  evidenceAuditResultSchema,
} from "./evidenceAudit.js";
import { createEvidence } from "./evidence.js";
import type { JsonValue } from "./jsonValue.js";
import { createEvidenceBundle } from "./evidenceBundle.js";
import {
  createResidualUnknown,
  recordUnknownInputSchema,
} from "./residualUnknown.js";

const PROVIDER = { id: "fixture", name: "Fixture", version: "1" } as const;
const record = (result: JsonValue) =>
  createEvidence(undefined, PROVIDER, {
    operation: "observe",
    parameters: {},
    result,
    confidence: "observed",
    authority: "shipped-artifact",
  });

const unknown = (question: string) =>
  createResidualUnknown(
    recordUnknownInputSchema.parse({
      question,
      severity: "low",
      domain: "audit",
      supporting_evidence_ids: [],
      contradicting_evidence_ids: [],
      required_authority: "shipped-artifact",
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [],
      relationships: [],
    }),
    "ev_" + "0".repeat(64),
    null,
  );

describe("evidence bundle audit", () => {
  it("reports no findings for a clean bundle", () => {
    const bundle = createEvidenceBundle([
      record({ observed: { address: "0x1000", name: "main" } }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(evidenceAuditResultSchema.parse(result)).toMatchObject({
      findings: [],
      failures: 0,
      warnings: 0,
      scanned_records: 1,
      scanned_unknowns: 0,
    });
  });

  it("flags leaked bearer tokens as failures without printing them", () => {
    const token = "Bearer abc123def456ghi789";
    const bundle = createEvidenceBundle([record({ header: token })]);
    const result = auditEvidenceBundle(bundle);
    expect(result.failures).toBe(1);
    const finding = result.findings[0]!;
    expect(finding.rule_id).toBe("credential-bearer-token");
    expect(finding.pointer).toBe("/normalized_result/header");
    expect(finding.matched_length).toBeGreaterThan(0);
    expect(finding.matched_hash_prefix).toMatch(/^[0-9a-f]{8}$/);
    // The matched value itself must never appear in the report.
    expect(JSON.stringify(result)).not.toContain("abc123def456ghi789");
  });

  it("flags leaked GitHub tokens and AWS access key IDs", () => {
    const bundle = createEvidenceBundle([
      record({
        github: "ghp_" + "a".repeat(36),
        aws: "AKIA" + "B".repeat(16),
      }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.failures).toBe(2);
    expect(result.findings.map((finding) => finding.rule_id).sort()).toEqual([
      "credential-aws-access-key-id",
      "credential-github-token",
    ]);
  });

  it("flags home directory paths and artifact paths as warnings", () => {
    const bundle = createEvidenceBundle([
      record({ note: "cached at /Users/alice/Downloads/prog.exe" }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.failures).toBe(0);
    expect(result.warnings).toBe(1);
    expect(result.findings[0]!.rule_id).toBe("local-path-posix-home");
    expect(JSON.stringify(result)).not.toContain("alice");
  });

  it("flags environment host identifiers as warnings", () => {
    const host = createEvidence(
      {
        path: "/tmp/prog.elf",
        sha256: "a".repeat(64),
        format: "elf",
        architecture: "x86_64",
      },
      PROVIDER,
      {
        operation: "observe",
        parameters: {},
        result: { ok: true },
        confidence: "observed",
        authority: "shipped-artifact",
        environment: {
          id: "alink-macbook",
          platform: "darwin",
          architecture: "arm64",
          isolation: "none",
        },
      },
    );
    const bundle = createEvidenceBundle([host]);
    const result = auditEvidenceBundle(bundle);
    expect(result.warnings).toBeGreaterThanOrEqual(1);
    const hostFinding = result.findings.find(
      (finding) => finding.rule_id === "environment-host-id",
    );
    expect(hostFinding?.pointer).toBe("/environment/id");
  });

  it("audits residual unknown questions for credentials", () => {
    const bundle = createEvidenceBundle(
      [record({ ok: true })],
      [unknown("why does the client send Bearer abc123def456ghi789xyz")],
    );
    const result = auditEvidenceBundle(bundle);
    expect(result.scanned_unknowns).toBe(1);
    expect(result.failures).toBe(1);
    expect(result.findings[0]!.rule_id).toBe("credential-bearer-token");
    expect(JSON.stringify(result)).not.toContain("abc123def456ghi789xyz");
  });

  it("sorts findings deterministically and validates the finding shape", () => {
    const bundle = createEvidenceBundle([
      record({ a: "/Users/zoe/tmp/x", b: "AKIA" + "C".repeat(16) }),
      record({ c: "/home/bob/data" }),
    ]);
    const result = auditEvidenceBundle(bundle);
    for (const finding of result.findings) {
      expect(() => evidenceAuditFindingSchema.parse(finding)).not.toThrow();
    }
    const keys = result.findings.map(
      ({ evidence_id, pointer }) => `${evidence_id}:${pointer}`,
    );
    expect([...keys].sort()).toEqual(keys);
  });

  it("reports its limitations on every result", () => {
    const result = auditEvidenceBundle(createEvidenceBundle([]));
    expect(result.limitations.length).toBeGreaterThan(0);
    expect(JSON.stringify(result.limitations)).toContain("safe to publish");
  });
});

describe("evidence bundle audit leak rules", () => {
  it("does not flag header names that were already redacted", () => {
    const bundle = createEvidenceBundle([
      record({
        headers: [{ name: "Authorization", value: null, redacted: true }],
      }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.findings).toEqual([]);
    expect(result.failures).toBe(0);
  });

  it("still flags a header whose value was not redacted", () => {
    const bundle = createEvidenceBundle([
      record({
        headers: [{ name: "Authorization", value: "secret-token-value" }],
      }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.failures).toBe(1);
    expect(result.findings[0]!.rule_id).toBe("credential-header-value");
    expect(result.findings[0]!.pointer).toBe(
      "/normalized_result/headers/0/value",
    );
  });

  it("audits subject paths and caller parameters, not just results", () => {
    const withSubject = createEvidence(
      {
        path: "/Users/zhangsan/Downloads/prog.elf",
        sha256: "a".repeat(64),
        format: "elf",
        architecture: "x86_64",
      },
      PROVIDER,
      {
        operation: "observe",
        parameters: { token: "ghp_" + "a".repeat(36) },
        result: { ok: true },
        confidence: "observed",
        authority: "shipped-artifact",
      },
    );
    const result = auditEvidenceBundle(createEvidenceBundle([withSubject]));
    const pointers = result.findings.map((finding) => finding.pointer);
    expect(pointers).toContain("/subject/local_path");
    expect(pointers).toContain("/parameters/token");
    expect(
      result.findings.some(
        (finding) => finding.rule_id === "credential-github-token",
      ),
    ).toBe(true);
  });

  it("treats decompiler operations as decompiled surfaces", () => {
    const decompiled = createEvidence(undefined, PROVIDER, {
      operation: "procedure_pseudo_code",
      parameters: { address: "0x1000" },
      result: { code: "int main(void) { return 0; }" },
      confidence: "observed",
      authority: "shipped-artifact",
    });
    const result = auditEvidenceBundle(createEvidenceBundle([decompiled]));
    const pointers = result.findings
      .filter((finding) => finding.rule_id === "decompiled-payload")
      .map((finding) => finding.pointer);
    expect(pointers).toEqual(["/normalized_result/code"]);
  });

  it("matches non-ASCII home directory names", () => {
    const bundle = createEvidenceBundle([
      record({ note: "dumped to /Users/张三/Desktop/out.bin" }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.findings[0]!.rule_id).toBe("local-path-posix-home");
    expect(JSON.stringify(result)).not.toContain("张三");
  });

  it("redacts a credential used as an object key instead of printing it", () => {
    const secretKey = "ghp_" + "b".repeat(36);
    const bundle = createEvidenceBundle([
      record({ [secretKey]: "dumped to /Users/alice/Desktop/out.bin" }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(JSON.stringify(result)).not.toContain(secretKey);
    expect(result.findings[0]!.pointer).toMatch(
      /^\/normalized_result\/<redacted-[0-9a-f]{8}>$/,
    );
  });

  it("flags Stripe, Slack, and PEM private key material", () => {
    const bundle = createEvidenceBundle([
      record({
        stripe: "sk_live_" + "a".repeat(24),
        slack: "xoxb-" + "1234567890".repeat(2),
        pem: "-----BEGIN RSA PRIVATE KEY-----",
      }),
    ]);
    const result = auditEvidenceBundle(bundle);
    expect(result.findings.map((finding) => finding.rule_id).sort()).toEqual([
      "credential-private-key",
      "credential-slack-token",
      "credential-stripe-live-key",
    ]);
  });
});
