import { describe, expect, it } from "vitest";

import {
  boundProofEvidence,
  build,
  originalCases,
  processEvidence,
  proofEvidence,
  readyProcessLedgerRequest,
  request,
  reviewedObligation,
} from "./ReconstructionObligationLedger.fixture.js";
import { deriveReconstructionObligationCandidates } from "./ReconstructionObligationCandidates.js";
import { evaluateReconstructionObligationLedger } from "./ReconstructionObligationLedgerEvaluation.js";

const buildWithSiblingControl = (
  status: "fail" | "unknown" | "unsupported" | "skipped",
  observed: "pass" | "missing",
) => {
  const input = readyProcessLedgerRequest();
  const binding = input.manifest.bindings[0];
  if (binding?.verifier === null || binding === undefined)
    throw new Error("Expected verifier binding");
  const defect = "The candidate drops the worker completion event.";
  const fixtureId = "packaged.worker-defect";
  const passingEvidence =
    observed === "pass"
      ? boundProofEvidence(
          `sibling-${status}`,
          {
            obligation_ids: [binding.obligation_id],
            fixture_ids: [fixtureId],
            case_kinds: [],
            verifier_ids: [binding.verifier.verifier_id],
            claim_ids: [binding.verifier.claim_id],
          },
          "controlled-replay",
          {
            control: {
              verifier_sha256: binding.verifier.implementation_sha256 ?? "",
              defect,
            },
          },
        )
      : null;
  const sibling = {
    candidate: { kind: "fixture" as const, fixture_id: fixtureId },
    defect,
    status,
    result_evidence_id: passingEvidence?.evidence_id ?? `ev_${"a".repeat(64)}`,
  };
  return build({
    ...input,
    evidence_bundle: request([
      ...input.evidence_bundle.records,
      ...(passingEvidence === null ? [] : [passingEvidence]),
    ]).evidence_bundle,
    manifest: {
      ...input.manifest,
      bindings: [
        {
          ...binding,
          verifier: {
            ...binding.verifier,
            negative_controls: [
              ...(binding.verifier.negative_controls ?? []),
              sibling,
            ],
          },
        },
      ],
    },
  });
};

describe("reconstruction obligation ledger", () => {
  it("emits the complete deterministic ledger and closure identity", () => {
    const evidence = proofEvidence("review");
    const reviewed = [
      reviewedObligation("obl.review.one", evidence.evidence_id),
      reviewedObligation("obl.review.two", evidence.evidence_id),
    ];
    const first = build(
      request([evidence], { reviewed_obligations: reviewed }),
    );
    const second = build(
      request([evidence], { reviewed_obligations: reviewed }),
    );
    expect(first.obligations).toHaveLength(2);
    expect(first).toEqual(second);
    expect(first.obligations[0]?.source_state).toBe("reviewed");
    expect(first.status).toBe("open");
  });

  it("merges repeated captures of one process scenario into one definition", () => {
    const first = processEvidence();
    const second = processEvidence({
      residual_unknowns: [{ scope: "network", reason: "Second run only." }],
    });
    expect(second.evidence_id).not.toBe(first.evidence_id);
    const single = build(request([first]));
    const repeated = build(request([first, second]));

    const obligation = repeated.obligations[0];
    expect(repeated.obligations).toHaveLength(1);
    expect(obligation?.obligation_id).toBe(
      single.obligations[0]?.obligation_id,
    );
    expect(obligation?.diagnostics.map(({ code }) => code)).not.toContain(
      "duplicate-definition",
    );
    expect(
      obligation?.authority_references.map(({ evidence_id: id }) => id).sort(),
    ).toEqual([first.evidence_id, second.evidence_id].sort());
    // The second capture's own uncertainty stays visible after the merge.
    expect(obligation?.unavailable_authority).toContain(
      "network: Second run only.",
    );
  });

  it("still reports a reviewed definition that reuses a generated ID", () => {
    const capture = processEvidence();
    const generated = build(request([capture])).obligations[0];
    if (generated === undefined) throw new Error("Expected process obligation");
    const ledger = build(
      request([capture], {
        reviewed_obligations: [
          reviewedObligation(generated.obligation_id, capture.evidence_id),
        ],
      }),
    );

    expect(
      ledger.obligations[0]?.diagnostics.map(({ code }) => code),
    ).toContain("duplicate-definition");
  });

  it("does not let green unit evidence close a packaged-process obligation", () => {
    const capture = processEvidence();
    const proof = proofEvidence("green-unit");
    const initial = build(request([capture, proof]));
    const obligation = initial.obligations[0];
    if (obligation === undefined)
      throw new Error("Expected process obligation");
    const unitBinding = {
      obligation_id: obligation.obligation_id,
      owner: {
        module_path: "src/processOwner.ts",
        symbol: "runProcess",
        owner_sha256: "1".repeat(64),
      },
      parser_type: null,
      original_cases: originalCases(obligation, capture.evidence_id),
      fixtures: obligation.required_case_kinds.map((caseKind) => ({
        fixture_id: `fixture.${caseKind}`,
        case_kind: caseKind,
        authority: "unit" as const,
        evidence_ids: [proof.evidence_id],
      })),
      verifier: {
        verifier_id: "verifier.unit",
        claim_id: "claim.process",
        command: "npm test -- processOwner",
        authority: "unit" as const,
        status: "pass" as const,
        result_evidence_id: proof.evidence_id,
        enumerated_obligation_ids: [obligation.obligation_id],
        nondeterminism: {
          mode: "total-order" as const,
          specification: "Exact unit-call order.",
        },
      },
    };

    const result = build(
      request([capture, proof], {
        manifest: {
          bindings: [unitBinding],
          contradictions: [],
        },
      }),
    );
    const evaluated = result.obligations[0];
    expect(evaluated?.status).toBe("implemented");
    expect(evaluated?.diagnostics.map(({ code }) => code)).toEqual(
      expect.arrayContaining([
        "weak-fixture-authority",
        "weak-verifier-authority",
      ]),
    );
    expect(result.status).toBe("open");
  });
});

describe("reconstruction obligation ledger Evidence provenance", () => {
  it("links observed-case Evidence separately from authority references", () => {
    const capture = processEvidence();
    const caseEvidence = proofEvidence("distinct-original-case");
    const bundle = request([capture, caseEvidence]).evidence_bundle;
    const generated = deriveReconstructionObligationCandidates(bundle, []);
    const candidates = generated.candidates.map((candidate) => ({
      ...candidate,
      observed_cases: candidate.observed_cases.map((observedCase) => ({
        ...observedCase,
        evidence_id: caseEvidence.evidence_id,
      })),
    }));

    const result = evaluateReconstructionObligationLedger({
      candidates,
      bundle,
      manifest: { bindings: [], contradictions: [] },
      generationLimitations: [],
    });

    expect(result.obligations[0]?.authority_references[0]?.evidence_id).toBe(
      capture.evidence_id,
    );
    expect(result.evidence_links).toContain(caseEvidence.evidence_id);
  });
});

describe("reconstruction obligation ledger case closure", () => {
  it("keeps unobserved original cases open", () => {
    const capture = processEvidence();
    const proof = proofEvidence("packaged-original-gap");
    const initial = build(request([capture, proof]));
    const obligation = initial.obligations[0];
    if (obligation === undefined)
      throw new Error("Expected process obligation");
    const result = build(
      request([capture, proof], {
        manifest: {
          bindings: [
            {
              obligation_id: obligation.obligation_id,
              owner: {
                module_path: "src/processOwner.ts",
                symbol: "runProcess",
                owner_sha256: "4".repeat(64),
              },
              parser_type: null,
              original_cases: obligation.observed_cases,
              fixtures: obligation.required_case_kinds.map((caseKind) => ({
                fixture_id: `packaged.${caseKind}`,
                case_kind: caseKind,
                authority: "packaged-process",
                evidence_ids: [proof.evidence_id],
              })),
              verifier: {
                verifier_id: "verifier.packaged",
                claim_id: "claim.process",
                command: "npm run verify:package -- process",
                authority: "packaged-process",
                status: "pass",
                result_evidence_id: proof.evidence_id,
                enumerated_obligation_ids: [obligation.obligation_id],
                nondeterminism: {
                  mode: "partial-order",
                  specification:
                    "Startup precedes teardown; worker completion is unordered.",
                },
              },
            },
          ],
          contradictions: [],
        },
      }),
    );

    expect(result.obligations[0]?.status).toBe("implemented");
    expect(result.obligations[0]?.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "missing-original-case",
          detail: expect.stringContaining("negative"),
        }),
        expect.objectContaining({
          code: "missing-original-case",
          detail: expect.stringContaining("cancellation"),
        }),
      ]),
    );
    expect(result.status).toBe("open");
  });

  it("closes only when every required case and verifier has comparable authority", () => {
    const ledgerRequest = readyProcessLedgerRequest();
    const result = build(ledgerRequest);

    expect(result.obligations[0]).toMatchObject({
      status: "verified",
      diagnostics: [],
    });
    expect(result.status).toBe("ready");
    expect(result.summary.required_open).toBe(0);

    const generated = deriveReconstructionObligationCandidates(
      ledgerRequest.evidence_bundle,
      ledgerRequest.reviewed_obligations,
    );
    const limited = evaluateReconstructionObligationLedger({
      candidates: generated.candidates,
      bundle: ledgerRequest.evidence_bundle,
      manifest: ledgerRequest.manifest,
      generationLimitations: ["A supplementary source was unavailable."],
    });
    expect(limited.obligations[0]?.status).toBe("verified");
    expect(limited.status).toBe("unknown");
    expect(limited.coverage.status).toBe("partial");
  });
});

describe("reconstruction obligation verifier compatibility", () => {
  it("keeps legacy manifests parseable while marking their verifier unchallenged", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const { negative_controls: _controls, ...legacyVerifier } =
      binding.verifier;
    const result = build({
      ...input,
      manifest: {
        ...input.manifest,
        bindings: [{ ...binding, verifier: legacyVerifier }],
      },
    });
    expect(result.obligations[0]?.status).toBe("implemented");
    expect(
      result.obligations[0]?.diagnostics.map(({ code }) => code),
    ).toContain("unchallenged-verifier");
    expect(result.status).toBe("open");
  });

  it("does not close when one of several negative controls passes", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const control = boundProofEvidence(
      "vacuous",
      {
        obligation_ids: [binding.obligation_id],
        fixture_ids: ["packaged.deliberate-defect"],
        case_kinds: [],
        verifier_ids: [binding.verifier.verifier_id],
        claim_ids: [binding.verifier.claim_id],
      },
      "controlled-replay",
      {
        control: {
          verifier_sha256: binding.verifier.implementation_sha256 ?? "",
          defect: "The candidate omits the shutdown result.",
        },
      },
    );
    const result = build({
      ...input,
      evidence_bundle: request([...input.evidence_bundle.records, control])
        .evidence_bundle,
      manifest: {
        ...input.manifest,
        bindings: [
          {
            ...binding,
            verifier: {
              ...binding.verifier,
              negative_controls: [
                ...(binding.verifier.negative_controls ?? []),
                {
                  candidate: {
                    kind: "fixture",
                    fixture_id: "packaged.deliberate-defect",
                  },
                  defect: "The candidate omits the shutdown result.",
                  status: "pass",
                  result_evidence_id: control.evidence_id,
                },
              ],
            },
          },
        ],
      },
    });
    expect(result.obligations[0]?.status).toBe("implemented");
    expect(result.obligations[0]?.diagnostics.map(({ code }) => code)).toEqual(
      expect.arrayContaining(["vacuous-verifier"]),
    );
    expect(
      result.obligations[0]?.diagnostics.map(({ code }) => code),
    ).not.toContain("unchallenged-verifier");
    expect(result.status).toBe("open");
  });
});

describe("reconstruction obligation mixed verifier controls", () => {
  it("reports a passing sibling as vacuous even when its status is nonterminal", () => {
    for (const status of ["unknown", "unsupported", "skipped"] as const) {
      const result = buildWithSiblingControl(status, "pass");
      expect(result.obligations[0]?.status).toBe("implemented");
      expect(result.status).toBe("open");
      expect(
        result.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toContain("vacuous-verifier");
    }
  });

  it("keeps closure open for nonterminal siblings with missing Evidence", () => {
    for (const status of ["unknown", "unsupported", "skipped"] as const) {
      const result = buildWithSiblingControl(status, "missing");
      expect(result.obligations[0]?.status).toBe("implemented");
      expect(result.status).toBe("open");
      expect(
        result.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toContain("missing-control-result");
    }
  });

  it("reports a passing sibling as vacuous when the manifest claims fail", () => {
    const result = buildWithSiblingControl("fail", "pass");
    expect(result.obligations[0]?.status).toBe("implemented");
    expect(result.status).toBe("open");
    expect(
      result.obligations[0]?.diagnostics.map(({ code }) => code),
    ).toContain("vacuous-verifier");
  });
});

describe("reconstruction obligation control Evidence", () => {
  it("reports a vacuous verifier when a claimed failure has passing Evidence", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const falseClaim = boundProofEvidence(
      "false-negative-control",
      {
        obligation_ids: [binding.obligation_id],
        fixture_ids: ["packaged.deliberate-defect"],
        case_kinds: [],
        verifier_ids: [binding.verifier.verifier_id],
        claim_ids: [binding.verifier.claim_id],
      },
      "controlled-replay",
      {
        control: {
          verifier_sha256: binding.verifier.implementation_sha256 ?? "",
          defect: "The candidate omits the shutdown result.",
        },
      },
    );
    const controls = binding.verifier.negative_controls ?? [];
    const claimed = controls[0];
    if (claimed === undefined) throw new Error("Expected negative control");
    const result = build({
      ...input,
      evidence_bundle: request([...input.evidence_bundle.records, falseClaim])
        .evidence_bundle,
      manifest: {
        ...input.manifest,
        bindings: [
          {
            ...binding,
            verifier: {
              ...binding.verifier,
              negative_controls: [
                { ...claimed, result_evidence_id: falseClaim.evidence_id },
              ],
            },
          },
        ],
      },
    });
    expect(result.obligations[0]?.status).toBe("implemented");
    expect(result.obligations[0]?.diagnostics.map(({ code }) => code)).toEqual(
      expect.arrayContaining(["vacuous-verifier", "unchallenged-verifier"]),
    );
  });

  it("does not count a positive fixture or absent Evidence as a negative control", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const control = binding.verifier.negative_controls?.[0];
    if (control === undefined) throw new Error("Expected negative control");
    const cases = [
      {
        control: {
          ...control,
          candidate: {
            kind: "fixture" as const,
            fixture_id: "packaged.positive",
          },
        },
        diagnostic: "invalid-control-candidate",
      },
      {
        control: {
          ...control,
          result_evidence_id: `ev_${"a".repeat(64)}`,
        },
        diagnostic: "missing-control-result",
      },
    ];
    for (const item of cases) {
      const result = build({
        ...input,
        manifest: {
          ...input.manifest,
          bindings: [
            {
              ...binding,
              verifier: {
                ...binding.verifier,
                negative_controls: [item.control],
              },
            },
          ],
        },
      });
      expect(result.obligations[0]?.status).toBe("implemented");
      expect(
        result.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toEqual(
        expect.arrayContaining([item.diagnostic, "unchallenged-verifier"]),
      );
    }
  });
});

describe("reconstruction obligation control Evidence identity", () => {
  it("does not accept a failing result from a different verifier, claim, or obligation", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const control = binding.verifier.negative_controls?.[0];
    if (control === undefined) throw new Error("Expected negative control");
    const cases = [
      { name: "digest", digest: "7".repeat(64) },
      { name: "verifier", verifierId: "another.verifier" },
      { name: "claim", claimId: "another.claim" },
      { name: "obligation", obligationId: "another.obligation" },
    ];
    for (const item of cases) {
      const resultEvidence = boundProofEvidence(
        `mismatched-${item.name}`,
        {
          obligation_ids: [item.obligationId ?? binding.obligation_id],
          fixture_ids: ["packaged.deliberate-defect"],
          case_kinds: [],
          verifier_ids: [item.verifierId ?? binding.verifier.verifier_id],
          claim_ids: [item.claimId ?? binding.verifier.claim_id],
        },
        "controlled-replay",
        {
          passed: false,
          control: {
            verifier_sha256:
              item.digest ?? binding.verifier.implementation_sha256 ?? "",
            defect: control.defect,
            failure_kind: "behavior-mismatch",
          },
        },
      );
      const rejected = build({
        ...input,
        evidence_bundle: request([
          ...input.evidence_bundle.records,
          resultEvidence,
        ]).evidence_bundle,
        manifest: {
          ...input.manifest,
          bindings: [
            {
              ...binding,
              verifier: {
                ...binding.verifier,
                negative_controls: [
                  {
                    ...control,
                    result_evidence_id: resultEvidence.evidence_id,
                  },
                ],
              },
            },
          ],
        },
      });
      expect(rejected.obligations[0]?.status).toBe("implemented");
      expect(
        rejected.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toEqual(
        expect.arrayContaining([
          "weak-control-evidence",
          "unchallenged-verifier",
        ]),
      );
    }
  });

  it("does not count nonterminal controls or controls without an implementation digest", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const control = binding.verifier.negative_controls?.[0];
    if (control === undefined) throw new Error("Expected negative control");
    for (const status of ["unknown", "unsupported", "skipped"] as const) {
      const result = build({
        ...input,
        manifest: {
          ...input.manifest,
          bindings: [
            {
              ...binding,
              verifier: {
                ...binding.verifier,
                negative_controls: [{ ...control, status }],
              },
            },
          ],
        },
      });
      expect(result.obligations[0]?.status).toBe("implemented");
      expect(
        result.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toContain("unchallenged-verifier");
    }
    const { implementation_sha256: _digest, ...withoutDigest } =
      binding.verifier;
    const missingDigest = build({
      ...input,
      manifest: {
        ...input.manifest,
        bindings: [{ ...binding, verifier: withoutDigest }],
      },
    });
    expect(missingDigest.obligations[0]?.status).toBe("implemented");
    expect(
      missingDigest.obligations[0]?.diagnostics.map(({ code }) => code),
    ).toContain("unchallenged-verifier");
  });
});

describe("reconstruction obligation control identities", () => {
  it("accepts an authenticated failing artifact control", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const candidateSha256 = "4".repeat(64);
    const defect = "The candidate omits the shutdown result.";
    const evidence = boundProofEvidence(
      "artifact-control",
      {
        obligation_ids: [binding.obligation_id],
        fixture_ids: [],
        case_kinds: [],
        verifier_ids: [binding.verifier.verifier_id],
        claim_ids: [binding.verifier.claim_id],
      },
      "controlled-replay",
      {
        passed: false,
        control: {
          verifier_sha256: binding.verifier.implementation_sha256 ?? "",
          candidate_sha256: candidateSha256,
          defect,
          failure_kind: "behavior-mismatch",
        },
      },
    );
    const result = build({
      ...input,
      evidence_bundle: request([...input.evidence_bundle.records, evidence])
        .evidence_bundle,
      manifest: {
        ...input.manifest,
        bindings: [
          {
            ...binding,
            verifier: {
              ...binding.verifier,
              negative_controls: [
                {
                  candidate: { kind: "artifact", sha256: candidateSha256 },
                  defect,
                  status: "fail",
                  result_evidence_id: evidence.evidence_id,
                },
              ],
            },
          },
        ],
      },
    });
    expect(result.obligations[0]?.status).toBe("verified");
    expect(result.evidence_links).toContain(evidence.evidence_id);
    for (const [sha256, diagnostic] of [
      [binding.owner.owner_sha256, "invalid-control-candidate"],
      ["6".repeat(64), "invalid-control-candidate"],
      ["5".repeat(64), "weak-control-evidence"],
    ] as const) {
      const rejected = build({
        ...input,
        evidence_bundle: request([...input.evidence_bundle.records, evidence])
          .evidence_bundle,
        manifest: {
          ...input.manifest,
          bindings: [
            {
              ...binding,
              verifier: {
                ...binding.verifier,
                negative_controls: [
                  {
                    candidate: { kind: "artifact", sha256 },
                    defect,
                    status: "fail",
                    result_evidence_id: evidence.evidence_id,
                  },
                ],
              },
            },
          ],
        },
      });
      expect(rejected.obligations[0]?.status).toBe("implemented");
      expect(
        rejected.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toContain(diagnostic);
    }
  });
});

describe("reconstruction obligation control result boundaries", () => {
  it("requires a valid positive candidate digest for artifact controls", () => {
    for (const positiveSha256 of [null, "not-a-sha256"]) {
      const input = readyProcessLedgerRequest(positiveSha256);
      const binding = input.manifest.bindings[0];
      if (binding?.verifier === null || binding === undefined)
        throw new Error("Expected verifier binding");
      const candidateSha256 = "4".repeat(64);
      const defect = "The candidate omits the shutdown result.";
      const evidence = boundProofEvidence(
        "uncomparable-artifact-control",
        {
          obligation_ids: [binding.obligation_id],
          fixture_ids: [],
          case_kinds: [],
          verifier_ids: [binding.verifier.verifier_id],
          claim_ids: [binding.verifier.claim_id],
        },
        "controlled-replay",
        {
          passed: false,
          control: {
            verifier_sha256: binding.verifier.implementation_sha256 ?? "",
            candidate_sha256: candidateSha256,
            defect,
            failure_kind: "behavior-mismatch",
          },
        },
      );
      const rejected = build({
        ...input,
        evidence_bundle: request([...input.evidence_bundle.records, evidence])
          .evidence_bundle,
        manifest: {
          ...input.manifest,
          bindings: [
            {
              ...binding,
              verifier: {
                ...binding.verifier,
                negative_controls: [
                  {
                    candidate: { kind: "artifact", sha256: candidateSha256 },
                    defect,
                    status: "fail",
                    result_evidence_id: evidence.evidence_id,
                  },
                ],
              },
            },
          ],
        },
      });
      expect(rejected.obligations[0]?.status).toBe("implemented");
      expect(
        rejected.obligations[0]?.diagnostics.map(({ code }) => code),
      ).toEqual(
        expect.arrayContaining([
          "invalid-control-candidate",
          "unchallenged-verifier",
        ]),
      );
    }
  });

  it("does not treat an execution failure as a detected defect", () => {
    const input = readyProcessLedgerRequest();
    const binding = input.manifest.bindings[0];
    if (binding?.verifier === null || binding === undefined)
      throw new Error("Expected verifier binding");
    const control = binding.verifier.negative_controls?.[0];
    if (control === undefined) throw new Error("Expected negative control");
    const executionFailure = boundProofEvidence(
      "control-execution-failure",
      {
        obligation_ids: [binding.obligation_id],
        fixture_ids: ["packaged.deliberate-defect"],
        case_kinds: [],
        verifier_ids: [binding.verifier.verifier_id],
        claim_ids: [binding.verifier.claim_id],
      },
      "controlled-replay",
      {
        passed: false,
        control: {
          verifier_sha256: binding.verifier.implementation_sha256 ?? "",
          defect: control.defect,
          failure_kind: "execution-failure",
        },
      },
    );
    const result = build({
      ...input,
      evidence_bundle: request([
        ...input.evidence_bundle.records,
        executionFailure,
      ]).evidence_bundle,
      manifest: {
        ...input.manifest,
        bindings: [
          {
            ...binding,
            verifier: {
              ...binding.verifier,
              negative_controls: [
                {
                  ...control,
                  result_evidence_id: executionFailure.evidence_id,
                },
              ],
            },
          },
        ],
      },
    });
    expect(result.obligations[0]?.status).toBe("implemented");
    expect(result.obligations[0]?.diagnostics.map(({ code }) => code)).toEqual(
      expect.arrayContaining([
        "weak-control-evidence",
        "unchallenged-verifier",
      ]),
    );
  });
});

describe("reconstruction obligation manifest references", () => {
  it("withholds readiness when a manifest entry names absent Evidence", () => {
    const ledgerRequest = readyProcessLedgerRequest();
    // A valid entry for the same case kind must not hide an absent reference.
    const absent = `ev_${"a".repeat(64)}`;
    const binding = ledgerRequest.manifest.bindings[0];
    if (binding === undefined) throw new Error("Expected binding");
    const variants: {
      readonly code: string;
      readonly binding: typeof binding;
    }[] = [
      {
        code: "missing-original-case",
        binding: {
          ...binding,
          original_cases: [
            ...binding.original_cases,
            { kind: "positive", evidence_id: absent, location: "/old" },
          ],
        },
      },
      {
        code: "missing-case",
        binding: {
          ...binding,
          fixtures: [
            ...binding.fixtures,
            {
              fixture_id: "packaged.old",
              case_kind: "positive",
              authority: "packaged-process",
              evidence_ids: [absent],
            },
          ],
        },
      },
    ];
    for (const { code, binding: dangling } of variants) {
      const open = build({
        ...ledgerRequest,
        manifest: { ...ledgerRequest.manifest, bindings: [dangling] },
      });
      expect(open.status).not.toBe("ready");
      expect(open.obligations[0]?.status).toBe("implemented");
      expect(open.obligations[0]?.diagnostics).toEqual([
        { code, detail: expect.stringContaining(absent) },
      ]);
    }
  });
});
