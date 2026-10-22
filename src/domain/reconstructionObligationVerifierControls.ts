import type { Evidence } from "./evidence.js";
import { digestSchema } from "./digests.js";
import type { ReconstructionObligation } from "./reconstructionObligationLedgerSchemas.js";
import { evidenceAuthoritySupportsProof } from "./reconstructionObligationAuthority.js";

type Binding = NonNullable<ReconstructionObligation["binding"]>;
type Verifier = NonNullable<Binding["verifier"]>;
type Control = NonNullable<Verifier["negative_controls"]>[number];
type Diagnostic = ReconstructionObligation["diagnostics"][number];

const addDiagnostic = (
  diagnostics: Diagnostic[],
  code: Diagnostic["code"],
  detail: string,
): void => {
  diagnostics.push({ code, detail });
};

interface ControlContext {
  readonly candidate: Pick<
    ReconstructionObligation,
    "obligation_id" | "target"
  >;
  readonly binding: Binding;
  readonly verifier: Verifier;
  readonly positiveEvidence: Evidence | undefined;
  readonly evidence: ReadonlyMap<string, Evidence>;
  readonly diagnostics: Diagnostic[];
}

/** A failed control counts only when its result authenticates the declared defect. */
export const evaluateVerifierControls = (context: ControlContext): void => {
  const { verifier, diagnostics } = context;
  const controls = verifier.negative_controls ?? [];
  if (controls.length === 0) {
    addDiagnostic(
      diagnostics,
      "unchallenged-verifier",
      "No failing negative control demonstrates that this verifier can reject a deliberately wrong candidate.",
    );
    return;
  }
  if (verifier.implementation_sha256 === undefined) {
    addDiagnostic(
      diagnostics,
      "unchallenged-verifier",
      "Negative controls require the verifier implementation digest in the binding and its Evidence.",
    );
    return;
  }
  const outcomes = controls.map((control) => evaluateControl(context, control));
  if (!outcomes.includes("failed"))
    addDiagnostic(
      diagnostics,
      "unchallenged-verifier",
      "No authenticated failing negative control demonstrates that this verifier can reject a deliberately wrong candidate.",
    );
};

const evaluateControl = (
  context: ControlContext,
  control: Control,
): "failed" | "unverified" => {
  const { candidate, verifier, evidence, diagnostics } = context;
  const candidateIssue = controlCandidateIssue(context, control);
  if (candidateIssue !== null) {
    addDiagnostic(diagnostics, "invalid-control-candidate", candidateIssue);
    return "unverified";
  }
  const result = evidence.get(control.result_evidence_id);
  if (result === undefined) {
    addDiagnostic(
      diagnostics,
      "missing-control-result",
      `Negative control result Evidence is absent: ${control.result_evidence_id}.`,
    );
    return "unverified";
  }
  const expected = {
    obligationId: candidate.obligation_id,
    verifierId: verifier.verifier_id,
    claimId: verifier.claim_id,
    verifierSha256: verifier.implementation_sha256 ?? "",
    defect: control.defect,
    ...(control.candidate.kind === "fixture"
      ? { fixtureId: control.candidate.fixture_id }
      : { candidateSha256: control.candidate.sha256 }),
  };
  if (
    evidenceAuthoritySupportsProof(result, verifier.authority, {
      ...expected,
      passed: true,
    })
  ) {
    addDiagnostic(
      diagnostics,
      "vacuous-verifier",
      `Verifier also passes the deliberately wrong ${control.candidate.kind} candidate.`,
    );
    return "unverified";
  }
  if (
    control.status !== "fail" ||
    !evidenceAuthoritySupportsProof(result, verifier.authority, {
      ...expected,
      passed: false,
      failureKind: "behavior-mismatch",
    })
  ) {
    addDiagnostic(
      diagnostics,
      "weak-control-evidence",
      `Negative control ${control.candidate.kind} result lacks comparable authenticated ${verifier.authority} Evidence for its declared outcome.`,
    );
    return "unverified";
  }
  return "failed";
};

const controlCandidateIssue = (
  context: ControlContext,
  control: Control,
): string | null => {
  const { candidate, binding, positiveEvidence } = context;
  const positiveResult = positiveEvidence?.normalized_result;
  const positiveProof =
    typeof positiveResult === "object" &&
    positiveResult !== null &&
    !Array.isArray(positiveResult)
      ? positiveResult
      : undefined;
  if (control.candidate.kind === "fixture") {
    const fixtureId = control.candidate.fixture_id;
    return binding.fixtures.some(({ fixture_id: id }) => id === fixtureId) ||
      (Array.isArray(positiveProof?.fixture_ids) &&
        positiveProof.fixture_ids.includes(fixtureId))
      ? "A negative control must identify a different fixture from the passing reconstruction."
      : null;
  }
  const parsedPositiveCandidate = digestSchema.safeParse(
    positiveProof?.candidate_sha256,
  );
  if (!parsedPositiveCandidate.success)
    return "An artifact control requires a valid positive candidate SHA-256 in verifier result Evidence.";
  return control.candidate.sha256 === binding.owner.owner_sha256 ||
    control.candidate.sha256 === candidate.target.artifact_sha256 ||
    control.candidate.sha256 === parsedPositiveCandidate.data
    ? "A negative control must identify a different artifact from the passing reconstruction or original artifact."
    : null;
};
