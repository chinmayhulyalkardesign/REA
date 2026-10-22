import type { Evidence } from "./evidence.js";
import type { ReconstructionObligation } from "./reconstructionObligationLedgerSchemas.js";
import {
  evidenceAuthoritySupportsProof,
  proofAuthoritySatisfies,
} from "./reconstructionObligationAuthority.js";
import { evaluateVerifierControls } from "./reconstructionObligationVerifierControls.js";

type Diagnostic = ReconstructionObligation["diagnostics"][number];

/** Assess verifier proof once for ledger construction and readiness consumption. */
export const reconstructionObligationVerifierDiagnostics = (
  obligation: Pick<
    ReconstructionObligation,
    "obligation_id" | "target" | "required_verifier_authority"
  >,
  binding: ReconstructionObligation["binding"],
  evidence: ReadonlyMap<string, Evidence>,
): Diagnostic[] => {
  const diagnostics: Diagnostic[] = [];
  const verifier = binding?.verifier;
  if (binding == null || verifier == null)
    return [
      {
        code: "missing-verifier",
        detail: "No verifier claim is bound to this obligation.",
      },
    ];
  if (!verifier.enumerated_obligation_ids.includes(obligation.obligation_id))
    diagnostics.push({
      code: "verifier-does-not-enumerate",
      detail: "The verifier claim does not enumerate this obligation ID.",
    });
  const resultEvidence = evidence.get(verifier.result_evidence_id);
  if (resultEvidence === undefined)
    diagnostics.push({
      code: "missing-verifier-result",
      detail: "The latest verifier result Evidence is absent from the bundle.",
    });
  if (
    !proofAuthoritySatisfies(
      verifier.authority,
      obligation.required_verifier_authority,
    ) ||
    (resultEvidence !== undefined &&
      !evidenceAuthoritySupportsProof(resultEvidence, verifier.authority, {
        obligationId: obligation.obligation_id,
        verifierId: verifier.verifier_id,
        claimId: verifier.claim_id,
        ...(verifier.implementation_sha256 === undefined
          ? {}
          : { verifierSha256: verifier.implementation_sha256 }),
      }))
  )
    diagnostics.push({
      code: "weak-verifier-authority",
      detail: `Verifier authority does not satisfy ${obligation.required_verifier_authority}.`,
    });
  if (verifier.status !== "pass")
    diagnostics.push({
      code: "verifier-failed",
      detail: `Latest verifier status is ${verifier.status}.`,
    });
  evaluateVerifierControls({
    candidate: obligation,
    binding,
    verifier,
    positiveEvidence: resultEvidence,
    evidence,
    diagnostics,
  });
  return diagnostics;
};
