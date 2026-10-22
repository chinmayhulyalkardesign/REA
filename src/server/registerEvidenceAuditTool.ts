import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import { readImmutableEvidenceBundle } from "../application/EvidenceBundleFiles.js";
import { toolContract } from "../contracts/toolContracts.js";
import {
  auditEvidenceBundle,
  evidenceAuditResultSchema,
} from "../domain/evidenceAudit.js";
import { ok } from "../domain/result.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { withAdmittedAnalysis } from "./analysisAdmission.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";

/** Register the read-only Evidence bundle audit. */
export const registerEvidenceAuditTool = (
  server: EvidenceMcpServer,
  session: BinarySessionPort,
  contract: ReturnType<typeof toolContract<"audit_evidence_bundle">>,
  resources: ArtifactResourceScope,
): void => {
  const admission = withAdmittedAnalysis({ kind: "session", session });
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        admission,
        contract.name,
        context.mcpReq.signal,
        async () => {
          const loaded = await readImmutableEvidenceBundle(
            input.path,
            context.mcpReq.signal,
            resources,
          );
          if (!loaded.ok)
            return server.delivery.toCallToolResult(loaded, contract);
          // The audit is a pure projection over the caller's file: no session
          // evidence is recorded, so findings never leak into later analysis.
          const audited = evidenceAuditResultSchema.parse(
            auditEvidenceBundle(loaded.value),
          );
          return server.delivery.toCallToolResult(ok(audited), contract);
        },
      ),
  );
};
