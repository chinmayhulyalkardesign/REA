import { expect } from "vitest";

import { createJavaScriptRuntimeObservationEvidence } from "../../../src/application/javascript/JavaScriptRuntimeObservationEvidence.js";
import { JAVASCRIPT_RUNTIME_RECONCILIATION_EXAMPLE } from "../../../src/contracts/javascript/javascriptRuntimeReconciliationExample.js";
import { javascriptRuntimeObservationSchema } from "../../../src/domain/javascript/javascriptRuntimeObservation.js";
import { V8_INSPECTOR_PROVIDER_IDENTITY } from "../../../src/inspector/providerIdentity.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { mcpTest } from "../../support/mcp/mcpFixture.js";

const observation = javascriptRuntimeObservationSchema.parse({
  runtime: {
    product: "node.js",
    protocol_version: "1.3",
    v8_version: null,
  },
  target: {
    target_id: "example-v8-target",
    protocol_type: "node",
    attached: false,
    location: { kind: "file", file_path: "/fixtures/main.js" },
    runtime_kind: "electron-main",
    runtime_kind_authority: "caller-declared-unverified",
  },
  capture: {
    observation_ms: 100,
    events_observed: 0,
    events_retained: 0,
    events_dropped: 0,
    metadata_bytes_retained: 0,
    truncated: false,
    truncation_reasons: [],
  },
  scripts: {
    items: [],
    observed_total: 0,
    excluded: { unsupported_location: 0, invalid_protocol_value: 0 },
  },
  execution_contexts: [],
  directly_observed: [],
  unavailable_without_instrumentation: [],
  unknowns: [],
  limitations: [],
});

mcpTest.for([
  {
    label: "role-only mismatch",
    targetId: "example-v8-target",
    runtimeKind: "node",
    issueField: "runtime_kind",
  },
  {
    label: "target-only mismatch",
    targetId: "wrong-target",
    runtimeKind: "electron-main",
    issueField: "target_id",
  },
  {
    label: "both mismatched",
    targetId: "wrong-target",
    runtimeKind: "node",
    issueField: "target_id",
  },
  {
    label: "matching target and role",
    targetId: "example-v8-target",
    runtimeKind: "electron-main",
    issueField: null,
  },
  {
    label: "omitted declared role",
    targetId: "example-v8-target",
    runtimeKind: undefined,
    issueField: null,
  },
] as const)(
  "attributes V8 reconciliation parameters: $label",
  async (scenario, { mcp }) => {
    let providerLaunches = 0;
    const session = createTestBinarySession(() => {
      providerLaunches++;
      throw new Error("Reconciliation must not acquire a provider");
    });
    try {
      const client = await mcp.connect(
        createServer({ kind: "session", session }),
      );
      const evidence = createJavaScriptRuntimeObservationEvidence(
        "observe_javascript_runtime",
        {
          inspector_endpoint: "http://127.0.0.1:9229",
          target_id: scenario.targetId,
          ...(scenario.runtimeKind === undefined
            ? {}
            : { runtime_kind: scenario.runtimeKind }),
          observation_ms: 100,
        },
        observation,
        V8_INSPECTOR_PROVIDER_IDENTITY,
      );
      const response = await client.callTool({
        name: "reconcile_javascript_runtime",
        arguments: {
          static_layers:
            JAVASCRIPT_RUNTIME_RECONCILIATION_EXAMPLE.static_layers,
          runtime_observations: [evidence],
        },
      });
      if (scenario.issueField === null) {
        expect(response.isError).not.toBe(true);
        expect(response.structuredContent).toMatchObject({
          operation: "reconcile_javascript_runtime",
        });
      } else {
        expect(parseMcpToolError(response)).toMatchObject({
          error: {
            code: "invalid_request",
            category: "invalid_input",
            retryable: false,
            recovery: {
              kind: "inspect_input_contract",
              operation: "reconcile_javascript_runtime",
            },
            details: {
              issues: [
                {
                  path: [
                    "runtime_observations",
                    0,
                    "parameters",
                    scenario.issueField,
                  ],
                  reason: "invalid_value",
                },
              ],
            },
          },
        });
      }
      await client.ping();
      expect(providerLaunches).toBe(0);
    } finally {
      await session.close();
    }
  },
);
