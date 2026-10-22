import { JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS } from "../../domain/javascript/javascriptDeobfuscation.js";

export const JS_REDOX_RELEASE = {
  version: "0.1.1",
  revision: "42ca30ade268b8c9abf9277feffa3cd23f533518",
  repository: "https://github.com/codeandsolder/js-redox",
} as const;

export const JS_REDOX_PROVIDER_IDENTITY = {
  id: "js-redox",
  name: "js-redox deobfuscate-safe",
  version: JS_REDOX_RELEASE.version,
} as const;

export const JS_REDOX_LIMITS = {
  inputBytes: JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.sourceBytes,
  outputBytes: JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.outputBytes,
  reportBytes: JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.reportBytes,
  executableBytes: 128 * 1024 * 1024,
  diagnosticBytes: JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS.diagnosticBytes,
  addressSpaceBytes: 1024 * 1024 * 1024,
  cpuSeconds: 120,
  timeoutMs: 120000,
} as const;

export const JS_REDOX_LIMITATIONS = [
  "Only proof-gated static rewrites are applied. Regions whose proof preconditions do not hold remain unchanged.",
  "The target JavaScript is never executed. The runtime-semantics-preserved-by-design claim applies to the unformatted safe-deobfuscation output contract, not arbitrary later formatting or edits.",
  "Recovered readability does not establish original source text, identifier names, source maps, runtime inputs or complete deobfuscation.",
  "Initial adapter verification is Linux x64. The owned worker receives a single-thread hint and configured per-process ceilings of at most 1 GiB virtual address space and 120 CPU seconds, each clamped so inherited soft or hard limits are never raised, plus a 120-second shared launch deadline, 64 MiB input/output bounds and 8 MiB diagnostic/report stream bounds. This adapter does not impose an aggregate process-count or cgroup memory limit.",
] as const;
