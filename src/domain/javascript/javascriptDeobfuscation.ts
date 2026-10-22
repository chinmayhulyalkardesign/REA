import { z } from "zod";
import { digestSchema } from "../digests.js";
import { analyzeJavaScriptApplicationInputSchema } from "./javascriptApplicationAnalysis.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Service-owned ceilings for every published deobfuscation artifact role. */
export const JAVASCRIPT_DEOBFUSCATION_ARTIFACT_LIMITS = {
  sourceBytes: 64 * 1024 * 1024,
  outputBytes: 64 * 1024 * 1024,
  reportBytes: 8 * 1024 * 1024,
  manifestBytes: 1024 * 1024,
  diagnosticBytes: 8 * 1024 * 1024,
} as const;

export const javascriptDeobfuscationInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to one UTF-8 JavaScript file; never executed",
  ),
  output_directory: absoluteLocalPathStringSchema.describe(
    "Absolute absent output directory; parent must exist",
  ),
  max_iterations: z.number().int().min(1).max(64).default(16),
});

const fileSchema = z.strictObject({
  path: z.string().min(1),
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
});

const diagnosticFileSchema = fileSchema.extend({
  observed_bytes: z.number().int().nonnegative(),
});

const commandDiagnosticsSchema = z
  .strictObject({
    exit_code: z.number().int().nullable(),
    exit_signal: z.string().nullable(),
    truncated: z.boolean(),
    stdout: diagnosticFileSchema,
    stderr: diagnosticFileSchema,
  })
  .superRefine((diagnostics, context) => {
    if (diagnostics.exit_code !== 0 || diagnostics.exit_signal !== null)
      context.addIssue({
        code: "custom",
        path: ["exit_code"],
        message:
          "Successful deobfuscation diagnostics must describe an exit-zero unsignalled command",
      });
    for (const stream of ["stdout", "stderr"] as const) {
      const file = diagnostics[stream];
      if (file.observed_bytes < file.bytes)
        context.addIssue({
          code: "custom",
          path: [stream, "observed_bytes"],
          message:
            "Observed diagnostic bytes cannot be smaller than retained bytes",
        });
      if (!diagnostics.truncated && file.observed_bytes !== file.bytes)
        context.addIssue({
          code: "custom",
          path: [stream, "observed_bytes"],
          message:
            "Untruncated diagnostic streams must retain every observed byte",
        });
    }
  });

export const javascriptDeobfuscationDiagnosticsSchema = z.strictObject({
  version: commandDiagnosticsSchema,
  execution: commandDiagnosticsSchema,
});

export const javascriptDeobfuscationResultSchema = z.strictObject({
  source: fileSchema.extend({
    published_copy: fileSchema,
  }),
  options: z.strictObject({
    max_iterations:
      javascriptDeobfuscationInputSchema.shape.max_iterations.removeDefault(),
  }),
  status: z.enum(["changed", "unchanged"]),
  output: fileSchema,
  report: fileSchema,
  manifest: fileSchema,
  diagnostics: javascriptDeobfuscationDiagnosticsSchema.optional(),
  /** Generic binding between the selected source and the published output. */
  proof: z.strictObject({
    input_sha256: digestSchema,
    output_sha256: digestSchema,
  }),
  analysis_input: z.strictObject({
    input_path: analyzeJavaScriptApplicationInputSchema.shape.input_path,
    format: z.literal("directory"),
  }),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});

export type JavaScriptDeobfuscationInput = z.output<
  typeof javascriptDeobfuscationInputSchema
>;
export type JavaScriptDeobfuscationResult = z.output<
  typeof javascriptDeobfuscationResultSchema
>;
