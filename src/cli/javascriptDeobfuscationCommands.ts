import { z } from "incur";
import type { Logger } from "pino";

import { JavaScriptDeobfuscationService } from "../application/javascript/JavaScriptDeobfuscationService.js";
import { evidenceSchema } from "../domain/evidence.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { createJavaScriptDeobfuscationProvider } from "../composition/javascriptDeobfuscation.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

export const registerJavaScriptDeobfuscationCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  service: Pick<
    JavaScriptDeobfuscationService,
    "deobfuscate" | "close"
  > = new JavaScriptDeobfuscationService(
    createJavaScriptDeobfuscationProvider(environment),
  ),
): void => {
  cli.command(CLI_COMMANDS.deobfuscateJavaScriptSource, {
    description:
      "Proof-gated static JavaScript deobfuscation with exact provenance",
    args: z.object({
      path: z
        .string()
        .describe("Absolute UTF-8 JavaScript input; never executed"),
      outputDirectory: z.string().describe("Absolute absent output directory"),
    }),
    options: z.object({
      maxIterations: z
        .number()
        .int()
        .min(1)
        .max(64)
        .optional()
        .describe("Maximum proof-gated optimization iterations (1–64)"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.deobfuscateJavaScriptSource, () =>
          finishAnalysisCommand(
            () =>
              service.deobfuscate(
                {
                  path: args.path,
                  output_directory: args.outputDirectory,
                  ...(options.maxIterations === undefined
                    ? {}
                    : { max_iterations: options.maxIterations }),
                },
                { signal },
              ),
            service,
            "js-redox",
            "deobfuscate_javascript_source",
            signal,
            undefined,
            (partial) => {
              const parsed = evidenceSchema.safeParse(partial);
              return parsed.success ? parsed.data : undefined;
            },
          ),
        ),
      ),
  });
};
