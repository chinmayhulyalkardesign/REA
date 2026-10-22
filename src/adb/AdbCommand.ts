import {
  AnalysisCancelledError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type {
  AnalysisCapturedOutput,
  AnalysisError,
} from "../domain/analysisErrorBase.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  execFileBytes,
  ExecFileOutputCancelledError,
  execFileOutputFailure,
  type ExecFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { packageChangeFailureReason } from "./AdbShellOutput.js";
import { isSuccessfulDaemonStartNotice } from "./AdbDeviceOutput.js";

const STDERR_EXCERPT_CHARACTERS = 512;

// Match the known host operand in adb's local-file diagnostics. The suffix is
// part of the format: opening/reading identify local failures explicitly.
const LOCAL_FILE_DIAGNOSTICS = [
  ["cannot create", ":"],
  ["cannot create file/directory", ":"],
  ["cannot stat", ":"],
  ["cannot open", ":"],
  ["cannot write", ":"],
  ["failed to stat local file", ":"],
  ["failed to read all of", ":"],
  ["failed to access", ":"],
  ["failed to stat", ":"],
  ["failed to open", ":"],
  ["opening", " locally failed:"],
  ["reading", " locally failed:"],
] as const;

/** Match an operand as a quoted value or a delimited token. */
const diagnosticNamesOperand = (
  diagnostic: string,
  operand: string,
): boolean => {
  if (operand === "") return false;
  if (
    diagnostic.includes(`'${operand}'`) ||
    diagnostic.includes(`"${operand}"`)
  )
    return true;
  for (
    let index = diagnostic.indexOf(operand);
    index !== -1;
    index = diagnostic.indexOf(operand, index + operand.length)
  ) {
    const before = diagnostic[index - 1];
    const after = diagnostic[index + operand.length];
    // A shorter path must not match the prefix of an unrelated longer path.
    if (
      (before === undefined || /[\s'"(]/u.test(before)) &&
      (after === undefined || /[\s'":,;)]/u.test(after))
    )
      return true;
  }
  return false;
};

/** Project parsed command-owner facts without reinterpreting the rejection. */
export const adbCommandCapturedOutput = (
  failure: ExecFileOutputFailure,
): AnalysisCapturedOutput => ({
  stdout: failure.stdout,
  stderr: failure.stderr,
  ...(failure.stdoutBytes === undefined
    ? {}
    : { stdout_bytes: failure.stdoutBytes }),
  ...(failure.stderrBytes === undefined
    ? {}
    : { stderr_bytes: failure.stderrBytes }),
  exit_code: typeof failure.code === "number" ? failure.code : null,
  signal: failure.signal,
  truncated: failure.outputTruncated,
});

/** Parsed command failure owned by this adapter, separate from its public tag. */
class AdbProtocolError extends AnalysisProtocolError {
  constructor(
    message: string,
    readonly commandFailure: ExecFileOutputFailure,
    cause: unknown,
  ) {
    super(message, { cause });
  }
}

/** adb joins shell operands into a remote POSIX command; quote at that boundary. */
const quoteShellOperand = (value: string): string =>
  /^[A-Za-z0-9_./:=@+,-]+$/u.test(value)
    ? value
    : "'" + value.replaceAll("'", "'\\''") + "'";

export const adbArguments = (
  serial: string | undefined,
  arguments_: readonly string[],
): readonly string[] => {
  const operands =
    arguments_[0] === "shell"
      ? ["shell", ...arguments_.slice(1).map(quoteShellOperand)]
      : [...arguments_];
  return serial === undefined ? operands : ["-s", serial, ...operands];
};

export interface AdbRunLimits {
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  /**
   * Live device observations can shrink between calls. Mutation commands omit
   * this so a truncated result stays non-retryable.
   */
  readonly volatileOutput?: boolean;
}

/** Keep the selected device separate from the file addressed by the command. */
export interface AdbCommandTarget {
  readonly device: string;
  /** Caller-addressed file, such as a remote path or the original APK input. */
  readonly path?: string;
  /** Exact host operand adb consumes, including an owned input snapshot. */
  readonly localPath?: string;
}

/** Run one bounded adb invocation and keep its exact failure shape. */
export const runAdbCapture = async (
  operation: string,
  target: AdbCommandTarget,
  binary: string,
  arguments_: readonly string[],
  limits: AdbRunLimits,
  signal: AbortSignal | undefined,
): Promise<Result<{ stdout: Buffer; stderr: Buffer }, AnalysisError>> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    return ok(
      await execFileBytes(binary, arguments_, {
        timeout: limits.timeoutMs,
        maxBuffer: limits.maxOutputBytes,
        stopSignal: "SIGTERM",
        ...(signal === undefined ? {} : { signal }),
      }),
    );
  } catch (cause) {
    const failure = execFileOutputFailure(cause);
    if (cause instanceof ExecFileOutputCancelledError)
      return err(
        new AnalysisCancelledError(operation, {
          cause: cause.cause,
          ...(failure === undefined
            ? {}
            : { capturedOutput: adbCommandCapturedOutput(failure) }),
        }),
      );
    if (failure === undefined)
      return err(
        new AnalysisProtocolError(`adb failed for ${operation}`, { cause }),
      );
    if (failure.outputTruncated) {
      const name = `The adb output capture allowance of ${String(limits.maxOutputBytes)} bytes (this release has no runtime override)`;
      const allowance =
        limits.volatileOutput === true
          ? {
              fixedAllowance: { name, kind: "live" as const },
              retryable: true as const,
            }
          : fixedAllowanceOptions(name, "capture");
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `adb output exceeded the ${String(limits.maxOutputBytes)}-byte capture budget`,
          { max_output_bytes: limits.maxOutputBytes },
          { cause, ...allowance },
        ),
      );
    }
    const stderr = failure.stderr.trim();
    const excerpt = stderr.slice(0, STDERR_EXCERPT_CHARACTERS);
    // Device-state words inside a reported file name are not device verdicts.
    // Only leading notices need line parsing. Do not expand a capture-sized
    // stderr into an array whose entries can exceed the byte capture budget.
    let diagnosticStart = 0;
    while (diagnosticStart < stderr.length) {
      const newline = stderr.indexOf("\n", diagnosticStart);
      const line = stderr
        .slice(diagnosticStart, newline === -1 ? stderr.length : newline)
        .trimEnd();
      if (
        !isSuccessfulDaemonStartNotice(line) &&
        !/^\* daemon not running(?:; starting now at [^\r\n]*|\. starting it now on port \d+ \*)$/u.test(
          line,
        )
      )
        break;
      diagnosticStart = newline === -1 ? stderr.length : newline + 1;
    }
    const diagnostic = stderr
      .slice(diagnosticStart)
      .replace(
        /^(?:adb:\s*)?(?:error:\s*)?(?:(?:failed to get feature set|connect failed):\s*)?/iu,
        "",
      );
    if (
      /^(?:unauthorized\b|device(?: '[^'\n]*')? (?:unauthorized\b|offline\b|not found\b|still authorizing\b)|still authorizing\b|more than one device\b)/iu.test(
        diagnostic,
      )
    )
      return err(
        new AnalysisUnsupportedTargetError(operation, target.device, excerpt, {
          cause,
        }),
      );
    if (
      /No such file or directory|Permission denied|read: Permission denied/iu.test(
        diagnostic,
      )
    ) {
      const filePath = target.path;
      const localPath = target.localPath;
      const samePath = filePath !== undefined && filePath === localPath;
      const knownLocal =
        localPath !== undefined &&
        LOCAL_FILE_DIAGNOSTICS.some(([verb, suffix]) =>
          [localPath, `'${localPath}'`, `"${localPath}"`].some((operand) =>
            diagnostic.startsWith(`${verb} ${operand}${suffix}`),
          ),
        );
      const namesFile =
        filePath !== undefined && diagnosticNamesOperand(diagnostic, filePath);
      const namesLocal =
        localPath !== undefined &&
        !samePath &&
        (knownLocal || diagnosticNamesOperand(diagnostic, localPath));
      // Attribute the refusal only when the diagnostic names one operand. If it
      // names both distinct operands, keep the device identity rather than
      // guessing. Equal operands are one identity. Generic file failures retain
      // the addressed-path fallback owned by this command boundary.
      const path = samePath
        ? filePath
        : namesFile && namesLocal
          ? undefined
          : namesFile
            ? filePath
            : namesLocal
              ? localPath
              : (filePath ?? target.device);
      return err(
        new AnalysisUnsupportedTargetError(
          operation,
          path ?? target.device,
          excerpt,
          { cause },
        ),
      );
    }
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, {
          cause,
          userMessage: `adb ${operation} reached its ${String(limits.timeoutMs)} ms deadline (deadlineExpired). This release has no runtime override.`,
          remediationAction: `This ${String(limits.timeoutMs)} ms adb deadline has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
        }),
      );
    return err(
      new AdbProtocolError(
        excerpt === ""
          ? `adb exited with code ${String(failure.code)} for ${operation}`
          : excerpt,
        failure,
        cause,
      ),
    );
  }
};

/** Decode textual adb protocols after the shared byte capture and error boundary. */
export const runAdb = async (
  ...arguments_: Parameters<typeof runAdbCapture>
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  const captured = await runAdbCapture(...arguments_);
  if (!captured.ok) return captured;
  return ok({
    stdout: captured.value.stdout.toString("utf8"),
    stderr: captured.value.stderr.toString("utf8"),
    // Byte count of the captured output before UTF-8 decoding, so malformed
    // sequences replaced by U+FFFD still report their true captured size.
    stdoutBytes: captured.value.stdout.byteLength,
  });
};

/**
 * adb exits nonzero when the device refuses a package change, printing the
 * `Failure [...]` verdict to stderr (install) or stdout (uninstall). Read the
 * refusal from that failed run so it is not reported as unreadable output.
 */
export const packageChangeRefusal = (
  operation: string,
  serial: string,
  error: AnalysisError,
): Result<never, AnalysisError> | undefined => {
  if (!(error instanceof AdbProtocolError)) return undefined;
  const failure = error.commandFailure;
  const reason = packageChangeFailureReason(
    `${failure.stdout}\n${failure.stderr}`,
  );
  return reason === null
    ? undefined
    : err(
        new AnalysisUnsupportedTargetError(operation, serial, reason, {
          cause: error,
        }),
      );
};

/** Only the clean false result of test -e establishes absence. */
export const probeAdbPathExistence = async (
  operation: string,
  serial: string,
  path: string,
  binary: string,
  limits: AdbRunLimits,
  signal: AbortSignal | undefined,
): Promise<Result<boolean, AnalysisError>> => {
  const probed = await runAdbCapture(
    operation,
    { device: serial, path },
    binary,
    adbArguments(serial, ["shell", "test", "-e", path]),
    { ...limits, volatileOutput: true },
    signal,
  );
  if (probed.ok) {
    if (probed.value.stdout.length === 0 && probed.value.stderr.length === 0)
      return ok(true);
    return err(
      new AnalysisProtocolError(
        "The ADB path existence probe returned unexpected output; destination existence is unknown",
        {
          diagnostics: { destination_existence: "unknown" },
          capturedOutput: {
            stdout: probed.value.stdout.toString("utf8"),
            stderr: probed.value.stderr.toString("utf8"),
            stdout_bytes: probed.value.stdout.length,
            stderr_bytes: probed.value.stderr.length,
            exit_code: 0,
            signal: null,
            truncated: false,
          },
        },
      ),
    );
  }
  const error = probed.error;
  if (!(error instanceof AdbProtocolError)) return probed;
  const failure = error.commandFailure;
  if (
    failure.code === 1 &&
    failure.signal === null &&
    !failure.killed &&
    !failure.outputTruncated &&
    failure.collectionFailure !== true &&
    failure.stdout === "" &&
    failure.stderr === ""
  )
    return ok(false);
  return err(
    new AnalysisProtocolError(error.message, {
      cause: error.cause,
      diagnostics: { destination_existence: "unknown" },
      capturedOutput: adbCommandCapturedOutput(failure),
    }),
  );
};
