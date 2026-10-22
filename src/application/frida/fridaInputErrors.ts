import { AnalysisInputError } from "../../domain/analysisErrorCore.js";

/** A session ID that names no open Frida session owned by this process. */
export const unknownFridaSession = (
  operation: string,
  sessionId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["session_id"],
      reason: "invalid_value",
      message: `No open Frida session ${sessionId}; start one with start_frida_session.`,
    },
  ]);

/** A session whose target already runs: an attach, or a spawn already resumed. */
export const notPausedFridaSession = (
  operation: string,
  sessionId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["session_id"],
      reason: "invalid_value",
      message: `Frida session ${sessionId} is already running; only a paused spawn can be resumed, so skip resume_frida_session for attached or already-resumed sessions.`,
    },
  ]);

/** A script ID that names no loaded script in the selected session. */
export const unknownFridaScript = (
  operation: string,
  scriptId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["script_id"],
      reason: "invalid_value",
      message: `No loaded Frida script ${scriptId} in this session.`,
    },
  ]);
