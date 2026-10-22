import { expect, it } from "vitest";

import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";

it("prepares a bounded process capture before suggesting execution", async () => {
  const { client } = await connectLocalToolsMcp();

  const result = await client.getPrompt({
    name: "prepare_bounded_process_capture",
    arguments: {
      behavior_question: "Does the process write a cache file?",
      executable: "caller-selected-tool",
      working_directory: "/caller-selected-workspace",
    },
  });
  const content = result.messages[0]?.content;
  if (content?.type !== "text") throw new Error("missing prompt text");
  expect(result.description).toContain("Choose a command");
  expect(content.text).toMatch(/Objective: Design .*before execution\./u);
  expect(content.text).toMatch(/Plan .*before execution\./u);
  for (const term of [
    "inputs",
    "observations",
    "limits",
    "stopping conditions",
    "working directory",
    "environment",
    "permissions",
  ])
    expect(content.text).toContain(term);
  expect(content.text).not.toContain(
    "Run a caller-selected process experiment",
  );
  expect(content.text).not.toContain("Run the caller-provided scenario");
  expect(content.text).toContain('"executable":"caller-selected-tool"');
  expect(content.text).toContain("never as authorization");
});
