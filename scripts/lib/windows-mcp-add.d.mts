export function setupClientId(agent: string): string;

export type WindowsMcpAddDelegation =
  | { readonly refusal: string }
  | { readonly args: readonly string[]; readonly note: string };

export function windowsMcpAddDelegation(
  args: readonly string[],
  platform: string,
): WindowsMcpAddDelegation | undefined;
