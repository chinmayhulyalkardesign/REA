# Ordinary .NET single-file bundle inventory and extraction

Implements [#2352](https://github.com/morluto/rea/issues/2352) within existing
offline artifact inspection/extraction authority.

- Identify a bundle from the apphost marker and a nonzero in-file header offset,
  preserving the complete native host identity.
- Admit header versions 1.0, 2.0, and 6.0; expose member version/type declarations,
  names, stored extents, expanded sizes, and computed expanded-byte identities.
- Decode only ordinary uncompressed and v6 raw-DEFLATE members. Preserve unknown
  types with explicit limitations and refuse unsupported versions/flags.
- Apply bounded metadata and compressed/expanded resource admission. Reject
  truncation, overlaps, unsafe/conflicting paths, malformed encoding, and
  source changes. Retain cancellation and resource-scope cleanup semantics.
- Reuse `inspect-artifact`/`extract-artifact` and their MCP equivalents. Extraction
  owns an absent output root and validates materialized bytes against inventory.
- Never load assemblies, run the host, decrypt content, or add a runtime provider.

The supported layout and policy limits are documented in
[the owning guide](../../dotnet-bundles.md).
