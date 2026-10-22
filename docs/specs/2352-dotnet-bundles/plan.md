# Plan

1. Add a bounded positional manifest parser, using Microsoft's first-marker
   contract and published v1/v2/v6 layouts.
2. Add a range-streamed ArtifactReader with raw-DEFLATE decoding, exact member
   lengths, stable source checks, and explicit stream/descriptor ownership.
3. Select the reader from native host bytes in existing inventory/extraction.
   Extend only artifact format/member declarations and stored source extents.
4. Verify malformed input and failure cleanup at filesystem boundaries, then
   exercise compiled public CLI and stdio MCP inspection/extraction.
5. Verify source-owned bundles emitted by Microsoft's SDK/HostModel, document
   admission and unsupported behavior, and complete static/contract checks.

No new tools, providers, external executables, or extraction path owner are added.
