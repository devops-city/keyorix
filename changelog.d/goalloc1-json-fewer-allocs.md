### Internal
- **Fewer allocations on JSON responses.** Responses whose times already carry a zero offset skip the reflective UTC copy (the wire bytes are identical), and the version-metadata classifier decodes the metadata once instead of twice. Same classification for every input (differential test + fuzz target).
