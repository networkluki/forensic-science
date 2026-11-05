# Tests

No executable forensic tools or automated tool tests are included in this repository foundation.

Add tests under `tests/<tool-name>/` when implementing a tool. Use synthetic fixtures and temporary output directories. Cover the tool's documented behavior, error paths, and security boundaries; do not require real evidence or privileged access by default.

Document the exact test command and expected outcome in the tool README. A passing test suite only supports its stated test scope; it does not certify forensic validity.
