# Tests

Imager's automated tests are in `tests/imager/`. They use synthetic fixtures and Python's standard-library `unittest` runner.

After installing Imager as described in its [README](../tools/imager/README.md), run from the repository root:

```text
python -m unittest discover -s tests/imager -v
```

The [CI workflow](../.github/workflows/imager-tests.yml) runs the tests on Windows and Ubuntu with Python 3.11 and 3.13. Check the actual Actions results before claiming a particular run passed. Tests cover container parsing, metadata decoding, malformed inputs, backup integrity, restoration, output protection, and bounded signature scanning.

Add tests under `tests/<tool-name>/` when implementing a tool. Use synthetic fixtures and temporary output directories. Cover the tool's documented behavior, error paths, and security boundaries; do not require real evidence or privileged access by default.

Document the exact test command and expected outcome in the tool README. A passing test suite only supports its stated test scope; it does not certify forensic validity.
