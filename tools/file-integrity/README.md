# NetworkLuki File Integrity 0.1.0

Local SHA-256 content manifests for regular files and recursive directories. Linux and Windows, Python 3.11+, standard library only, no installation or elevated privileges required. Covered by the repository's [license](../../LICENSE).

See the [command reference](../../commands/file-integrity/README.md). Run `python tools/file-integrity/file_integrity.py --help` from the repository root.

## Contract

- `create SOURCE --output MANIFEST` creates a UTF-8-compatible ASCII JSON manifest. `verify MANIFEST --root SOURCE` prints JSON lists `changed`, `missing`, and `added`. A file source uses its basename as its relative identifier; directory sources include every regular file recursively. Empty directories are not represented. Moving a directory tree preserves identifiers; renaming a single file changes its identifier.
- Exit status: **0** complete creation or matching verification; **1** complete verification with differences; **2** invalid arguments, malformed manifest, inaccessible or unstable source, unsafe entry, or output failure. An error is not a clean verification and never produces a success report. A missing root is an examination error; missing files inside an accessible root are differences.
- Deterministic versioned schema: `format`, `algorithm`, `tool_version`, `kind`, `files`; each file has `path`, `size` (bytes), and lowercase `sha256`. Paths use `/` and records are sorted by Unicode code point. No host paths or timestamps are embedded. Manifest bytes do not depend on mtimes, enumeration order or platform for the same portable names and content. Version 1 accepts only tool version 0.1.0.
- Absolute paths, traversal, backslashes, ADS syntax, control characters, Windows reserved names, trailing dots/spaces, invalid UTF-8 names and case collisions are rejected. Symlinks (including ancestor links), Windows reparse points/junctions, and special files are refused rather than skipped. Hard-linked regular files are hashed per pathname.
- Strict schema, duplicate JSON key/path detection, SHA-256 and integer validation; maximum manifest 32 MiB and maximum inventory 100,000 entries including directories. Reads use 1 MiB chunks and are bounded by the initial file size. Very deep trees may fail safely at Python's recursion limit. There is no elapsed-time guarantee for slow storage.
- Identity, type, size, nanosecond mtime and ctime are compared before/after reading; the complete inventory is compared again afterwards. POSIX opens anchor each path component through directory descriptors with `O_NOFOLLOW`. Windows rejects observed reparse points and checks ancestry before and after reading.
- Source content is opened read-only. Reading can update atime, caches and audit logs. Run on a trusted, quiescent, write-protected working copy or filesystem snapshot: these checks are **not an atomic filesystem snapshot** and cannot guarantee detection of malicious concurrent namespace swaps (particularly on Windows), same-metadata rewrites, or changes restored between checks. Do not run against a namespace controlled by an active adversary.
- Output must be outside the source tree, in an existing ordinary directory. Existing outputs are never overwritten. A temporary file is flushed and atomically published with a no-clobber hard link, then removed. Filesystems without hard-link support fail closed. A crash may leave a temporary file; a cleanup failure can occur after a complete manifest was published. Keep the output directory trusted and stable.
- Verification never writes reports or metadata to the source. No network, telemetry or external commands are used. File names are JSON-escaped in reports; error strings use escaped representations.

## Evidence limits

A matching digest supports content similarity, not authorship, event timing, provenance, or an unbroken chain of custody. An attacker who can replace both a file and its manifest can make them agree. Preserve the original manifest separately with controlled access and private case records. Record source identifiers, command, tool/Python versions, UTC collection time, operators, transfers, errors and storage limitations in those records; timestamps deliberately stay outside the deterministic manifest. See [evidence handling](../../docs/evidence-handling.md).

## Regression checks

```text
python -m unittest discover -s tests/file-integrity -v
```

Synthetic temporary files only. CI runs on Ubuntu and Windows with Python 3.11 and 3.13, including malformed manifests, deterministic hashes, changes, missing/added files, links, junctions, read failures, limits and simulated concurrent changes. Platform-inapplicable tests skip explicitly. Tests support their stated scope and do not certify forensic validity.
