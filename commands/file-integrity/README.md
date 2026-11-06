# File integrity commands

Target: Linux / Windows, Python 3.11+. Run from the repository root without administrator privileges. Use a verified, stable working copy; keep manifests outside it. These commands read file contents and may affect access times, caches or audit logs. They do not intentionally change source content.

## Linux

```bash
python3 tools/file-integrity/file_integrity.py create '/analysis/case-copy' --output '/analysis/manifests/baseline.json'
python3 tools/file-integrity/file_integrity.py verify '/analysis/manifests/baseline.json' --root '/analysis/case-copy'
```

## Windows

```powershell
py -3 tools/file-integrity/file_integrity.py create 'C:\Analysis\case-copy' --output 'C:\Analysis\manifests\baseline.json'
py -3 tools/file-integrity/file_integrity.py verify 'C:\Analysis\manifests\baseline.json' --root 'C:\Analysis\case-copy'
```

Create the trusted output directory beforehand. Replace the source directory with a file path for a single-file manifest; pass that file path to `--root` when verifying. Output refuses to overwrite existing results: choose a new manifest name for a new collection.

Expected matching verification: empty `added`, `changed`, and `missing` arrays, exit 0. Differences return 1. Unsafe paths, links/reparse points, read failures, unstable files or invalid manifests return 2; treat these as incomplete examinations. A missing root also returns 2.

See [format, limits and concurrency limitations](../../tools/file-integrity/README.md). Hashes alone do not establish an unbroken chain of custody. Preserve a trusted baseline and collection records separately.

Implementation references: Python [hashlib](https://docs.python.org/3/library/hashlib.html), [os file operations](https://docs.python.org/3/library/os.html), and [stat](https://docs.python.org/3/library/stat.html).
