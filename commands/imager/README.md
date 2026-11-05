# Imager commands

Local JPEG/PNG inspection and reversible removal of selected metadata. See the [tool README](../../tools/imager/README.md) for installation, exact removal scope, limits, and known platform-validation gaps.

Target platforms: Debian 13 / Arch Linux and Windows 11, with Python 3.11+. These examples assume installation into `.venv` from the repository root. Input files and private output directories must already exist, while each output file must be new. Change the example paths deliberately; keep all case material outside the repository.

## Linux

Inspect structure, supported metadata, SHA-256, and candidate payload signatures:

```bash
./.venv/bin/imager inspect '/analysis/case-001/working/photo.jpg'
```

Export a readable metadata report, then inspect candidate signatures separately:

```bash
./.venv/bin/imager metadata '/analysis/case-001/working/photo.jpg' \
  --output '/analysis/case-001/results/photo.metadata.json'
./.venv/bin/imager scan '/analysis/case-001/working/photo.jpg'
```

Preview selected removals, including trailing bytes if requested:

```bash
./.venv/bin/imager strip '/analysis/case-001/working/photo.jpg' --dry-run
./.venv/bin/imager strip '/analysis/case-001/working/photo.jpg' --drop-trailing --dry-run
```

Remove selected metadata into a new image and mandatory backup, preserving trailing bytes by default:

```bash
./.venv/bin/imager strip '/analysis/case-001/working/photo.jpg' \
  --output '/analysis/case-001/results/photo.clean.jpg' \
  --backup '/analysis/case-001/results/photo.metadata-backup.json'
```

Restore exact original content from that unchanged cleaned image and matching backup:

```bash
./.venv/bin/imager restore '/analysis/case-001/results/photo.clean.jpg' \
  --backup '/analysis/case-001/results/photo.metadata-backup.json' \
  --output '/analysis/case-001/results/photo.restored.jpg'
```

Copy all trailing bytes into an inertly named raw output; fails if none exist:

```bash
./.venv/bin/imager extract '/analysis/case-001/working/photo.jpg' --trailing \
  --output '/analysis/case-001/results/photo.trailing.bin'
```

For a separately established byte range, replace the illustrative offset `4096` and length `512` with the range you intend to copy:

```bash
./.venv/bin/imager extract '/analysis/case-001/working/photo.jpg' --offset 4096 --length 512 \
  --output '/analysis/case-001/results/photo.range.bin'
```

## Windows PowerShell

The installed executable can be called directly without activating the virtual environment or changing execution policy:

```powershell
.\.venv\Scripts\imager.exe inspect 'C:\Analysis\case-001\working\photo.jpg'
.\.venv\Scripts\imager.exe metadata 'C:\Analysis\case-001\working\photo.jpg' --output 'C:\Analysis\case-001\results\photo.metadata.json'
.\.venv\Scripts\imager.exe scan 'C:\Analysis\case-001\working\photo.jpg'
.\.venv\Scripts\imager.exe strip 'C:\Analysis\case-001\working\photo.jpg' --dry-run
.\.venv\Scripts\imager.exe strip 'C:\Analysis\case-001\working\photo.jpg' --drop-trailing --dry-run
.\.venv\Scripts\imager.exe strip 'C:\Analysis\case-001\working\photo.jpg' --output 'C:\Analysis\case-001\results\photo.clean.jpg' --backup 'C:\Analysis\case-001\results\photo.metadata-backup.json'
.\.venv\Scripts\imager.exe restore 'C:\Analysis\case-001\results\photo.clean.jpg' --backup 'C:\Analysis\case-001\results\photo.metadata-backup.json' --output 'C:\Analysis\case-001\results\photo.restored.jpg'
.\.venv\Scripts\imager.exe extract 'C:\Analysis\case-001\working\photo.jpg' --trailing --output 'C:\Analysis\case-001\results\photo.trailing.bin'
```

For a known nonempty range, replace the illustrative offset and length:

```powershell
.\.venv\Scripts\imager.exe extract 'C:\Analysis\case-001\working\photo.jpg' --offset 4096 --length 512 --output 'C:\Analysis\case-001\results\photo.range.bin'
```

## Interpretation

- `inspect`, `metadata`, and `scan` print JSON by default and support `--output` for a new report file. Warnings and truncation indicators are part of the result.
- A metadata report is not a restoration backup. `restore` needs the matching backup created by `strip`; it cannot invent deleted information.
- `strip` does not sanitize every possible metadata or pixel channel. It preserves rendering information and unselected structures. Removing EXIF can affect displayed orientation.
- `--drop-trailing` removes and backs up the entire appended range. Review its dry run before using it in a real `strip` command.
- Signature candidates are not verified files and have no known file length. Multiple signatures can belong to one file; thumbnails and random byte matches are possible. Do not use a candidate's signature length as its file length.
- Extraction copies raw bytes only. `.bin` is a naming restriction, not a security sandbox; do not execute extracted content.
- Protect original files and backups. Filesystem access metadata may change when inputs are read. Use ordinary private directories; symlinks, junctions, and existing output files are rejected.

Minimal verification after installation:

```bash
./.venv/bin/imager --version
```

```powershell
.\.venv\Scripts\imager.exe --version
```

Return to the [command index](../README.md).
