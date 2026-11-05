# NetworkLuki Imager

`imager` is a local command-line tool for JPEG and PNG metadata inspection, reversible removal of selected metadata, and triage of possible embedded or appended files.

Version: **0.1.0**. Requires **Python 3.11 or newer**. Runtime dependencies: **Python standard library only**. Intended platforms: Debian 13, Arch Linux, and Windows 11. Windows runtime behavior has not yet been tested in this development environment.

## Capabilities

| Command | Behavior |
| --- | --- |
| `inspect` | Report SHA-256, image dimensions, container structure, supported metadata, and signature candidates. |
| `metadata` | Decode supported metadata and optionally save a JSON report. |
| `scan` | Report candidate signatures, byte offsets, and data after the parsed image end. |
| `strip` | Write a new image with selected metadata removed and a mandatory restoration backup. |
| `restore` | Reconstruct the exact original bytes from an unchanged cleaned image and its matching backup. |
| `extract` | Copy a chosen byte range or trailing data into a new `.bin` file. |

JPEG and PNG are identified by their signatures, not by filename extensions. Other image formats and disk images are unsupported. The tool inspects container framing; it does not decode pixels or establish that every image is fully standards-conformant.

## Install from this repository

Run these commands from the repository root. Installation creates a project-local virtual environment; keep examination data elsewhere. Python and its virtual-environment support must already be installed. Package installation may download the declared build dependency; examination commands do not access the network.

Linux:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install ./tools/imager
./.venv/bin/imager --version
./.venv/bin/imager --help
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\tools\imager
.\.venv\Scripts\imager.exe --version
.\.venv\Scripts\imager.exe --help
```

If the Windows Python launcher `py` is unavailable, use your installed Python 3.11+ executable for the first command. No activation script or execution-policy change is required. The installed package also supports `python -m networkluki_imager` using the virtual environment's Python.

## Basic workflow

The following Linux example uses an existing working copy and an existing private results directory outside the repository. The [command reference](https://github.com/networkluki/forensic-science/blob/main/commands/imager/README.md) includes equivalent Windows commands.

```bash
./.venv/bin/imager inspect '/analysis/case-001/working/photo.jpg'
./.venv/bin/imager strip '/analysis/case-001/working/photo.jpg' --dry-run
./.venv/bin/imager strip '/analysis/case-001/working/photo.jpg' \
  --output '/analysis/case-001/results/photo.clean.jpg' \
  --backup '/analysis/case-001/results/photo.metadata-backup.json'
./.venv/bin/imager restore '/analysis/case-001/results/photo.clean.jpg' \
  --backup '/analysis/case-001/results/photo.metadata-backup.json' \
  --output '/analysis/case-001/results/photo.restored.jpg'
```

`strip --dry-run` creates no files. A real `strip` requires both `--output` and `--backup`; existing files are never overwritten. The original is read without intentional modification. Read access can still affect filesystem access times or audit records.

## Metadata behavior

Inspection decodes common EXIF/TIFF tags, including supported camera, timestamp, orientation, exposure, and GPS fields. It also reads supported PNG text and time metadata. XMP is displayed as bounded text without XML evaluation. Proprietary or unsupported data may be inventoried without decoding its contents. Read the report's warnings and truncation indicators; a report is not an exhaustive metadata inventory.

Removal is deliberately scoped:

| Format | Removed by `strip` | Retained |
| --- | --- | --- |
| JPEG | Entire `APP1`, `APP13`, and `COM` segments, including contained EXIF/XMP/IPTC where present. | Encoded pixels and other segments, including JFIF, ICC profiles, Adobe markers, and unknown APP segments. |
| PNG | Entire `tEXt`, `zTXt`, `iTXt`, `eXIf`, and `tIME` chunks. | Encoded pixels, color/rendering information, animation chunks, and other ancillary chunks. |

This is **not a complete privacy sanitizer**. Retained structures or pixels can still contain identifying or hidden information. Removing EXIF orientation can change how a viewer rotates an image even though encoded pixels are unchanged. PNG animation framing is retained without full animation validation.

Trailing bytes are preserved by default. Add `--drop-trailing` to `strip` to remove and back up bytes after the JPEG end marker or PNG `IEND` chunk. This can remove legitimate appended data as well as suspicious payloads; review a dry run first.

## Restoration and backups

The backup records the removed bytes, offsets, format, original size, SHA-256 hashes, and creation time. `restore` requires the exact cleaned image associated with that backup and verifies the reconstructed original hash before writing. It restores original file content, not filesystem permissions, access times, ownership, or other filesystem metadata.

An ordinary `metadata --output` report is **not** a restoration backup. Information removed without a backup or original source cannot be reconstructed by this tool. Editing or re-encoding the cleaned image breaks the exact-match restoration workflow.

Backups can contain GPS coordinates, serial numbers, thumbnails, and removed trailing payloads. Store them privately and keep copies of the original. Hashes check consistency; backups are not signed or authenticated, so use backups from a trusted source. Restoring one can reintroduce private metadata and embedded content.

## Embedded-file triage

`scan` searches for ZIP, PDF, 7z, RAR, gzip, ELF, DOS/PE `MZ`, JPEG, and PNG prefixes. It returns up to 100 candidates with zero-based byte offsets, signature lengths, and structural regions. `confidence` is always `signature_only`; candidate file `length` is unknown. An appended range has a known byte count but is not automatically a valid file.

Signatures can occur accidentally in compressed pixels, and EXIF thumbnails legitimately contain images. A negative scan does not exclude encrypted content, embedded files without recognized prefixes, or pixel-based steganography. The tool does not decode steganography, unpack archives, execute payloads, or certify that a file is harmless.

`extract --trailing` copies all bytes after the parsed image end. Alternatively, specify both `--offset` and `--length` for a known nonempty range. Extraction requires a new `.bin` output and performs no file validation or decompression. Never execute extracted bytes merely because the tool found a recognizable signature.

## Limits and output safety

- Maximum image input: **64 MiB**; maximum restoration-backup JSON: **96 MiB**.
- Maximum container parts: **10,000**; maximum signature candidates: **100**.
- Metadata decoding is bounded, including text fields, aggregate text, tags, and directory traversal. Warnings identify omitted or truncated information.
- Inputs must be ordinary files. Links, Windows reparse points/junctions, devices, and paths through linked directories are rejected. Windows alternate data streams, UNC shares, device namespaces, and trailing-dot/space aliases are unsupported. Output parent directories must already exist.
- Output creation is exclusive and never overwrites existing paths. New POSIX files request mode `0600`; Windows access follows filesystem ACLs. Use a private workspace with appropriate access controls.
- The backup is written before the cleaned image. If the image write fails, the complete backup can remain. Handled write failures attempt to remove partial files, but interruption or power loss can leave files requiring manual inspection. Output pairs are not one atomic transaction.
- Inspection performs no subprocess execution, telemetry, or network access. It does not protect a workspace against another process concurrently replacing its directories.

Reports use JSON on stdout or in a new file selected with `--output`. Errors go to stderr. Exit codes: `0` successful command, `1` processing or I/O failure, `2` invalid command-line arguments, `130` interrupted command. Successful inspection can still contain warnings or capped results; read them before interpreting the output as complete.

## Verification

After installation, run the synthetic test suite from the repository root:

```bash
./.venv/bin/python -m unittest discover -s tests/imager -v
```

Windows PowerShell equivalent:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests/imager -v
```

Tests exercise structural parsing, bounded metadata decoding, signature triage, exact strip/restore round trips, and file-handling failures. Passing tests cover their stated cases and do not certify forensic validity or legal admissibility.

## License

Copyright (c) 2026 NetworkLuki. Distributed under the [NetworkLuki Forensic Science Personal Use License](https://github.com/networkluki/forensic-science/blob/main/LICENSE). Personal, non-commercial use is permitted under its terms; commercial use and redistribution require permission subject to the license's exceptions.

Use only images and systems you own or are explicitly authorized to examine. Keep real evidence, backups, reports, and extracted payloads outside this public repository.
