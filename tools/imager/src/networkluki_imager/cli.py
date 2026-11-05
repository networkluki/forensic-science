"""The imager console entry point. JSON output, no subprocesses or networking."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import os
from pathlib import Path
import sys

from . import __version__
from .core import json_bytes, restore_bytes, sha256, strip_bytes
from .formats import parse_image
from .metadata import metadata_report
from .scanner import scan_report
from .storage import MAX_BACKUP_BYTES, checked_path, read_checked, write_new


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="imager",
        description="Local JPEG/PNG inspection and reversible metadata removal. Never overwrites files.",
    )
    result.add_argument("--version", action="version", version=f"imager {__version__}")
    subcommands = result.add_subparsers(dest="command", required=True)
    for name, description in (
        ("inspect", "Report image structure, metadata, SHA-256 and payload candidates"),
        ("metadata", "Decode supported metadata and export JSON"),
        ("scan", "Find possible embedded/appended file signatures (not proof of a file)"),
    ):
        command = subcommands.add_parser(name, help=description, description=description)
        command.add_argument("image", type=Path)
        command.add_argument("--output", type=Path, help="New JSON file; otherwise print JSON")
    strip = subcommands.add_parser("strip", help="Remove selected metadata into a mandatory backup")
    strip.add_argument("image", type=Path)
    strip.add_argument("--output", type=Path, help="New cleaned image (required unless --dry-run)")
    strip.add_argument("--backup", type=Path, help="New sensitive backup JSON (required unless --dry-run)")
    strip.add_argument("--drop-trailing", action="store_true", help="Also remove and back up bytes after the image end")
    strip.add_argument("--dry-run", action="store_true", help="Report removals without creating any files")
    restore = subcommands.add_parser("restore", help="Restore an exact original from its cleaned image and backup")
    restore.add_argument("image", type=Path, help="Unmodified cleaned image matching the backup hash")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True, help="New restored image")
    extract = subcommands.add_parser("extract", help="Copy an explicit byte range to a new .bin file; never execute/unpack")
    extract.add_argument("image", type=Path)
    mode = extract.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trailing", action="store_true", help="Copy all bytes after the image end")
    mode.add_argument("--offset", type=int, help="Zero-based start byte offset")
    extract.add_argument("--length", type=int, help="Required with --offset; byte count")
    extract.add_argument("--output", type=Path, required=True, help="New raw .bin file")
    return result


def _emit(report: dict, output: Path | None = None) -> None:
    serialized = json_bytes(report)
    if output is None:
        sys.stdout.write(serialized.decode("ascii"))
    else:
        write_new(output, serialized)
        sys.stdout.write(json_bytes({"status": "written", "output": str(output)}).decode("ascii"))


def run(args: argparse.Namespace) -> None:
    data = read_checked(args.image)
    structure = parse_image(data)
    identity = {"tool": "imager", "version": __version__, "size_bytes": len(data), "sha256": sha256(data), "format": structure.format}
    if args.command in {"inspect", "metadata", "scan"}:
        report = dict(identity)
        if args.command == "inspect":
            report["structure"] = asdict(structure)
        if args.command in {"inspect", "metadata"}:
            report["metadata"] = metadata_report(data, structure)
        if args.command in {"inspect", "scan"}:
            report["scan"] = scan_report(data, structure)
        report["warnings"] = structure.warnings
        _emit(report, args.output)
        return
    if args.command == "strip":
        if not args.dry_run:
            if args.output is None or args.backup is None:
                raise ValueError("strip requires --output and --backup, or --dry-run")
            output = checked_path(args.output, output=True)
            backup_path = checked_path(args.backup, output=True)
            if os.path.normcase(str(output)) == os.path.normcase(str(backup_path)):
                raise ValueError("Image output and backup must be different paths")
        cleaned, backup = strip_bytes(data, drop_trailing=args.drop_trailing)
        report = dict(identity)
        report.update({
            "status": "dry_run" if args.dry_run else "written",
            "cleaned_sha256": sha256(cleaned),
            "removed_bytes": len(data) - len(cleaned),
            "removed_ranges": [{"kind": p["kind"], "offset": p["offset"]} for p in backup["patches"]],
            "trailing_data_removed": bool(args.drop_trailing and structure.image_end < len(data)),
            "warnings": structure.warnings + [
                "This removes selected metadata only; it is not a complete privacy sanitizer.",
                "Removing EXIF may change displayed orientation without changing encoded pixels.",
                "The backup contains removed information and can restore trailing payloads. Keep it private.",
            ],
        })
        if not args.dry_run:
            backup_data = json_bytes(backup)
            if restore_bytes(cleaned, backup_data) != data:
                raise ValueError("Internal restoration verification failed")
            write_new(args.backup, backup_data)
            # Keep the complete backup if creating the image fails later.
            write_new(args.output, cleaned)
            report.update({"output": str(args.output), "backup": str(args.backup)})
        _emit(report)
        return
    if args.command == "restore":
        checked_path(args.output, output=True)
        backup_data = read_checked(args.backup, MAX_BACKUP_BYTES)
        restored = restore_bytes(data, backup_data)
        write_new(args.output, restored)
        _emit({"status": "written", "output": str(args.output), "size_bytes": len(restored), "sha256": sha256(restored)})
        return
    if args.command == "extract":
        if args.output.suffix.lower() != ".bin":
            raise ValueError("Raw extraction output must use the .bin extension")
        if args.trailing:
            if args.length is not None:
                raise ValueError("--length is not used with --trailing")
            offset, length = structure.image_end, len(data) - structure.image_end
        else:
            offset, length = args.offset, args.length
        if length is None or offset < 0 or length <= 0 or offset > len(data) or length > len(data) - offset:
            raise ValueError("Select a nonempty byte range entirely inside the input")
        payload = data[offset:offset + length]
        write_new(args.output, payload)
        _emit({"status": "written", "output": str(args.output), "offset": offset, "length": length, "sha256": sha256(payload), "warning": "Raw bytes only; no file validation, decompression or execution was performed."})


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        run(args)
    except BrokenPipeError:
        return 1
    except (OSError, ValueError, RecursionError, OverflowError) as exc:
        print(f"imager: {str(exc)!a}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("imager: interrupted; check output paths for incomplete files", file=sys.stderr)
        return 130
    return 0
