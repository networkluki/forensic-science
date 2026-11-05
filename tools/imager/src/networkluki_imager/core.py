"""Reversible byte-range metadata removal and strict backup validation."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import re

from . import __version__
from .formats import parse_image
from .storage import MAX_BACKUP_BYTES, MAX_IMAGE_BYTES

BACKUP_SCHEMA = "networkluki-imager-backup-v1"
MAX_PATCHES = 10001


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    # ASCII escaping also prevents control characters from reaching terminals.
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def strip_bytes(data: bytes, *, drop_trailing: bool = False) -> tuple[bytes, dict]:
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("Image exceeds the size limit")
    structure = parse_image(data)
    ranges = [(p.start, p.end, p.kind) for p in structure.parts if p.removable]
    if drop_trailing and structure.image_end < len(data):
        ranges.append((structure.image_end, len(data), "trailing_data"))
    ranges.sort()
    cursor = 0
    chunks = []
    patches = []
    for start, end, kind in ranges:
        if not cursor <= start < end <= len(data):
            raise ValueError("Invalid or overlapping metadata range")
        chunks.append(data[cursor:start])
        patches.append({"offset": start, "kind": kind, "data_base64": base64.b64encode(data[start:end]).decode("ascii")})
        cursor = end
    chunks.append(data[cursor:])
    cleaned = b"".join(chunks)
    verified = parse_image(cleaned)
    if (verified.format, verified.width, verified.height) != (structure.format, structure.width, structure.height):
        raise ValueError("Image structure changed unexpectedly")
    if any(p.removable for p in verified.parts):
        raise ValueError("Selected metadata remains after removal")
    backup = {
        "schema": BACKUP_SCHEMA,
        "tool_version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "format": structure.format,
        "original_size": len(data),
        "original_sha256": sha256(data),
        "cleaned_sha256": sha256(cleaned),
        "patches": patches,
    }
    return cleaned, backup


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate backup JSON key")
        result[key] = value
    return result


def restore_bytes(cleaned: bytes, backup_data: bytes) -> bytes:
    if len(cleaned) > MAX_IMAGE_BYTES or len(backup_data) > MAX_BACKUP_BYTES:
        raise ValueError("Input exceeds the size limit")
    try:
        backup = json.loads(backup_data, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid backup JSON") from exc
    if not isinstance(backup, dict) or backup.get("schema") != BACKUP_SCHEMA:
        raise ValueError("Unsupported backup schema")
    expected_keys = {"schema", "tool_version", "created_utc", "format", "original_size", "original_sha256", "cleaned_sha256", "patches"}
    if set(backup) != expected_keys:
        raise ValueError("Unexpected or missing backup fields")
    for field in ("tool_version", "created_utc"):
        if not isinstance(backup[field], str) or not 1 <= len(backup[field]) <= 128:
            raise ValueError("Invalid backup descriptive fields")
    for field in ("original_sha256", "cleaned_sha256"):
        if not isinstance(backup[field], str) or re.fullmatch(r"[0-9a-f]{64}", backup[field]) is None:
            raise ValueError("Invalid backup hash")
    size = backup["original_size"]
    if type(size) is not int or not len(cleaned) <= size <= MAX_IMAGE_BYTES:
        raise ValueError("Invalid original size")
    if sha256(cleaned) != backup["cleaned_sha256"]:
        raise ValueError("Backup does not match this cleaned image")
    structure = parse_image(cleaned)
    if backup["format"] != structure.format:
        raise ValueError("Backup format does not match the image")
    patches = backup["patches"]
    if not isinstance(patches, list) or len(patches) > MAX_PATCHES:
        raise ValueError("Invalid backup patch list")
    original_cursor = 0
    clean_cursor = 0
    restored_parts = []
    restored_size = len(cleaned)
    for patch in patches:
        if not isinstance(patch, dict) or set(patch) != {"offset", "kind", "data_base64"}:
            raise ValueError("Invalid backup patch")
        offset = patch["offset"]
        encoded = patch["data_base64"]
        if type(offset) is not int or not original_cursor <= offset <= size:
            raise ValueError("Invalid or overlapping backup offset")
        if not isinstance(patch["kind"], str) or len(patch["kind"]) > 64:
            raise ValueError("Invalid backup patch kind")
        if not isinstance(encoded, str) or len(encoded) > MAX_BACKUP_BYTES:
            raise ValueError("Invalid backup payload")
        try:
            removed = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Invalid base64 backup payload") from exc
        if not removed:
            raise ValueError("Empty backup patch")
        gap = offset - original_cursor
        if clean_cursor + gap > len(cleaned) or offset + len(removed) > size:
            raise ValueError("Backup patch exceeds the image bounds")
        restored_size += len(removed)
        if restored_size > size:
            raise ValueError("Backup payload exceeds the declared size")
        restored_parts.extend((cleaned[clean_cursor:clean_cursor + gap], removed))
        clean_cursor += gap
        original_cursor = offset + len(removed)
    restored_parts.append(cleaned[clean_cursor:])
    restored = b"".join(restored_parts)
    if len(restored) != size or sha256(restored) != backup["original_sha256"]:
        raise ValueError("Restored bytes do not match the backup's original hash")
    result = parse_image(restored)
    if result.format != structure.format:
        raise ValueError("Restored image has an unexpected format")
    return restored
