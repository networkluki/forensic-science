"""Bounded byte-signature triage; findings are candidates, not verified files."""

from __future__ import annotations

import heapq
from typing import Any


MAX_FINDINGS = 100

# A magic prefix alone does not validate a complete file or determine its size.
_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("ZIP local header", b"PK\x03\x04"),
    ("ZIP end record", b"PK\x05\x06"),
    ("PDF", b"%PDF-"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("RAR4", b"Rar!\x1a\x07\x00"),
    ("RAR5", b"Rar!\x1a\x07\x01\x00"),
    ("gzip", b"\x1f\x8b\x08"),
    ("ELF", b"\x7fELF"),
    ("DOS/PE MZ candidate", b"MZ"),
    ("JPEG", b"\xff\xd8\xff"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
)

_PNG_METADATA = frozenset(
    {"tEXt", "zTXt", "iTXt", "eXIf", "tIME", "iCCP", "pHYs", "sPLT"}
)
_IMAGE_DATA = frozenset({"IDAT", "fdAT", "SCAN_DATA"})


def _region(offset: int, structure: Any) -> str:
    """Classify a signature's first byte without claiming payload boundaries."""
    if offset >= structure.image_end:
        return "trailing"
    for part in structure.parts:
        if part.data_start <= offset < part.data_end:
            if part.kind in _IMAGE_DATA:
                return "image_data"
            if (
                part.kind.startswith("APP")
                or part.kind == "COM"
                or part.kind in _PNG_METADATA
                or part.removable
            ):
                return "metadata"
            return "container"
    return "container"


def scan_report(data: bytes, structure: Any) -> dict[str, Any]:
    """Return up to 100 signature candidates in ascending byte-offset order.

    The caller supplies a validated image structure and enforces input-size
    limits. The scanner never decompresses, opens, extracts, or executes a
    candidate. Each signature search advances monotonically; the heap contains
    at most one pending match per signature and scanning stops at the cap.
    """
    if not isinstance(data, bytes):
        raise TypeError("scan_report requires bytes")
    if (
        type(structure.image_end) is not int
        or not 0 <= structure.image_end <= len(data)
    ):
        raise ValueError("image_end must be within the input")

    # Merge signature matches without materializing every hit from hostile data.
    pending: list[tuple[int, int]] = []
    for index, (kind, signature) in enumerate(_SIGNATURES):
        start = 1 if kind == structure.format and kind in {"JPEG", "PNG"} else 0
        offset = data.find(signature, start)
        if offset >= 0:
            heapq.heappush(pending, (offset, index))

    candidates: list[dict[str, Any]] = []
    while pending and len(candidates) < MAX_FINDINGS:
        offset, index = heapq.heappop(pending)
        kind, signature = _SIGNATURES[index]
        candidates.append(
            {
                "kind": kind,
                "offset": offset,
                "signature_length": len(signature),
                "region": _region(offset, structure),
                "confidence": "signature_only",
                "length": None,
            }
        )
        next_offset = data.find(signature, offset + 1)
        if next_offset >= 0:
            heapq.heappush(pending, (next_offset, index))

    trailing_size = len(data) - structure.image_end
    return {
        "candidates": candidates,
        "candidate_count": len(candidates),
        "truncated": bool(pending),
        "max_findings": MAX_FINDINGS,
        "appended_range": (
            {"offset": structure.image_end, "length": trailing_size}
            if trailing_size
            else None
        ),
        "limitations": [
            "Signatures are unverified candidates, not proof of complete embedded files; "
            "payload lengths are unknown and multiple findings may belong to one file.",
            "Signatures can occur accidentally in compressed pixels or metadata; "
            "EXIF thumbnails may legitimately contain another JPEG image.",
            "Trailing bytes are structurally outside the parsed image, but are not "
            "automatically a valid file or malicious content.",
            "A negative scan does not rule out embedded files, encrypted content, "
            "or steganography such as data hidden in pixel least-significant bits.",
            "No candidate content was decompressed or executed. Offsets are zero-based bytes.",
        ],
    }
