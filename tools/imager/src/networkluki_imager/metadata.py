"""Bounded, best-effort metadata inspection without executing embedded content.

This module intentionally does not implement every EXIF extension or parse XML.
Offsets refer to the input file, not a decoded image. See the project license.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import struct
import zlib
from dataclasses import dataclass
from typing import Any

MAX_FIELD_BYTES = 64 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_TAGS = 1024
MAX_ARRAY_ITEMS = 32
MAX_IFDS = 32
MAX_METADATA_PARTS = 1024

_TIFF_TYPES = {
    1: (1, "B"), 2: (1, None), 3: (2, "H"), 4: (4, "I"),
    5: (8, None), 6: (1, "b"), 7: (1, None), 8: (2, "h"),
    9: (4, "i"), 10: (8, None), 11: (4, "f"), 12: (8, "d"),
}
_TAGS = {
    0x0100: "ImageWidth", 0x0101: "ImageLength", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x0201: "JPEGInterchangeFormat", 0x0202: "JPEGInterchangeFormatLength",
    0x8298: "Copyright", 0x829A: "ExposureTime", 0x829D: "FNumber",
    0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer",
    0x8827: "PhotographicSensitivity", 0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized", 0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue", 0x9209: "Flash", 0x920A: "FocalLength",
    0x927C: "MakerNote", 0x9286: "UserComment", 0x9290: "SubSecTime",
    0x9291: "SubSecTimeOriginal", 0x9292: "SubSecTimeDigitized",
    0xA001: "ColorSpace", 0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0xA005: "InteroperabilityIFDPointer", 0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber",
    0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
}
_GPS_TAGS = {
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0008: "GPSSatellites",
    0x0009: "GPSStatus", 0x000A: "GPSMeasureMode", 0x000B: "GPSDOP",
    0x000C: "GPSSpeedRef", 0x000D: "GPSSpeed", 0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection", 0x0012: "GPSMapDatum",
    0x001B: "GPSProcessingMethod", 0x001C: "GPSAreaInformation",
    0x001D: "GPSDateStamp", 0x001E: "GPSDifferential", 0x001F: "GPSHPositioningError",
}
_POINTERS = {0x8769: "ExifIFD", 0x8825: "GPS", 0xA005: "InteropIFD"}
_XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
_EXTENDED_XMP_PREFIX = b"http://ns.adobe.com/xmp/extension/\x00"
_PNG_PIXEL_CHUNKS = {"IHDR", "PLTE", "IDAT", "IEND", "acTL", "fcTL", "fdAT"}


class _MetadataError(ValueError):
    """Malformed metadata, separate from image-container validation."""


@dataclass
class _Budget:
    text_bytes: int = 0
    tags: int = 0

    def text(self, raw: bytes, encoding: str, warnings: list[str]) -> str:
        limit = min(MAX_FIELD_BYTES, MAX_TEXT_BYTES - self.text_bytes)
        if len(raw) > limit:
            warnings.append("Text truncated by the per-field or aggregate byte limit.")
        selected = raw[:limit]
        self.text_bytes += len(selected)
        try:
            return selected.decode(encoding)
        except UnicodeDecodeError:
            warnings.append("Invalid text encoding replaced in the displayed value.")
            return selected.decode(encoding, errors="replace")


def _inflate(raw: bytes, budget: _Budget, warnings: list[str]) -> bytes:
    limit = min(MAX_FIELD_BYTES, MAX_TEXT_BYTES - budget.text_bytes)
    if limit <= 0:
        warnings.append("Compressed text omitted: aggregate decoded-text limit reached.")
        return b""
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(raw, limit + 1)
    except zlib.error as exc:
        raise _MetadataError("Invalid zlib metadata stream.") from exc
    if len(decoded) > limit or decoder.unconsumed_tail:
        warnings.append("Compressed text truncated by the decoded-text byte limit.")
        return decoded[:limit]
    if not decoder.eof:
        warnings.append("Compressed metadata stream is incomplete.")
    if decoder.unused_data:
        warnings.append("Extra bytes follow the compressed metadata stream.")
    return decoded


def _keyword(raw: bytes) -> tuple[bytes, bytes]:
    end = raw.find(b"\x00", 0, 80)
    if end < 1:
        raise _MetadataError("PNG text keyword must contain 1 to 79 bytes and a terminator.")
    return raw[:end], raw[end + 1:]


class _ExifDecoder:
    def __init__(self, raw: bytes, base: int, budget: _Budget, warnings: list[str]):
        self.raw = raw
        self.base = base
        self.budget = budget
        self.warnings = warnings
        self.order = "<"

    def _integer(self, offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(self.raw):
            raise _MetadataError("EXIF offset is outside the metadata block.")
        return int.from_bytes(self.raw[offset:offset + size], "little" if self.order == "<" else "big")

    def _value(self, offset: int, type_id: int, count: int, byte_count: int) -> Any:
        size, code = _TIFF_TYPES[type_id]
        if type_id == 2:
            # Do not copy an attacker-selected huge value before applying the cap.
            limit = min(MAX_FIELD_BYTES, MAX_TEXT_BYTES - self.budget.text_bytes)
            selected = self.raw[offset:offset + min(byte_count, limit)]
            if byte_count > limit:
                self.warnings.append("EXIF ASCII value truncated by the text byte limit.")
            return self.budget.text(selected.rstrip(b"\x00"), "ascii", self.warnings)
        if type_id == 7:
            return {"byte_count": byte_count, "preview_hex": self.raw[offset:offset + min(byte_count, 32)].hex(), "opaque": True}
        if count > MAX_ARRAY_ITEMS:
            self.warnings.append("EXIF array truncated to 32 displayed elements.")
        values = []
        for index in range(min(count, MAX_ARRAY_ITEMS)):
            location = offset + index * size
            if type_id in (5, 10):
                pair_code = "II" if type_id == 5 else "ii"
                numerator, denominator = struct.unpack_from(self.order + pair_code, self.raw, location)
                value: Any = {"numerator": numerator, "denominator": denominator}
                if denominator == 0:
                    self.warnings.append("EXIF rational has a zero denominator; raw values retained.")
            else:
                value = struct.unpack_from(self.order + str(code), self.raw, location)[0]
                if isinstance(value, float) and not math.isfinite(value):
                    value = {"non_finite_float": str(value)}
                    self.warnings.append("Non-finite EXIF floating-point value represented as text.")
            values.append(value)
        return values[0] if count == 1 else values

    def decode(self) -> list[dict[str, Any]]:
        if len(self.raw) < 8 or self.raw[:2] not in (b"II", b"MM"):
            raise _MetadataError("EXIF does not contain a classic TIFF byte-order header.")
        self.order = "<" if self.raw[:2] == b"II" else ">"
        if self._integer(2, 2) != 42:
            raise _MetadataError("Unsupported TIFF header (classic TIFF marker 42 required).")
        pending = [(self._integer(4, 4), "IFD0", 0)]
        visited: set[int] = set()
        result: list[dict[str, Any]] = []
        while pending:
            offset, group, depth = pending.pop(0)
            if offset == 0:
                continue
            if offset < 8:
                self.warnings.append("EXIF IFD points into the TIFF header; directory skipped.")
                continue
            if offset in visited:
                self.warnings.append("Repeated or cyclic EXIF IFD offset skipped.")
                continue
            if len(visited) >= MAX_IFDS or depth > 8:
                self.warnings.append("EXIF IFD traversal limit reached.")
                break
            visited.add(offset)
            try:
                count = self._integer(offset, 2)
                table_end = offset + 2 + 12 * count
                if table_end + 4 > len(self.raw):
                    raise _MetadataError("EXIF IFD entry table is truncated.")
                for index in range(count):
                    if self.budget.tags >= MAX_TAGS:
                        self.warnings.append("EXIF tag limit reached; remaining tags omitted.")
                        return result
                    self.budget.tags += 1
                    entry_offset = offset + 2 + 12 * index
                    tag, type_id, value_count = struct.unpack_from(self.order + "HHI", self.raw, entry_offset)
                    name_table = _GPS_TAGS if group == "GPS" else _TAGS
                    entry: dict[str, Any] = {
                        "group": group, "tag": f"0x{tag:04x}",
                        "name": name_table.get(tag, f"UnknownTag_0x{tag:04x}"),
                        "entry_offset": self.base + entry_offset,
                        "type": type_id, "count": value_count,
                    }
                    result.append(entry)
                    if type_id not in _TIFF_TYPES:
                        entry["status"] = "unsupported_type"
                        self.warnings.append("EXIF tag has an unsupported TIFF data type.")
                        continue
                    byte_count = _TIFF_TYPES[type_id][0] * value_count
                    value_offset = entry_offset + 8 if byte_count <= 4 else self._integer(entry_offset + 8, 4)
                    entry["value_offset"] = self.base + value_offset
                    if value_offset < 0 or value_offset + byte_count > len(self.raw):
                        entry["status"] = "invalid_offset"
                        self.warnings.append("EXIF value extends beyond its metadata block.")
                        continue
                    entry["value"] = self._value(value_offset, type_id, value_count, byte_count)
                    entry["status"] = "decoded" if tag in name_table and type_id != 7 else "raw"
                    if group != "GPS" and tag in _POINTERS:
                        if type_id == 4 and value_count == 1:
                            pending.append((self._integer(value_offset, 4), _POINTERS[tag], depth + 1))
                        else:
                            self.warnings.append("EXIF IFD pointer has an unsupported type or count.")
                    if tag == 0x927C:
                        self.warnings.append("MakerNote is vendor-specific and remains opaque.")
                next_offset = self._integer(table_end, 4)
                if next_offset:
                    pending.append((next_offset, "IFD1" if group == "IFD0" else group + ".next", depth + 1))
            except (struct.error, _MetadataError) as exc:
                self.warnings.append(str(exc))
        return result


def _png_fields(kind: str, raw: bytes, base: int, budget: _Budget, warnings: list[str]) -> Any:
    if kind == "eXIf":
        return _ExifDecoder(raw, base, budget, warnings).decode()
    if kind == "tIME":
        if len(raw) != 7:
            raise _MetadataError("PNG tIME must contain exactly seven bytes.")
        year, month, day, hour, minute, second = struct.unpack(">HBBBBB", raw)
        try:
            dt.datetime(year, month, day, hour, minute, min(second, 59))
        except ValueError as exc:
            raise _MetadataError("PNG tIME contains an invalid date or time.") from exc
        if second > 60:
            raise _MetadataError("PNG tIME contains an invalid seconds value.")
        return {"LastModificationTimeUTC": f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"}
    if kind not in ("tEXt", "zTXt", "iTXt"):
        return None
    keyword, rest = _keyword(raw)
    result = {"keyword": budget.text(keyword, "latin-1", warnings)}
    if kind == "tEXt":
        result["text"] = budget.text(rest, "latin-1", warnings)
    elif kind == "zTXt":
        if not rest or rest[0] != 0:
            raise _MetadataError("Unsupported PNG zTXt compression method.")
        result["text"] = budget.text(_inflate(rest[1:], budget, warnings), "latin-1", warnings)
    else:
        if len(rest) < 2 or rest[0] not in (0, 1) or rest[1] != 0:
            raise _MetadataError("Invalid PNG iTXt compression header.")
        compressed = bool(rest[0])
        fields = rest[2:].split(b"\x00", 2)
        if len(fields) != 3:
            raise _MetadataError("PNG iTXt lacks language or translated-keyword separators.")
        language, translated, text = fields
        result["language"] = budget.text(language, "ascii", warnings)
        result["translated_keyword"] = budget.text(translated, "utf-8", warnings)
        if compressed:
            text = _inflate(text, budget, warnings)
        result["text"] = budget.text(text, "utf-8", warnings)
    return result


def _is_metadata_part(format_name: str, kind: str) -> bool:
    if format_name == "JPEG":
        return kind.startswith("APP") or kind == "COM"
    return kind not in _PNG_PIXEL_CHUNKS and bool(kind) and kind[0].islower()


def metadata_report(data: bytes, structure: Any) -> dict[str, Any]:
    """Return JSON-safe metadata inventory and bounded, best-effort values.

    Container integrity belongs to ``parse_image``. Malformed EXIF/text metadata
    is reported with warnings rather than silently considered absent.
    """
    budget = _Budget()
    parts = [part for part in structure.parts if _is_metadata_part(structure.format, part.kind)]
    entries: list[dict[str, Any]] = []
    global_warnings = []
    if len(parts) > MAX_METADATA_PARTS:
        global_warnings.append("Metadata-part display limit reached; later parts are not decoded.")
    for part in parts[:MAX_METADATA_PARTS]:
        warnings: list[str] = []
        raw = data[part.data_start:part.data_end]
        entry: dict[str, Any] = {
            "kind": part.kind, "offset": part.start, "length": part.end - part.start,
            "payload_offset": part.data_start, "payload_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "removable": part.removable, "status": "opaque", "fields": None,
        }
        try:
            fields: Any = None
            if structure.format == "PNG":
                fields = _png_fields(part.kind, raw, part.data_start, budget, warnings)
            elif part.kind == "APP1" and raw.startswith(b"Exif\x00\x00"):
                fields = _ExifDecoder(raw[6:], part.data_start + 6, budget, warnings).decode()
            elif part.kind == "APP1" and raw.startswith(_XMP_PREFIX):
                fields = {"xmp_text": budget.text(raw[len(_XMP_PREFIX):], "utf-8", warnings)}
                warnings.append("XMP is displayed as raw text; XML is not parsed or expanded.")
            elif part.kind == "APP1" and raw.startswith(_EXTENDED_XMP_PREFIX):
                warnings.append("Extended XMP segments are inventoried but not reassembled.")
            elif part.kind == "COM":
                fields = {"comment": budget.text(raw, "utf-8", warnings)}
                warnings.append("JPEG comment encoding is not guaranteed; UTF-8 display is best-effort.")
            entry["fields"] = fields
            if fields is not None:
                entry["status"] = "partial" if warnings else "decoded"
        except (_MetadataError, struct.error) as exc:
            warnings.append(str(exc))
            entry["status"] = "malformed"
        entry["warnings"] = list(dict.fromkeys(warnings))[:128]
        entries.append(entry)
    return {
        "entries": entries,
        "metadata_parts": len(parts),
        "metadata_payload_bytes": sum(part.data_end - part.data_start for part in parts),
        "metadata_region_bytes": sum(part.end - part.start for part in parts),
        "decoded_text_bytes": budget.text_bytes,
        "decoded_exif_tags": budget.tags,
        "warnings": global_warnings,
        "limitations": [
            "Best-effort values only; proprietary metadata and unsupported types may remain opaque.",
            "Inventory includes JPEG application markers or PNG ancillary information, including retained display-related metadata.",
            "EXIF timestamps are raw values; they do not establish acquisition time or provenance.",
            "Embedded image thumbnails and pixel steganography are not decoded by this metadata reader.",
        ],
    }
