"""Bounded PNG/JPEG framing inspection; compressed pixels are never decoded.

References: https://www.w3.org/TR/png/ and ITU-T T.81, Annex B.
This is intentionally not a complete conformance validator or image decoder.
"""

from dataclasses import dataclass
import struct
import zlib


MAX_PARTS = 10_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_REMOVABLE = frozenset({"tEXt", "zTXt", "iTXt", "eXIf", "tIME"})
PNG_KNOWN = frozenset({
    "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT",
    "sRGB", "bKGD", "hIST", "pHYs", "sPLT", "tIME", "tEXt", "zTXt", "iTXt",
    "eXIf", "acTL", "fcTL", "fdAT", "cICP", "mDCv", "cLLi",
})
JPEG_SOF = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB})
JPEG_DIFFERENTIAL_SOF = frozenset({0xC5, 0xC6, 0xC7, 0xCD, 0xCE, 0xCF})


class ImageError(ValueError):
    """Unsupported image or invalid container framing."""


@dataclass(frozen=True)
class Part:
    kind: str
    start: int
    end: int
    data_start: int
    data_end: int
    removable: bool


@dataclass(frozen=True)
class ImageStructure:
    format: str
    width: int
    height: int
    parts: list[Part]
    image_end: int
    warnings: list[str]


def parse_image(data: bytes) -> ImageStructure:
    """Inspect a bounded caller-supplied byte snapshot, identified by signature.

    Callers must limit the input file size before loading it into memory. This
    module independently limits framing records and does not decompress data.
    """
    if data.startswith(PNG_SIGNATURE):
        return _parse_png(data)
    if data.startswith(b"\xff\xd8"):
        return _parse_jpeg(data)
    raise ImageError("Unsupported image signature; only PNG and JPEG are supported.")


def _add_part(parts: list[Part], part: Part) -> None:
    if len(parts) >= MAX_PARTS:
        raise ImageError(f"Container exceeds the {MAX_PARTS}-part inspection limit.")
    parts.append(part)


def _warnings(image_end: int, size: int) -> list[str]:
    warnings = [
        "Container framing was inspected; compressed pixel data was not decoded or validated.",
        "Metadata removal targets documented fields only; retained structures and pixels may contain other information.",
    ]
    if image_end < size:
        warnings.append(f"{size - image_end} trailing bytes follow the image end marker.")
    return warnings


def _parse_png(data: bytes) -> ImageStructure:
    parts: list[Part] = []
    pos = len(PNG_SIGNATURE)
    width = height = color = depth = 0
    seen_header = seen_palette = seen_idat = idat_closed = False
    idat_bytes = 0
    notes: set[str] = set()
    while pos < len(data):
        if len(data) - pos < 12:
            raise ImageError(f"Truncated PNG chunk header at offset {pos}.")
        length = struct.unpack_from(">I", data, pos)[0]
        if length > 0x7FFFFFFF:
            raise ImageError("PNG chunk length exceeds the format limit.")
        name = data[pos + 4:pos + 8]
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in name):
            raise ImageError(f"Invalid PNG chunk name at offset {pos}.")
        if name[2] & 0x20:
            raise ImageError(f"PNG reserved chunk-name bit is set at offset {pos}.")
        kind = name.decode("ascii")
        data_start = pos + 8
        data_end = data_start + length
        end = data_end + 4
        if end > len(data):
            raise ImageError(f"Truncated PNG {kind} chunk at offset {pos}.")
        crc = zlib.crc32(memoryview(data)[pos + 4:data_end]) & 0xFFFFFFFF
        if crc != struct.unpack_from(">I", data, data_end)[0]:
            raise ImageError(f"PNG {kind} CRC mismatch at offset {pos}.")
        if not seen_header and kind != "IHDR":
            raise ImageError("PNG IHDR must be the first chunk.")
        if kind not in PNG_KNOWN:
            if not name[0] & 0x20:
                raise ImageError(f"Unsupported critical PNG chunk: {kind}.")
            notes.add(f"Unknown ancillary PNG chunk {kind} is retained.")
        if kind == "IHDR":
            if seen_header or length != 13:
                raise ImageError("PNG must contain one 13-byte IHDR chunk.")
            width, height, depth, color, compression, filtering, interlace = struct.unpack_from(
                ">IIBBBBB", data, data_start
            )
            depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if not (1 <= width <= 0x7FFFFFFF and 1 <= height <= 0x7FFFFFFF):
                raise ImageError("PNG dimensions are outside the format limits.")
            if depth not in depths.get(color, set()):
                raise ImageError("PNG bit depth and color type are incompatible.")
            if compression != 0 or filtering != 0 or interlace not in (0, 1):
                raise ImageError("Unsupported PNG IHDR compression, filter, or interlace method.")
            seen_header = True
        elif kind == "PLTE":
            if seen_palette or seen_idat or color in (0, 4):
                raise ImageError("PNG PLTE is duplicated, misplaced, or forbidden for this color type.")
            if not length or length % 3 or length > 768:
                raise ImageError("PNG PLTE has an invalid length.")
            if color == 3 and length // 3 > 1 << depth:
                raise ImageError("PNG palette exceeds its bit-depth capacity.")
            seen_palette = True
        elif kind == "IDAT":
            if idat_closed:
                raise ImageError("PNG IDAT chunks must be consecutive.")
            if color == 3 and not seen_palette:
                raise ImageError("Indexed-color PNG requires PLTE before IDAT.")
            seen_idat = True
            idat_bytes += length
        elif kind == "IEND":
            if length or not seen_idat or not idat_bytes:
                raise ImageError("PNG requires image data and an empty IEND chunk.")
        if seen_idat and kind != "IDAT":
            idat_closed = True
        if kind in {"acTL", "fcTL", "fdAT"}:
            notes.add("APNG animation chunks are retained; animation semantics are not validated.")
        if kind == "eXIf":
            notes.add("Removing EXIF may change display orientation or other interpretation.")
        _add_part(parts, Part(kind, pos, end, data_start, data_end, kind in PNG_REMOVABLE))
        pos = end
        if kind == "IEND":
            return ImageStructure("PNG", width, height, parts, pos, _warnings(pos, len(data)) + sorted(notes))
    raise ImageError("PNG has no complete IEND chunk.")


def _jpeg_kind(marker: int) -> str:
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    if marker in JPEG_SOF or marker in JPEG_DIFFERENTIAL_SOF:
        return f"SOF{marker - 0xC0}"
    return {0xC4: "DHT", 0xCC: "DAC", 0xDA: "SOS", 0xDB: "DQT", 0xDC: "DNL",
            0xDD: "DRI", 0xDE: "DHP", 0xDF: "EXP", 0xFE: "COM", 0x01: "TEM",
            0xD8: "SOI", 0xD9: "EOI"}.get(marker, f"MARKER_{marker:02X}")


def _read_frame(data: bytes, start: int, end: int, marker: int) -> tuple[int, int, set[int], int]:
    if end - start < 6:
        raise ImageError("Truncated JPEG frame header.")
    precision = data[start]
    height, width = struct.unpack_from(">HH", data, start + 1)
    count = data[start + 5]
    if not width or not height:
        raise ImageError("JPEG zero dimensions or deferred-height DNL images are unsupported.")
    if not count or end - start != 6 + 3 * count:
        raise ImageError("JPEG frame component table has an invalid length.")
    valid_precision = {8} if marker == 0xC0 else (set(range(2, 17)) if marker in {0xC3, 0xCB} else {8, 12})
    if precision not in valid_precision:
        raise ImageError("JPEG frame precision is invalid for the coding mode.")
    components: set[int] = set()
    for offset in range(start + 6, end, 3):
        component, sampling, table = data[offset:offset + 3]
        if component in components or not (1 <= sampling >> 4 <= 4 and 1 <= sampling & 15 <= 4):
            raise ImageError("JPEG frame has duplicate components or invalid sampling factors.")
        if table > 3 or (marker in {0xC3, 0xCB} and table != 0):
            raise ImageError("JPEG frame has an invalid quantization table selector.")
        components.add(component)
    return width, height, components, precision


def _check_scan(data: bytes, start: int, end: int, components: set[int], frame: int, precision: int) -> None:
    if end - start < 4:
        raise ImageError("Truncated JPEG scan header.")
    count = data[start]
    if not 1 <= count <= 4 or count > len(components) or end - start != 4 + 2 * count:
        raise ImageError("JPEG scan component table has an invalid length.")
    seen: set[int] = set()
    limit = 15 if frame in {0xC9, 0xCA, 0xCB} else 3
    for offset in range(start + 1, end - 3, 2):
        component, tables = data[offset:offset + 2]
        if component not in components or component in seen or tables >> 4 > limit or tables & 15 > limit:
            raise ImageError("JPEG scan contains an invalid component or table selector.")
        seen.add(component)
    first, last, approx = data[end - 3:end]
    high, low = approx >> 4, approx & 15
    if frame in {0xC0, 0xC1, 0xC9}:
        valid = (first, last, approx) == (0, 63, 0)
    elif frame in {0xC2, 0xCA}:
        valid = first <= last <= 63 and high <= 13 and low <= 13
        valid = valid and (first != 0 or last == 0) and (first == 0 or count == 1)
        valid = valid and (high == 0 or high == low + 1)
    else:
        valid = 1 <= first <= 7 and last == 0 and high == 0 and low < precision
    if not valid:
        raise ImageError("JPEG scan parameters are invalid for the coding mode.")


def _scan_end(data: bytes, start: int) -> int:
    """Locate a marker while honoring entropy byte stuffing and restart markers."""
    pos = start
    while pos < len(data):
        marker_start = data.find(b"\xff", pos)
        if marker_start < 0:
            raise ImageError("JPEG scan is truncated before its terminating marker.")
        code_pos = marker_start + 1
        while code_pos < len(data) and data[code_pos] == 0xFF:
            code_pos += 1
        if code_pos >= len(data):
            raise ImageError("Truncated JPEG marker in scan data.")
        code = data[code_pos]
        if code == 0:
            if code_pos != marker_start + 1:
                raise ImageError("JPEG entropy data has invalid byte stuffing.")
            pos = code_pos + 1
        elif 0xD0 <= code <= 0xD7 or code == 0x01:
            pos = code_pos + 1
        else:
            return marker_start
    raise ImageError("JPEG scan is truncated.")


def _parse_jpeg(data: bytes) -> ImageStructure:
    parts = [Part("SOI", 0, 2, 2, 2, False)]
    pos = 2
    width = height = frame = precision = 0
    components: set[int] = set()
    saw_scan = False
    notes: set[str] = set()
    while pos < len(data):
        start = pos
        if data[pos] != 0xFF:
            raise ImageError(f"Expected JPEG marker at offset {pos}.")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            raise ImageError("Truncated JPEG marker.")
        marker = data[pos]
        pos += 1
        if marker == 0 or marker == 0xD8 or 0xD0 <= marker <= 0xD7:
            raise ImageError(f"Unexpected JPEG marker 0x{marker:02x} outside scan data.")
        if marker == 0xD9:
            if not components or not saw_scan:
                raise ImageError("JPEG is missing its frame or scan.")
            _add_part(parts, Part("EOI", start, pos, pos, pos, False))
            return ImageStructure("JPEG", width, height, parts, pos, _warnings(pos, len(data)) + sorted(notes))
        if marker == 0x01:
            _add_part(parts, Part("TEM", start, pos, pos, pos, False))
            continue
        if marker in JPEG_DIFFERENTIAL_SOF or marker in {0xDC, 0xDE, 0xDF}:
            raise ImageError("Hierarchical or deferred-height JPEG coding is unsupported.")
        if marker < 0xC0 or marker in {0xC8, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD}:
            raise ImageError(f"Unsupported JPEG extension marker 0x{marker:02x}.")
        if len(data) - pos < 2:
            raise ImageError("Truncated JPEG segment length.")
        length = struct.unpack_from(">H", data, pos)[0]
        if length < 2 or pos + length > len(data):
            raise ImageError(f"Invalid or truncated JPEG segment at offset {start}.")
        payload_start, end = pos + 2, pos + length
        kind = _jpeg_kind(marker)
        if marker in JPEG_SOF:
            if components:
                raise ImageError("Multiple JPEG frames are unsupported.")
            width, height, components, precision = _read_frame(data, payload_start, end, marker)
            frame = marker
        elif marker == 0xDA:
            if not components:
                raise ImageError("JPEG scan precedes the frame header.")
            _check_scan(data, payload_start, end, components, frame, precision)
            saw_scan = True
        elif marker == 0xDD and length != 4:
            raise ImageError("JPEG restart interval segment must have length 4.")
        if marker == 0xE1:
            notes.add("Removing APP1 also removes EXIF orientation and may change displayed orientation.")
        if 0xE0 <= marker <= 0xEF and marker not in {0xE1, 0xED}:
            notes.add("JPEG APP0/APP2/other retained application segments may include profiles, thumbnails, or private data.")
        _add_part(parts, Part(kind, start, end, payload_start, end, marker in {0xE1, 0xED, 0xFE}))
        pos = end
        if marker == 0xDA:
            scan_end = _scan_end(data, pos)
            if scan_end == pos:
                raise ImageError("JPEG scan contains no entropy data.")
            _add_part(parts, Part("SCAN_DATA", pos, scan_end, pos, scan_end, False))
            pos = scan_end
    raise ImageError("JPEG has no complete EOI marker.")
