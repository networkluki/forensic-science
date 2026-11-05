"""Container tests use synthetic framing, not real evidence or decoder claims."""

import struct
import unittest
from unittest.mock import patch
import zlib

from networkluki_imager.formats import ImageError, PNG_SIGNATURE, parse_image


def chunk(kind, payload=b""):
    kind = kind.encode("ascii")
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def png(*extra, color=2, depth=8):
    header = chunk("IHDR", struct.pack(">IIBBBBB", 1, 1, depth, color, 0, 0, 0))
    return PNG_SIGNATURE + header + b"".join(extra) + chunk("IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk("IEND")


def segment(marker, payload):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def jpeg(extra=b"", entropy=b"\x3f", progressive=False):
    frame = segment(0xC2 if progressive else 0xC0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
    scan = segment(0xDA, b"\x01\x01\x00\x00" + (b"\x00" if progressive else b"\x3f") + b"\x00")
    return b"\xff\xd8" + extra + frame + scan + entropy + b"\xff\xd9"


class PngTests(unittest.TestCase):
    def test_basic_dimensions_and_end(self):
        data = png()
        parsed = parse_image(data)
        self.assertEqual((parsed.format, parsed.width, parsed.height, parsed.image_end), ("PNG", 1, 1, len(data)))
        self.assertEqual([part.kind for part in parsed.parts], ["IHDR", "IDAT", "IEND"])

    def test_metadata_payload_offsets(self):
        payload = b"Author\x00Synthetic"
        data = png(chunk("tEXt", payload), chunk("eXIf", b"II*\x00"))
        parsed = parse_image(data)
        metadata = [part for part in parsed.parts if part.removable]
        self.assertEqual([part.kind for part in metadata], ["tEXt", "eXIf"])
        self.assertEqual(data[metadata[0].data_start:metadata[0].data_end], payload)
        stripped = b"".join(data[i:j] for i, j in [(0, metadata[0].start), (metadata[0].end, metadata[1].start), (metadata[1].end, len(data))])
        self.assertEqual(stripped, png())
        self.assertEqual(parse_image(stripped).width, 1)

    def test_trailing_data(self):
        image = png()
        result = parse_image(image + b"PK\x03\x04payload")
        self.assertEqual(result.image_end, len(image))
        self.assertTrue(any("trailing bytes" in warning for warning in result.warnings))

    def test_crc_failure(self):
        data = bytearray(png())
        data[29] ^= 1
        with self.assertRaisesRegex(ImageError, "CRC"):
            parse_image(bytes(data))

    def test_unknown_critical_rejected_ancillary_retained(self):
        with self.assertRaisesRegex(ImageError, "critical"):
            parse_image(png(chunk("ABCD", b"opaque")))
        parsed = parse_image(png(chunk("abCD", b"opaque")))
        self.assertFalse(parsed.parts[1].removable)
        self.assertTrue(any("Unknown ancillary" in warning for warning in parsed.warnings))

    def test_invalid_reserved_chunk_bit(self):
        with self.assertRaisesRegex(ImageError, "reserved"):
            parse_image(png(chunk("abcd")))

    def test_invalid_ihdr(self):
        with self.assertRaisesRegex(ImageError, "bit depth"):
            parse_image(png(color=2, depth=1))
        malformed = PNG_SIGNATURE + chunk("IHDR", struct.pack(">IIBBBBB", 0, 1, 8, 2, 0, 0, 0))
        with self.assertRaisesRegex(ImageError, "dimensions"):
            parse_image(malformed)

    def test_palette_requirement(self):
        with self.assertRaisesRegex(ImageError, "requires PLTE"):
            parse_image(png(color=3))
        self.assertEqual(parse_image(png(chunk("PLTE", b"\x00\x00\x00"), color=3)).width, 1)
        with self.assertRaisesRegex(ImageError, "PLTE"):
            parse_image(png(chunk("PLTE", b"\x00\x00")))

    def test_nonconsecutive_idat_rejected(self):
        with self.assertRaisesRegex(ImageError, "consecutive"):
            parse_image(png(chunk("IDAT", b"x"), chunk("tEXt", b"K\x00V")))

    def test_missing_or_invalid_end(self):
        with self.assertRaisesRegex(ImageError, "IEND"):
            parse_image(png()[:-12])
        with self.assertRaisesRegex(ImageError, "IEND"):
            parse_image(png()[:-12] + chunk("IEND", b"x"))

    def test_truncation_and_part_limit(self):
        with self.assertRaises(ImageError):
            parse_image(png()[:-2])
        with patch("networkluki_imager.formats.MAX_PARTS", 2):
            with self.assertRaisesRegex(ImageError, "part inspection limit"):
                parse_image(png())


class JpegTests(unittest.TestCase):
    def test_baseline_framing(self):
        data = jpeg()
        result = parse_image(data)
        self.assertEqual((result.format, result.width, result.height, result.image_end), ("JPEG", 1, 1, len(data)))
        self.assertEqual([part.kind for part in result.parts], ["SOI", "SOF0", "SOS", "SCAN_DATA", "EOI"])

    def test_removal_policy_and_offsets(self):
        extra = segment(0xE0, b"JFIF\x00") + segment(0xE1, b"Exif\x00\x00") + segment(0xE2, b"ICC_PROFILE\x00") + segment(0xED, b"Photoshop") + segment(0xEE, b"Adobe") + segment(0xFE, b"comment")
        data = jpeg(extra)
        parsed = parse_image(data)
        metadata = [part for part in parsed.parts if part.removable]
        self.assertEqual([part.kind for part in metadata], ["APP1", "APP13", "COM"])
        self.assertEqual(data[metadata[0].data_start:metadata[0].data_end], b"Exif\x00\x00")
        chunks = []
        pos = 0
        for part in metadata:
            chunks.append(data[pos:part.start])
            pos = part.end
        chunks.append(data[pos:])
        stripped = b"".join(chunks)
        self.assertFalse(any(part.removable for part in parse_image(stripped).parts))
        self.assertIn(b"ICC_PROFILE", stripped)
        self.assertIn(b"Adobe", stripped)

    def test_entropy_stuffing_restart_and_marker_fill(self):
        result = parse_image(jpeg(entropy=b"\x01\xff\x00\x02\xff\xd0\x03\xff\xff\xd1\x04"))
        self.assertEqual(result.parts[-2].kind, "SCAN_DATA")

    def test_progressive_multiple_scans(self):
        first = jpeg(progressive=True)[:-2]
        second_scan = segment(0xDA, b"\x01\x01\x00\x01\x3f\x00")
        data = first + segment(0xFE, b"between scans") + second_scan + b"\x35" + b"\xff\xd9"
        result = parse_image(data)
        self.assertEqual(sum(part.kind == "SOS" for part in result.parts), 2)
        self.assertTrue(next(part for part in result.parts if part.kind == "COM").removable)

    def test_embedded_eoi_inside_metadata_is_not_end(self):
        data = jpeg(segment(0xE1, b"Exif\x00\x00\xff\xd9"))
        self.assertEqual(parse_image(data).image_end, len(data))

    def test_trailing_data_and_missing_end(self):
        data = jpeg()
        self.assertEqual(parse_image(data + b"trailing").image_end, len(data))
        with self.assertRaises(ImageError):
            parse_image(data[:-2])

    def test_segment_length_and_invalid_scan(self):
        with self.assertRaisesRegex(ImageError, "segment"):
            parse_image(b"\xff\xd8\xff\xe1\x00\x01")
        with self.assertRaisesRegex(ImageError, "frame or scan"):
            parse_image(b"\xff\xd8\xff\xd9")
        data = jpeg().replace(b"\x01\x01\x00\x00\x3f\x00", b"\x01\x02\x00\x00\x3f\x00")
        with self.assertRaisesRegex(ImageError, "component"):
            parse_image(data)

    def test_zero_dimensions_and_missing_frame(self):
        data = jpeg().replace(b"\x08\x00\x01\x00\x01", b"\x08\x00\x00\x00\x01")
        with self.assertRaisesRegex(ImageError, "dimensions"):
            parse_image(data)
        with self.assertRaisesRegex(ImageError, "precedes"):
            parse_image(b"\xff\xd8" + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00"))

    def test_invalid_stuffing(self):
        with self.assertRaisesRegex(ImageError, "stuffing"):
            parse_image(jpeg(entropy=b"\x01\xff\xff\x00\x02"))

    def test_part_limit(self):
        with patch("networkluki_imager.formats.MAX_PARTS", 3):
            with self.assertRaisesRegex(ImageError, "part inspection limit"):
                parse_image(jpeg())

    def test_unknown_format(self):
        with self.assertRaisesRegex(ImageError, "Unsupported image"):
            parse_image(b"GIF89a")


if __name__ == "__main__":
    unittest.main()
