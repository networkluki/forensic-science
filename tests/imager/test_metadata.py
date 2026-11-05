"""Synthetic, dependency-free tests for bounded metadata decoding."""

import json
import struct
import unittest
import zlib
from types import SimpleNamespace

from networkluki_imager.metadata import MAX_FIELD_BYTES, MAX_TEXT_BYTES, metadata_report


def report(kind, payload, format_name="PNG"):
    part = SimpleNamespace(kind=kind, start=0, end=len(payload), data_start=0,
                           data_end=len(payload), removable=True)
    return metadata_report(payload, SimpleNamespace(format=format_name, parts=[part]))


def exif_fixture():
    """Classic little-endian TIFF with Make, Model and a GPS IFD."""
    header = b"II" + struct.pack("<HI", 42, 8)
    table_size = 2 + 3 * 12 + 4
    make_offset = len(header) + table_size
    model_offset = make_offset + 6
    gps_offset = model_offset + 6
    gps_values_offset = gps_offset + 2 + 2 * 12 + 4
    entries = struct.pack("<H", 3)
    entries += struct.pack("<HHII", 0x010F, 2, 6, make_offset)
    entries += struct.pack("<HHII", 0x0110, 2, 6, model_offset)
    entries += struct.pack("<HHII", 0x8825, 4, 1, gps_offset)
    entries += struct.pack("<I", 0)
    gps = struct.pack("<H", 2)
    gps += struct.pack("<HHI", 1, 2, 2) + b"N\x00\x00\x00"
    gps += struct.pack("<HHII", 2, 5, 3, gps_values_offset)
    gps += struct.pack("<I", 0)
    gps += struct.pack("<IIIIII", 59, 1, 20, 1, 30, 1)
    return header + entries + b"Maker\x00Model\x00" + gps


class MetadataTests(unittest.TestCase):
    def test_png_plain_text(self):
        entry = report("tEXt", b"Author\x00Synthetic tester")["entries"][0]
        self.assertEqual(entry["fields"], {"keyword": "Author", "text": "Synthetic tester"})
        self.assertEqual(entry["status"], "decoded")

    def test_png_compressed_text(self):
        entry = report("zTXt", b"Note\x00\x00" + zlib.compress(b"hello"))["entries"][0]
        self.assertEqual(entry["fields"]["text"], "hello")

    def test_png_international_text(self):
        payload = b"Title\x00\x01\x00sv\x00Titel\x00" + zlib.compress("Hälsning".encode())
        entry = report("iTXt", payload)["entries"][0]
        self.assertEqual(entry["fields"]["text"], "Hälsning")
        self.assertEqual(entry["fields"]["language"], "sv")

    def test_png_compression_bomb_is_capped(self):
        payload = b"Note\x00\x00" + zlib.compress(b"A" * (MAX_FIELD_BYTES * 100))
        result = report("zTXt", payload)
        entry = result["entries"][0]
        self.assertLessEqual(len(entry["fields"]["text"]), MAX_FIELD_BYTES)
        self.assertTrue(any("truncated" in warning for warning in entry["warnings"]))

    def test_aggregate_text_limit(self):
        payload = b"Note\x00" + b"A" * MAX_FIELD_BYTES
        data = payload * 20
        parts = [SimpleNamespace(kind="tEXt", start=i * len(payload), end=(i + 1) * len(payload),
                                 data_start=i * len(payload), data_end=(i + 1) * len(payload),
                                 removable=True) for i in range(20)]
        result = metadata_report(data, SimpleNamespace(format="PNG", parts=parts))
        self.assertLessEqual(result["decoded_text_bytes"], MAX_TEXT_BYTES)
        self.assertTrue(result["entries"][-1]["warnings"])

    def test_invalid_compression_and_truncation_reported(self):
        bad = report("zTXt", b"Note\x00\x00not-zlib")["entries"][0]
        self.assertEqual(bad["status"], "malformed")
        incomplete = report("zTXt", b"Note\x00\x00" + zlib.compress(b"hello")[:-2])["entries"][0]
        self.assertEqual(incomplete["status"], "partial")

    def test_exif_make_model_and_gps(self):
        result = report("APP1", b"Exif\x00\x00" + exif_fixture(), "JPEG")
        fields = result["entries"][0]["fields"]
        by_name = {field["name"]: field for field in fields}
        self.assertEqual(by_name["Make"]["value"], "Maker")
        self.assertEqual(by_name["Model"]["value"], "Model")
        self.assertEqual(by_name["GPSLatitudeRef"]["value"], "N")
        self.assertEqual(by_name["GPSLatitude"]["value"][0], {"numerator": 59, "denominator": 1})
        self.assertEqual(by_name["GPSLatitude"]["group"], "GPS")

    def test_png_exif_has_no_jpeg_prefix(self):
        entry = report("eXIf", exif_fixture())["entries"][0]
        self.assertEqual(entry["fields"][0]["name"], "Make")

    def test_big_endian_tiff(self):
        payload = b"MM" + struct.pack(">HIH", 42, 8, 1)
        payload += struct.pack(">HHI", 0x0112, 3, 1) + struct.pack(">H", 6) + b"\x00\x00" + b"\x00" * 4
        entry = report("eXIf", payload)["entries"][0]
        self.assertEqual(entry["fields"][0]["value"], 6)

    def test_cyclic_ifd(self):
        payload = b"II" + struct.pack("<HIHI", 42, 8, 0, 8)
        entry = report("eXIf", payload)["entries"][0]
        self.assertTrue(any("cyclic" in warning for warning in entry["warnings"]))

    def test_bad_offset_and_truncated_ifd(self):
        for payload in (b"II" + struct.pack("<HI", 42, 999),
                        b"II" + struct.pack("<HIH", 42, 8, 100)):
            entry = report("eXIf", payload)["entries"][0]
            self.assertTrue(entry["warnings"])
        payload = b"II" + struct.pack("<HIH", 42, 8, 1)
        payload += struct.pack("<HHII", 0x010F, 2, 100, 999) + b"\x00" * 4
        entry = report("eXIf", payload)["entries"][0]
        self.assertEqual(entry["fields"][0]["status"], "invalid_offset")

    def test_invalid_tiff_header(self):
        entry = report("eXIf", b"not TIFF")["entries"][0]
        self.assertEqual(entry["status"], "malformed")

    def test_nonfinite_float_is_json_safe(self):
        payload = b"II" + struct.pack("<HIH", 42, 8, 1)
        payload += struct.pack("<HHI", 0x9999, 11, 1) + struct.pack("<f", float("nan")) + b"\x00" * 4
        result = report("eXIf", payload)
        json.dumps(result, allow_nan=False)
        self.assertIn("non_finite_float", result["entries"][0]["fields"][0]["value"])

    def test_xmp_is_not_expanded(self):
        xml = b'<!DOCTYPE x [<!ENTITY test SYSTEM "file:///etc/passwd">]><x>&test;</x>'
        entry = report("APP1", b"http://ns.adobe.com/xap/1.0/\x00" + xml, "JPEG")["entries"][0]
        self.assertEqual(entry["fields"]["xmp_text"], xml.decode())

    def test_png_time(self):
        entry = report("tIME", struct.pack(">HBBBBB", 2026, 11, 5, 10, 20, 30))["entries"][0]
        self.assertEqual(entry["fields"]["LastModificationTimeUTC"], "2026-11-05T10:20:30Z")
        bad = report("tIME", struct.pack(">HBBBBB", 2026, 2, 31, 10, 20, 30))["entries"][0]
        self.assertEqual(bad["status"], "malformed")

    def test_app13_is_inventoried_not_fabricated(self):
        entry = report("APP13", b"Photoshop fake private bytes", "JPEG")["entries"][0]
        self.assertEqual(entry["status"], "opaque")
        self.assertIsNone(entry["fields"])
        self.assertEqual(len(entry["payload_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
