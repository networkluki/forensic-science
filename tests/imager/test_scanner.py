"""Synthetic tests for bounded signature triage without decoding images."""

import unittest
from types import SimpleNamespace

from networkluki_imager.scanner import MAX_FINDINGS, scan_report


PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"


def structure(data, *, image_end=None, parts=(), image_format="PNG"):
    return SimpleNamespace(
        format=image_format,
        image_end=len(data) if image_end is None else image_end,
        parts=list(parts),
    )


def part(kind, start, end, *, removable=False):
    return SimpleNamespace(
        kind=kind,
        start=start,
        end=end,
        data_start=start,
        data_end=end,
        removable=removable,
    )


class ScannerTests(unittest.TestCase):
    def test_primary_signature_is_not_an_embedded_file(self):
        for magic, image_format in ((PNG, "PNG"), (JPEG, "JPEG")):
            with self.subTest(image_format=image_format):
                data = magic + b"safe bytes"
                report = scan_report(data, structure(data, image_format=image_format))
                self.assertEqual(report["candidates"], [])
                self.assertEqual(report["candidate_count"], 0)
                self.assertFalse(report["truncated"])
                self.assertIsNone(report["appended_range"])

    def test_appended_zip_and_pdf_are_unverified_candidates(self):
        data = PNG + b"image bytes" + b"PK\x03\x04archive%PDF-1.7"
        end = len(PNG + b"image bytes")
        report = scan_report(data, structure(data, image_end=end))
        self.assertEqual(report["appended_range"], {"offset": end, "length": len(data) - end})
        self.assertEqual([c["kind"] for c in report["candidates"]], ["ZIP local header", "PDF"])
        for candidate in report["candidates"]:
            self.assertEqual(candidate["region"], "trailing")
            self.assertEqual(candidate["confidence"], "signature_only")
            self.assertIsNone(candidate["length"])

    def test_unsigned_trailing_bytes_are_reported(self):
        data = PNG + b"extra data"
        report = scan_report(data, structure(data, image_end=len(PNG)))
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["appended_range"]["length"], 10)

    def test_metadata_thumbnail_is_not_claimed_to_be_malicious(self):
        data = JPEG + b"Exif\0\0" + JPEG + b"thumbnail"
        metadata = part("APP1", 3, len(data), removable=True)
        report = scan_report(data, structure(data, parts=[metadata], image_format="JPEG"))
        self.assertEqual(len(report["candidates"]), 1)
        self.assertEqual(report["candidates"][0]["offset"], 9)
        self.assertEqual(report["candidates"][0]["region"], "metadata")
        self.assertTrue(any("thumbnails" in text for text in report["limitations"]))

    def test_pixel_signature_has_image_data_region(self):
        data = PNG + b"pixelsMZpixels"
        image_data = part("IDAT", len(PNG), len(data))
        candidate = scan_report(data, structure(data, parts=[image_data]))["candidates"][0]
        self.assertEqual(candidate["kind"], "DOS/PE MZ candidate")
        self.assertEqual(candidate["region"], "image_data")

    def test_structural_bytes_are_container_region(self):
        data = PNG + b"MZ"
        report = scan_report(data, structure(data))
        self.assertEqual(report["candidates"][0]["region"], "container")

    def test_jpeg_entropy_signature_has_image_data_region(self):
        data = JPEG + b"entropyMZentropy"
        scan_data = part("SCAN_DATA", len(JPEG), len(data))
        report = scan_report(data, structure(data, parts=[scan_data], image_format="JPEG"))
        self.assertEqual(report["candidates"][0]["region"], "image_data")

    def test_global_limit_and_ordering(self):
        data = PNG + (b"%PDF-MZPK\x03\x04" * 1000)
        report = scan_report(data, structure(data))
        self.assertEqual(report["candidate_count"], MAX_FINDINGS)
        self.assertTrue(report["truncated"])
        offsets = [candidate["offset"] for candidate in report["candidates"]]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(report["candidates"][0]["kind"], "PDF")

    def test_exactly_limit_findings_is_not_truncated(self):
        data = PNG + b"MZ." * MAX_FINDINGS
        report = scan_report(data, structure(data))
        self.assertEqual(report["candidate_count"], MAX_FINDINGS)
        self.assertFalse(report["truncated"])

    def test_all_documented_magic_prefixes(self):
        signatures = [
            b"PK\x03\x04", b"PK\x05\x06", b"%PDF-", b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00", b"\x1f\x8b\x08",
            b"\x7fELF", b"MZ", JPEG, PNG,
        ]
        data = PNG + b"\0".join(signatures)
        report = scan_report(data, structure(data, image_end=len(PNG)))
        self.assertEqual(report["candidate_count"], len(signatures))
        self.assertTrue(all(c["region"] == "trailing" for c in report["candidates"]))

    def test_invalid_image_end_is_rejected(self):
        for image_end in (-1, 20, True, None):
            with self.subTest(image_end=image_end):
                invalid = SimpleNamespace(format="PNG", image_end=image_end, parts=[])
                with self.assertRaises(ValueError):
                    scan_report(PNG, invalid)


if __name__ == "__main__":
    unittest.main()
