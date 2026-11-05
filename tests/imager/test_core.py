"""Synthetic round trips and adversarial backup validation."""

import base64
import copy
import json
import struct
import unittest
import zlib

from networkluki_imager.core import json_bytes, restore_bytes, sha256, strip_bytes
from networkluki_imager.formats import parse_image


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def sample_png(*, metadata=True, trailer=b""):
    header = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    text = chunk(b"tEXt", b"Artist\0Synthetic Test") if metadata else b""
    pixels = chunk(b"IDAT", zlib.compress(b"\0\xff\0\0"))
    timestamp = chunk(b"tIME", struct.pack(">HBBBBB", 2026, 11, 5, 12, 30, 0)) if metadata else b""
    return header + text + pixels + timestamp + chunk(b"IEND", b"") + trailer


def segment(marker, payload):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def sample_jpeg():
    # Minimal framing fixture; compressed pixels deliberately not validated.
    return (b"\xff\xd8" + segment(0xE1, b"Exif\0\0opaque") + segment(0xE2, b"ICC_PROFILE\0keep")
            + segment(0xFE, b"Synthetic comment")
            + segment(0xC0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
            + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x23\xff\x00\x67\xff\xd9")


class RoundTripTests(unittest.TestCase):
    def test_png_exact_round_trip(self):
        original = sample_png()
        cleaned, backup = strip_bytes(original)
        self.assertEqual(cleaned, sample_png(metadata=False))
        self.assertEqual(restore_bytes(cleaned, json_bytes(backup)), original)

    def test_jpeg_exact_round_trip_and_retained_profile(self):
        original = sample_jpeg()
        cleaned, backup = strip_bytes(original)
        self.assertIn(b"ICC_PROFILE", cleaned)
        self.assertNotIn(b"Synthetic comment", cleaned)
        self.assertNotIn(b"Exif\0", cleaned)
        self.assertEqual(restore_bytes(cleaned, json_bytes(backup)), original)

    def test_trailer_preserved_by_default(self):
        original = sample_png(trailer=b"PK\x03\x04private")
        cleaned, backup = strip_bytes(original)
        self.assertTrue(cleaned.endswith(b"PK\x03\x04private"))
        self.assertEqual(restore_bytes(cleaned, json_bytes(backup)), original)

    def test_optional_trailer_removal_is_reversible(self):
        original = sample_png(trailer=b"PK\x03\x04private")
        cleaned, backup = strip_bytes(original, drop_trailing=True)
        self.assertEqual(len(cleaned), parse_image(cleaned).image_end)
        self.assertEqual(restore_bytes(cleaned, json_bytes(backup)), original)

    def test_no_metadata_round_trip(self):
        original = sample_png(metadata=False)
        cleaned, backup = strip_bytes(original)
        self.assertEqual(backup["patches"], [])
        self.assertEqual(restore_bytes(cleaned, json_bytes(backup)), original)

    def test_mismatched_cleaned_image_rejected(self):
        cleaned, backup = strip_bytes(sample_png())
        with self.assertRaisesRegex(ValueError, "does not match"):
            restore_bytes(cleaned + b"changed", json_bytes(backup))

    def test_mutated_backup_fields_rejected(self):
        cleaned, backup = strip_bytes(sample_png())
        cases = [
            ("schema", "unknown"), ("original_size", True), ("original_size", -1),
            ("original_sha256", "0" * 64), ("cleaned_sha256", "invalid"),
            ("format", "WEBP"), ("patches", None), ("patches", [{}]),
            ("tool_version", float("nan")), ("created_utc", []),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(backup)
                bad[field] = value
                with self.assertRaises(ValueError):
                    restore_bytes(cleaned, json.dumps(bad).encode())

    def test_invalid_patch_offsets_and_payloads(self):
        cleaned, backup = strip_bytes(sample_png())
        for field, value in [("offset", -1), ("offset", True), ("offset", 999999),
                             ("data_base64", "!not base64!"), ("data_base64", ""),
                             ("data_base64", base64.b64encode(b"forged").decode())]:
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(backup)
                bad["patches"][0][field] = value
                with self.assertRaises(ValueError):
                    restore_bytes(cleaned, json_bytes(bad))

    def test_duplicate_or_overlapping_patches_rejected(self):
        cleaned, backup = strip_bytes(sample_png())
        backup["patches"].insert(1, backup["patches"][0])
        with self.assertRaises(ValueError):
            restore_bytes(cleaned, json_bytes(backup))

    def test_duplicate_json_keys_rejected(self):
        cleaned, backup = strip_bytes(sample_png())
        raw = json_bytes(backup).rstrip()[:-1] + b', "schema": "duplicate"}'
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            restore_bytes(cleaned, raw)

    def test_deep_or_malformed_json_fails_cleanly(self):
        cleaned, _ = strip_bytes(sample_png())
        for raw in (b"[" * 2000 + b"]" * 2000, b"not json", b"\xff", b"[]"):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                restore_bytes(cleaned, raw)

    def test_structurally_broken_input_rejected(self):
        with self.assertRaises(ValueError):
            strip_bytes(sample_png()[:-1])

    def test_json_escapes_terminal_control_characters(self):
        self.assertNotIn(b"\x1b", json_bytes({"text": "\x1b[31mred"}))
        self.assertEqual(sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
