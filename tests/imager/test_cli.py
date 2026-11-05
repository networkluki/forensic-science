"""CLI integration tests run on Windows and Linux without external dependencies."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from networkluki_imager.cli import main
from networkluki_imager.storage import read_checked, validate_windows_path, write_new
from test_core import sample_png


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "image [test].png"
        self.original = sample_png(trailer=b"PK\x03\x04synthetic")
        self.source.write_bytes(self.original)

    def run_cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main([str(item) for item in args])
        return status, output.getvalue(), errors.getvalue()

    def test_inspect_metadata_and_scan(self):
        for command in ("inspect", "metadata", "scan"):
            with self.subTest(command=command):
                status, output, error = self.run_cli(command, self.source)
                self.assertEqual((status, error), (0, ""))
                report = json.loads(output)
                self.assertEqual(report["format"], "PNG")
                self.assertEqual(self.source.read_bytes(), self.original)

    def test_strip_restore_and_source_preservation(self):
        cleaned, backup, restored = (self.root / name for name in ("clean.png", "backup.json", "restored.png"))
        status, _, error = self.run_cli("strip", self.source, "--output", cleaned, "--backup", backup, "--drop-trailing")
        self.assertEqual((status, error), (0, ""))
        self.assertEqual(self.source.read_bytes(), self.original)
        status, _, error = self.run_cli("restore", cleaned, "--backup", backup, "--output", restored)
        self.assertEqual((status, error), (0, ""))
        self.assertEqual(restored.read_bytes(), self.original)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_strip_requires_backup_and_dry_run_creates_nothing(self):
        target = self.root / "clean.png"
        status, _, _ = self.run_cli("strip", self.source, "--output", target)
        self.assertEqual(status, 1)
        before = set(self.root.iterdir())
        status, output, _ = self.run_cli("strip", self.source, "--dry-run")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["status"], "dry_run")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_existing_output_or_backup_is_never_overwritten(self):
        for occupied in ("clean.png", "backup.json"):
            with self.subTest(occupied=occupied):
                target = self.root / occupied
                target.write_bytes(b"keep")
                status, _, _ = self.run_cli("strip", self.source, "--output", self.root / "clean.png", "--backup", self.root / "backup.json")
                self.assertEqual(status, 1)
                self.assertEqual(target.read_bytes(), b"keep")
                target.unlink()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_output_cannot_replace_input_or_backup(self):
        for output, backup in ((self.source, self.root / "b.json"), (self.root / "same", self.root / "same")):
            status, _, _ = self.run_cli("strip", self.source, "--output", output, "--backup", backup)
            self.assertEqual(status, 1)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_metadata_export_exclusive(self):
        output = self.root / "metadata.json"
        self.assertEqual(self.run_cli("metadata", self.source, "--output", output)[0], 0)
        self.assertIn("metadata", json.loads(output.read_bytes()))
        saved = output.read_bytes()
        self.assertEqual(self.run_cli("metadata", self.source, "--output", output)[0], 1)
        self.assertEqual(output.read_bytes(), saved)

    def test_extract_trailing_or_explicit_range(self):
        trailer = self.root / "payload.bin"
        self.assertEqual(self.run_cli("extract", self.source, "--trailing", "--output", trailer)[0], 0)
        self.assertEqual(trailer.read_bytes(), b"PK\x03\x04synthetic")
        header = self.root / "header.bin"
        self.assertEqual(self.run_cli("extract", self.source, "--offset", 0, "--length", 8, "--output", header)[0], 0)
        self.assertEqual(header.read_bytes(), self.original[:8])

    def test_invalid_extract_range_and_extension(self):
        for extra in (("--offset", "-1", "--length", "2"), ("--offset", "0"),
                      ("--offset", "1", "--length", "999999"), ("--trailing", "--length", "1")):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_cli("extract", self.source, *extra, "--output", self.root / "bad.bin")[0], 1)
        self.assertEqual(self.run_cli("extract", self.source, "--trailing", "--output", self.root / "bad.exe")[0], 1)
        self.assertFalse((self.root / "bad.bin").exists())

    def test_unknown_format_and_directory_rejected(self):
        bad = self.root / "fake.png"
        bad.write_bytes(b"MZnot_an_image")
        for path in (bad, self.root):
            self.assertEqual(self.run_cli("inspect", path)[0], 1)

    def test_input_size_limit(self):
        with self.assertRaises(ValueError):
            read_checked(self.source, limit=8)

    def test_windows_special_path_rejection_on_all_platforms(self):
        paths = [r"C:\Analysis\image.png:payload.bin", r"relative:stream", r"C:\NUL.png",
                 r"C:\CON", r"C:\COM1.txt", r"C:\LPT².txt", r"C:\NUL .txt",
                 r"\\.\PhysicalDrive0", r"\\?\C:\Analysis\image.png",
                 r"\\server\share\image.png", "C:\\Analysis\\trailing. ", r"C:image.png"]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_windows_path(path)
        for path in (r"C:\Analysis\photo [1].png", "photo.png", r".\photo.png", r"..\photo.png"):
            validate_windows_path(path)

    def test_handled_write_error_removes_own_partial_file(self):
        target = self.root / "failed.bin"
        with patch("networkluki_imager.storage.os.fsync", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                write_new(target, b"synthetic")
        self.assertFalse(target.exists())

    def test_link_input_and_output_rejected(self):
        link = self.root / "link.png"
        try:
            link.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic link creation unavailable for this account")
        self.assertEqual(self.run_cli("inspect", link)[0], 1)
        with self.assertRaises(FileExistsError):
            write_new(link, b"replacement")
        self.assertEqual(self.source.read_bytes(), self.original)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_fifo_input_rejected_without_opening(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            read_checked(fifo)
