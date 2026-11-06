"""Synthetic regression tests shared by Windows and Linux CI."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'tools/file-integrity/file_integrity.py'
spec = importlib.util.spec_from_file_location('integrity', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'a.txt').write_bytes(b'abc')
        self.manifest = self.base / 'manifest.json'

    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, timeout=15)

    def create(self):
        result = self.cli('create', self.root, '--output', self.manifest)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deterministic_known_hash_and_unicode(self):
        (self.root / 'space å.txt').write_bytes(b'')
        (self.root / 'sub').mkdir()
        (self.root / 'sub' / 'z').write_bytes(bytes(range(256)))
        self.create()
        second = self.base / 'second.json'
        self.assertEqual(self.cli('create', self.root, '--output', second).returncode, 0)
        self.assertEqual(self.manifest.read_bytes(), second.read_bytes())
        entries = json.loads(second.read_bytes())['files']
        self.assertEqual(entries[0]['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(self.cli('verify', second, '--root', self.root).returncode, 0)
        self.assertEqual((self.root / 'a.txt').read_bytes(), b'abc')

    def test_changed_missing_added(self):
        (self.root / 'gone').write_bytes(b'x')
        self.create()
        (self.root / 'a.txt').write_bytes(b'xyz')
        (self.root / 'gone').unlink()
        (self.root / 'new').write_bytes(b'n')
        result = self.cli('verify', self.manifest, '--root', self.root)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'changed': ['a.txt'], 'missing': ['gone'], 'added': ['new']})

    def test_single_file_and_empty_directory(self):
        self.assertEqual(self.cli('create', self.root / 'a.txt', '--output', self.manifest).returncode, 0)
        self.assertEqual(self.cli('verify', self.manifest, '--root', self.root / 'a.txt').returncode, 0)
        (self.root / 'a.txt').unlink()
        self.assertEqual(m.collect(self.root, 'directory')['files'], [])

    def test_no_overwrite_or_output_inside_source(self):
        self.create()
        before = self.manifest.read_bytes()
        self.assertEqual(self.cli('create', self.root, '--output', self.manifest).returncode, 2)
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assertEqual(self.cli('create', self.root, '--output', self.root / 'result').returncode, 2)
        self.assertFalse((self.root / 'result').exists())

    def test_unsafe_paths(self):
        for name in ('../x', '/x', 'C:/x', 'a\\b', 'a:b', 'a//b', 'CON.txt', 'a.', 'a/../x', 'a\n'):
            with self.subTest(name=name), self.assertRaises(m.IntegrityError):
                m.safe_path(name)

    def test_malformed_manifests(self):
        self.create()
        valid = json.loads(self.manifest.read_bytes())
        variants = [b'{', b'{"format":1,"format":2}', b'[]', b'\xff']
        for field, value in [('algorithm', 'md5'), ('kind', 'other'), ('files', None), ('tool_version', '99')]:
            obj = dict(valid)
            obj[field] = value
            variants.append(json.dumps(obj).encode())
        for update in ({'path': '../escape'}, {'size': True}, {'sha256': 'f' * 63}):
            obj = json.loads(json.dumps(valid))
            obj['files'][0].update(update)
            variants.append(json.dumps(obj).encode())
        obj = json.loads(json.dumps(valid))
        obj['files'] *= 2
        variants.append(json.dumps(obj).encode())
        for data in variants:
            self.manifest.write_bytes(data)
            result = self.cli('verify', self.manifest, '--root', self.root)
            self.assertEqual(result.returncode, 2, data)
            self.assertEqual(result.stdout, '')

    def test_limits(self):
        with patch.object(m, 'MAX_FILES', 1), self.assertRaises(m.IntegrityError):
            m.collect(self.root, 'directory')
        self.manifest.write_bytes(b' ' * 100)
        with patch.object(m, 'MAX_MANIFEST', 10), self.assertRaises(m.IntegrityError):
            m.load_manifest(self.manifest)

    def test_permission_error_fails_closed(self):
        with patch.object(m.os, 'open', side_effect=PermissionError('synthetic denial')):
            with self.assertRaises(PermissionError):
                m.collect(self.root, 'directory')
        self.assertFalse(self.manifest.exists())

    def test_windows_cross_api_ctime(self):
        expected = (1, 2, 0o100644, 3, 100, 90)
        observed = (1, 2, 0o100644, 3, 100, 100)
        self.assertTrue(m.identity_matches(observed, expected, 'nt'))
        self.assertFalse(m.identity_matches(observed, expected, 'posix'))
        for index in range(5):
            changed = list(observed)
            changed[index] += 1
            self.assertFalse(m.identity_matches(tuple(changed), expected, 'nt'))

    def test_change_during_hash(self):
        original = m.os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.root / 'a.txt').write_bytes(b'changed')
            return original(fd)
        with patch.object(m.os, 'fstat', side_effect=changed), self.assertRaises(m.IntegrityError):
            m.collect(self.root, 'directory')

    def test_tree_change(self):
        original = m.hash_file
        def added(path, info):
            digest = original(path, info)
            (self.root / 'new').write_bytes(b'new')
            return digest
        with patch.object(m, 'hash_file', side_effect=added), self.assertRaises(m.IntegrityError):
            m.collect(self.root, 'directory')

    def test_reparse_attribute_rejected_on_all_platforms(self):
        class Info:
            st_mode = 0o100644
            st_file_attributes = 0x400
        with patch.object(Path, 'lstat', return_value=Info()), self.assertRaises(m.IntegrityError):
            m.checked(self.root)

    def test_symlinks(self):
        link = self.root / 'link'
        try:
            link.symlink_to(self.root / 'a.txt')
        except OSError as exc:
            self.skipTest(f'Symlink privilege unavailable: {exc}')
        self.assertEqual(self.cli('create', self.root, '--output', self.manifest).returncode, 2)
        self.assertFalse(self.manifest.exists())
        link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.cli('create', link, '--output', self.manifest).returncode, 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO')
    def test_fifo_refused(self):
        os.mkfifo(self.root / 'pipe')
        self.assertEqual(self.cli('create', self.root, '--output', self.manifest).returncode, 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction')
    def test_windows_junction(self):
        junction = self.root / 'junction'
        target = self.base / 'target'
        target.mkdir()
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(lambda: os.rmdir(junction))
        self.assertEqual(self.cli('create', self.root, '--output', self.manifest).returncode, 2)


if __name__ == '__main__':
    unittest.main()
