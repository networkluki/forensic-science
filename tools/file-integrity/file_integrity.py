#!/usr/bin/env python3
"""Local, read-only content inventory. Requires Python 3.11+."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

VERSION = '0.1.0'
MAX_MANIFEST = 32 * 1024 * 1024
MAX_FILES = 100_000
CHUNK = 1024 * 1024


class IntegrityError(Exception):
    """Incomplete or unsafe examination."""


def checked(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise IntegrityError(f'Link or reparse point refused: {path}')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise IntegrityError(f'Special file refused: {path}')
    return info


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def identity_matches(observed, expected, platform):
    # ctime remains checked within each API before/after reading.
    return observed[:-1] == expected[:-1] if platform == 'nt' else observed == expected


def safe_path(name):
    if not isinstance(name, str) or not name or len(name) > 4096:
        raise IntegrityError('Invalid manifest path')
    parts = name.split('/')
    for part in parts:
        if (part in ('', '.', '..') or part.endswith((' ', '.'))
                or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in part)
                or re.fullmatch(r'(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', part, re.I)):
            raise IntegrityError(f'Non-portable or unsafe path: {name!r}')
    try:
        name.encode('utf-8')
    except UnicodeError as exc:
        raise IntegrityError('Path is not valid UTF-8') from exc
    return name


def source_path(value):
    path = Path(os.path.abspath(value))
    for part in reversed((path, *path.parents)):
        checked(part)
    return path


def inventory(root, kind):
    result = {}
    def visit(path, relative):
        info = checked(path)
        result[relative] = fingerprint(info)
        if len(result) > MAX_FILES:
            raise IntegrityError('Inventory entry limit exceeded')
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir(), key=lambda p: p.name):
                name = f'{relative}/{child.name}' if relative else child.name
                safe_path(name)
                visit(child, name)
    if kind == 'file':
        info = checked(root)
        if not stat.S_ISREG(info.st_mode):
            raise IntegrityError('Expected a regular file')
        result[root.name] = fingerprint(info)
        safe_path(root.name)
    else:
        if not stat.S_ISDIR(checked(root).st_mode):
            raise IntegrityError('Expected a directory')
        visit(root, '')
    names = [name.casefold() for name in result]
    if len(names) != len(set(names)):
        raise IntegrityError('Case-insensitive path collision')
    return result


def open_readonly(path, flags):
    """Anchor each POSIX component; never resolve an intermediate symlink."""
    if os.name != 'posix':
        source_path(path)
        return os.open(path, flags)
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


def hash_file(path, expected):
    if fingerprint(checked(path)) != expected:
        raise IntegrityError(f'File changed before reading: {path}')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = open_readonly(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        # Windows stat and fstat can expose different ctime semantics (CPython #157671).
        # Compare ctime within each API, not across path and descriptor APIs.
        observed = fingerprint(before)
        matches = identity_matches(observed, expected, os.name)
        if not stat.S_ISREG(before.st_mode) or not matches:
            raise IntegrityError(f'File replaced before reading: {path}; expected={expected!r}; observed={fingerprint(before)!r}')
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            data = stream.read(min(CHUNK, remaining))
            if not data:
                raise IntegrityError(f'File truncated during reading: {path}')
            digest.update(data)
            remaining -= len(data)
        if stream.read(1) or fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
            raise IntegrityError(f'File changed during reading: {path}')
    source_path(path)
    if fingerprint(checked(path)) != expected:
        raise IntegrityError(f'File replaced during reading: {path}')
    return digest.hexdigest()


def collect(root, kind):
    before = inventory(root, kind)
    records = []
    for name, info in sorted(before.items()):
        if stat.S_ISREG(info[2]):
            path = root if kind == 'file' else root.joinpath(*name.split('/'))
            records.append({'path': name, 'size': info[3], 'sha256': hash_file(path, info)})
    if inventory(root, kind) != before:
        raise IntegrityError('Source tree changed during collection')
    return {'format': 'networkluki-integrity-v1', 'algorithm': 'sha256',
            'tool_version': VERSION, 'kind': kind, 'files': records}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError('Duplicate JSON key')
        result[key] = value
    return result


def load_manifest(path):
    with open(path, 'rb') as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise IntegrityError('Manifest size limit exceeded')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {'format', 'algorithm', 'tool_version', 'kind', 'files'}
            or value['format'] != 'networkluki-integrity-v1' or value['algorithm'] != 'sha256'
            or value['kind'] not in ('file', 'directory') or value['tool_version'] != VERSION
            or not isinstance(value['files'], list) or len(value['files']) > MAX_FILES):
        raise IntegrityError('Unsupported manifest schema')
    seen = set()
    for entry in value['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'size', 'sha256'}:
            raise IntegrityError('Invalid file record')
        name = safe_path(entry['path'])
        if name.casefold() in seen:
            raise IntegrityError('Duplicate or case-colliding path')
        seen.add(name.casefold())
        if (type(entry['size']) is not int or entry['size'] < 0
                or not isinstance(entry['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
            raise IntegrityError('Invalid size or SHA-256')
    names = [e['path'] for e in value['files']]
    for name in names:
        parts = name.split('/')
        if any('/'.join(parts[:i]).casefold() in seen for i in range(1, len(parts))):
            raise IntegrityError('File/directory path conflict')
    if names != sorted(names) or (value['kind'] == 'file' and (len(names) != 1 or '/' in names[0])):
        raise IntegrityError('Invalid record ordering or file scope')
    return value


def serialize(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')


def write_manifest(destination, root, payload):
    output = Path(os.path.abspath(destination))
    parent = source_path(output.parent)
    if output == root or root in output.parents:
        raise IntegrityError('Manifest must be outside the source tree')
    if output.exists() or output.is_symlink():
        raise IntegrityError('Output already exists')
    data = serialize(payload)
    if len(data) > MAX_MANIFEST:
        raise IntegrityError('Manifest size limit exceeded')
    fd, temporary = tempfile.mkstemp(prefix='.integrity-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber publication; fail safely if hard links are unsupported.
        os.link(temporary, output)
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('create')
    create.add_argument('source')
    create.add_argument('--output', required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('manifest')
    verify.add_argument('--root', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            root = source_path(args.source)
            kind = 'directory' if root.is_dir() else 'file'
            write_manifest(args.output, root, collect(root, kind))
            return 0
        expected = load_manifest(args.manifest)
        root = source_path(args.root)
        actual = collect(root, expected['kind'])
        old = {e['path']: e for e in expected['files']}
        new = {e['path']: e for e in actual['files']}
        report = {'changed': sorted(k for k in old.keys() & new.keys() if old[k] != new[k]),
                  'missing': sorted(old.keys() - new.keys()), 'added': sorted(new.keys() - old.keys())}
        print(serialize(report).decode('ascii'), end='')
        return 1 if any(report.values()) else 0
    except (OSError, ValueError, IntegrityError, RecursionError) as exc:
        print(f'error: {str(exc)!r}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
