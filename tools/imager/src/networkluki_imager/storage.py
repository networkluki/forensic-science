"""Bounded reads and exclusive output creation; never overwrite a source."""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
import re
import stat

MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_BACKUP_BYTES = 96 * 1024 * 1024


def validate_windows_path(path: str) -> None:
    """Reject stream/device/remote names before Win32 can reinterpret them."""
    if path.startswith(("\\\\", "//")):
        raise ValueError("UNC shares and Windows device namespaces are unsupported")
    parsed = PureWindowsPath(path)
    if parsed.drive and (re.fullmatch(r"[A-Za-z]:", parsed.drive) is None or not parsed.root):
        raise ValueError("Use a local absolute drive path or an ordinary relative path")
    for component in parsed.parts:
        if component == parsed.anchor or component in (".", ".."):
            continue
        if ":" in component or component.endswith((".", " ")):
            raise ValueError("Alternate data streams and trailing-dot/space aliases are unsupported")
        stem = component.split(".", 1)[0].rstrip(" ").upper()
        if stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"} or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem):
            raise ValueError("Windows device names are not ordinary files")


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def checked_path(path: str | Path, *, output: bool = False) -> Path:
    """Reject links/reparse points; require an existing parent for outputs."""
    if os.name == "nt":
        validate_windows_path(os.fspath(path))
    result = Path(os.path.abspath(path))
    if os.name == "nt":
        validate_windows_path(str(result))
    for parent in reversed(result.parents):
        info = parent.lstat()
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Paths must use ordinary directories, not links/reparse points")
    try:
        info = result.lstat()
    except FileNotFoundError:
        if output:
            return result
        raise
    if output:
        raise FileExistsError(f"Output already exists: {str(result)!r}")
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise ValueError("Input must be an ordinary file, not a device, link, or directory")
    return result


def read_checked(path: str | Path, limit: int = MAX_IMAGE_BYTES) -> bytes:
    source = checked_path(path)
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(source, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or _is_link(before):
            raise ValueError("Input is not an ordinary file")
        if before.st_size > limit:
            raise ValueError(f"Input exceeds the {limit}-byte limit")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        before_key = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_key = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(data) > limit or len(data) != before.st_size or before_key != after_key:
            raise ValueError("Input changed while reading or exceeded the size limit")
    return data


def write_new(path: str | Path, data: bytes) -> None:
    """Create with O_EXCL. Remove our own partial file on handled failures."""
    target = checked_path(path, output=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(target, flags, 0o600)
    created = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            current = target.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                target.unlink()
        except OSError:
            pass
        raise
