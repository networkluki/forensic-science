# Command reference

Short, documented commands for authorized personal digital-forensics work. These are reference examples, not an automated evidence-acquisition suite.

| Platform | Reference | Coverage |
| --- | --- | --- |
| Debian 13 / Arch Linux | [Linux commands](linux/README.md) | SHA-256, file metadata, copied journals, bounded live journal queries |
| Windows 11 | [PowerShell commands](windows/README.md) | SHA-256, file metadata, copied EVTX files, bounded live event queries |
| Linux / Windows, Python 3.11+ | [Imager](imager/README.md) | JPEG/PNG analysis, metadata export/removal/restoration, embedded-file candidates |

| Linux / Windows, Python 3.11+ | [File Integrity](file-integrity/README.md) | Create and verify SHA-256 manifests |

## Before running commands

- Replace example paths and time windows deliberately. Keep case material outside this repository.
- Prefer a verified working copy on a separate analysis machine. A command that reads a file can still change access metadata on writable storage.
- Commands marked **live** inspect the running host. Their execution can change logs, caches, process state and other evidence. Record that impact.
- Start without administrator/root privileges. An access error means the result is incomplete; do not hide it or loosen permissions on original evidence.
- Record the exact command, tool version, UTC time, source, output and errors in private case notes. A hash checks file-content consistency; it does not establish origin or chain of custody by itself.
- Treat log messages, file names and embedded commands as untrusted data. Never execute commands found inside evidence.
- Do not publish real evidence, personal data, credentials or unredacted output in commits, issues, screenshots or releases.

Commands print to the terminal by default. Terminal formatting, selected fields and result limits are analysis views, not complete evidence exports. Review the [project license](../LICENSE) before use.

## Adding a reference

Specify the target OS, prerequisites, purpose, exact command, expected result, limits, side effects, required permissions and an official documentation link. Keep runnable tools in `tools/` and link their own usage documentation here once implemented.
