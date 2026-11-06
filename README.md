# NetworkLuki Forensic Science

Digital forensics workspace by **NetworkLuki** for local, authorized examination of files, logs, and system artifacts on Linux and Windows.

**Available tools:** [File Integrity](tools/file-integrity/README.md) creates and verifies deterministic SHA-256 manifests for files and directory trees; [Imager](tools/imager/README.md), a local Python command for JPEG/PNG analysis, metadata export, reversible metadata removal, and possible embedded-file detection. The repository also contains platform command references and evidence-handling templates. No standalone executable release is provided yet.

## Imager

Requires Python 3.11 or newer; no third-party runtime dependencies. Run directly from the repository on Linux:

```bash
python3 tools/imager/imager.py inspect '/analysis/photo.jpg'
```

On Windows:

```powershell
py -3 tools/imager/imager.py inspect 'C:\Analysis\photo.jpg'
```

Install into a virtual environment to use the `imager` command. See the [installation guide](tools/imager/README.md) and [command reference](commands/imager/README.md). Original files are never overwritten. Metadata restoration requires the matching backup; signature matches are candidates, not proof of hidden files or malware.

## Start here

1. Read the [personal-use license](LICENSE).
2. Read the [evidence-handling guide](docs/evidence-handling.md) before examining real data.
3. Choose a reference from the [command index](commands/README.md).
4. Keep case data and results outside this public repository. Use the [case-notes template](templates/case-notes.md) in your private case workspace.

## Repository layout

| Path | Purpose |
| --- | --- |
| [commands/](commands/README.md) | Organized command references, prerequisites, and limitations. |
| [commands/linux/](commands/linux/README.md) | Linux file inspection and systemd log queries. |
| [commands/windows/](commands/windows/README.md) | Windows and PowerShell file inspection and event queries. |
| [commands/imager/](commands/imager/README.md) | Cross-platform image metadata and embedded-content commands. |
| [tools/](tools/README.md) | Implemented analysis tools, one directory per tool. |
| [docs/](docs/README.md) | Evidence handling and development conventions. |
| [templates/](templates/README.md) | Tool documentation and private case-note templates. |
| [examples/](examples/README.md) | Synthetic examples only; no real case evidence. |
| [tests/](tests/README.md) | Automated tests with synthetic fixtures. |

Command documentation belongs in `commands/`; executable implementations belong in `tools/<tool-name>/`. Each future tool must describe its inputs, outputs, privileges, source effects, and verification procedure.

## Planned areas

These are further development areas beyond Imager's documented JPEG/PNG support:

- Additional file formats and metadata decoders.
- Linux journal and Windows event-log analysis.
- Timestamp normalization and event timelines.
- Offline network-capture analysis.
- Disk-image and memory-artifact analysis.

See [adding a tool](docs/adding-a-tool.md) for the project conventions.

## Evidence and safety

Use only systems and data you own or are explicitly authorized to examine. Work from verified copies when possible. Even commands that only read data can affect access times, caches, logs, or the state of a live system. A matching hash supports a content comparison; it does not establish who created a file, when an event occurred, or a complete chain of custody.

Do not commit real evidence, personal information, credentials, captures, memory dumps, or case reports. The included `.gitignore` is a convenience, not a data-loss prevention control.

## License

Copyright (c) 2026 NetworkLuki. All rights reserved except as granted in [LICENSE](LICENSE).

This project uses the **NetworkLuki Forensic Science Personal Use License**, adapted for this repository. It permits personal, non-commercial use and sharing official links. Commercial use and redistribution require prior written permission, subject to the exceptions in the license. Public visibility does not make this an open-source license.

The license preserves GitHub's platform permissions for viewing and forking a public repository and rights that applicable law does not allow to be excluded. Third-party tools referenced in the documentation retain their own licenses.

License context: [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and [Open Source Definition](https://opensource.org/osd).

## Project

- Maintainer: [NetworkLuki](https://github.com/networkluki)
- Official repository: [networkluki/forensic-science](https://github.com/networkluki/forensic-science)
- Bug reports: use repository issues with synthetic, minimal examples. Never attach real evidence or secrets.
