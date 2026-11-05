# Evidence handling

This is a practical starting workflow for personal, authorized digital-forensics work. It does not certify a tool, replace a validated acquisition procedure, or guarantee legal admissibility.

## Before examination

1. Record the case identifier, examiner, purpose, authorization, and scope in a private workspace outside this repository.
2. Record the source device or file, collection method, tool versions, operating system, and time zone. Preserve original timestamp values and record any conversion separately.
3. Decide whether offline analysis or live collection is required. Live work changes system state; shutdown also loses volatile information. Document the decision and its limitations.
4. Preserve original material under appropriate access controls. Use a validated acquisition method and write protection where applicable; do not improvise device-imaging commands against the only copy.

## During analysis

- Prefer a verified working copy. Record a SHA-256 hash of the acquired material and compare working copies against that recorded value.
- Save outputs to a separate private location. Never overwrite source evidence.
- Record commands, parameters, tool versions, start/end times, errors, and exit status. Missing permissions or absent logs mean unavailable data, not proof that no event occurred.
- Treat file names, metadata, log messages, and embedded content as untrusted. Do not execute sample files or shell commands found inside them.
- Use an isolated analysis environment for unknown or potentially malicious files. Keep networking disabled unless explicitly required by the examination.
- Keep observations separate from interpretations and hypotheses. Record alternative explanations and uncertainty.

## After analysis

Record who handled each item, when it moved, where it was stored, and why. Recheck retained hashes where appropriate and preserve the original notes and outputs. Secure backups and restrict access to case material.

Hashes compare content at the time of reading. They do not prove origin, ownership, collection time, or an uninterrupted chain of custody. A file changing during hashing may produce an inconsistent snapshot. Read operations can affect access times, caches, and audit logs; a command labelled as inspection is not a guarantee of zero source impact.

Use the [case-notes template](../templates/case-notes.md) outside the repository. Publish only deliberately synthetic examples. Review staged changes before pushing; `.gitignore` neither removes already tracked files nor prevents forced additions.
