# Linux commands

Target: Debian 13 and Arch Linux with GNU Coreutils and systemd. Run these examples in Bash on an analysis host. The paths are examples; the files must already exist. No package installation, mounting or disk-acquisition commands are included.

## File-content hash — working copy

```bash
sha256sum -- '/analysis/case-001/working/sample.bin'
```

Record the SHA-256 value and compare it with the independently recorded acquisition hash. A mismatch requires investigation. Matching hashes do not prove who created a file. Do not hash a changing file and treat the result as a stable snapshot.

## Filesystem metadata — working copy

```bash
TZ=UTC stat -- '/analysis/case-001/working/sample.bin'
```

This prints size, permissions, ownership and timestamps for the working-copy filesystem. Copying may have changed metadata; these values are not automatically the original source timestamps. GNU `stat` reports a symbolic link itself by default. Confirm the input is the intended regular file before interpreting its hash or metadata.

## Copied systemd journal — offline

```bash
journalctl --file='/analysis/case-001/working/system.journal' \
  --since='2026-11-04 00:00:00 UTC' \
  --until='2026-11-04 23:59:59 UTC' \
  --lines=200 --output=json --no-pager
```

This reads only the specified copied journal file and returns at most the most recent 200 matching entries. The time boundaries are inclusive. Change the window to fit the investigation. JSON is an analysis representation; preserve the original journal separately. Missing or unreadable files are errors, not evidence of no activity.

## Local systemd journal — live

```bash
journalctl --system \
  --since='2026-11-04 00:00:00 UTC' \
  --until='2026-11-04 23:59:59 UTC' \
  --lines=200 --output=json --no-pager
```

This queries accessible system journals on the running host. Permission restrictions and retention settings can omit records. The 200-entry cap is intentional; output is not a complete collection. Record warnings and query parameters. Running this command is itself live-system activity.

## Verify available commands

```bash
sha256sum --version
stat --version
journalctl --version
```

Check `journalctl --help` on the target system before changing options. These examples do not request root access or write an output file.

## Official references

- [GNU SHA-2 utilities](https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html)
- [GNU stat](https://www.gnu.org/software/coreutils/manual/html_node/stat-invocation.html)
- [systemd journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)

Return to the [command index](../README.md).
