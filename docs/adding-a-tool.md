# Adding a tool

## Placement

| Content | Location |
| --- | --- |
| Implementation and dependency declaration | `tools/<tool-name>/` |
| Tool documentation | `tools/<tool-name>/README.md` |
| Reusable command examples | `commands/<platform-or-topic>/` |
| Automated tests | `tests/<tool-name>/` |
| Synthetic fixtures and demonstrations | `examples/<tool-name>/` |

Use English for code, identifiers, comments, configuration, and documentation. Keep command references independent from implementation files so users can find and review commands before running anything.

## Implementation requirements

- Declare supported operating systems, runtime versions, dependencies, and required privileges. Run without elevated privileges by default.
- Validate input paths and types; set explicit limits for file sizes, record counts, and parsing work. Treat names and content as untrusted; do not interpolate them into shell commands.
- Read source material without intentionally modifying it. Explain unavoidable effects. Do not silently follow links or switch input targets without documenting the behavior.
- Require an explicit output destination. Refuse to overwrite source material or existing results by default. Document failure cleanup and partial-output behavior.
- Keep processing local by default. Do not upload evidence or send telemetry without an explicit, documented user action.
- Report actionable errors to stderr and use nonzero exit status on failure. Do not report partial or inaccessible data as a successful complete examination.
- Include tool version, input identifiers, time zone, and collection limitations in reports. Preserve raw timestamp values alongside normalized ones.
- Test ordinary use, invalid paths, permission failures, malformed data, and relevant resource limits using synthetic fixtures.

Start from the [tool README template](../templates/tool-README.md). Update the root README and command index only when the implementation exists and its documented behavior has been checked.

## License and review

Original project material uses the root [LICENSE](../LICENSE). Preserve third-party notices and verify compatibility before incorporating external code. Contributions do not change the project's personal-use restrictions.

Before publishing, inspect the staged diff and file list. Verify that fixtures are synthetic and that no credentials, real logs, personal information, or case outputs are included. Document what was tested and any platform that remains untested.
