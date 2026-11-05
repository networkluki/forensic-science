# Tools

| Tool | Status | Purpose |
| --- | --- | --- |
| [Imager](imager/README.md) | 0.1.0 | JPEG/PNG inspection, metadata export, reversible removal, and embedded/appended signature scanning. |

Imager runs locally on Python 3.11+ with no third-party runtime dependencies. Its command reference is in [commands/imager](../commands/imager/README.md).

Use one directory per tool: `tools/<tool-name>/`. Use lowercase names separated by hyphens, such as `file-integrity` or `event-timeline`.

Each tool should include its implementation, README, and dependency declarations where required. Keep command recipes in [commands/](../commands/README.md), automated checks in [tests/](../tests/README.md), and synthetic examples in [examples/](../examples/README.md).

Start with the [tool README template](../templates/tool-README.md) and follow [adding a tool](../docs/adding-a-tool.md). Do not add empty programs or advertise planned tools as working features.
