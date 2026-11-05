#!/usr/bin/env python3
"""Run the checked-out tool without installing it or accessing the network."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from networkluki_imager.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
