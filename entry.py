#!/usr/bin/python3
"""Isolated entry point; installed source is root-owned and never user writable."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from clamshield.cli import main

raise SystemExit(main())
