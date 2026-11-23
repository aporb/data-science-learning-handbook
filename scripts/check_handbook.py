#!/usr/bin/env python3
"""Check repository Python syntax without importing infrastructure-dependent tools.

Platform: Local Python 3.11+
Usage: python scripts/check_handbook.py
Parsing is not a runtime, security, or compliance certification.
"""
import ast
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "*.py"], cwd=ROOT
    ).decode().split("\0")
    errors = []
    for relative in filter(None, paths):
        try:
            ast.parse((ROOT / relative).read_text(), filename=relative, feature_version=(3, 11))
        except (SyntaxError, UnicodeError) as error:
            errors.append(f"{relative}: {error}")
    for error in errors:
        print(error, file=sys.stderr)
    count = len([p for p in paths if p])
    print(f"Python 3.11 grammar: {count} tracked files, {len(errors)} failures")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
