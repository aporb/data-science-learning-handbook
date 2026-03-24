#!/usr/bin/env python3
"""
Maintenance script: audit .gitkeep files across the repository.

For each .gitkeep:
  - If its parent directory now contains real files, report it as REMOVABLE.
  - If its parent directory is still empty (only the .gitkeep itself), report
    it as KEPT.

Optionally removes stale .gitkeep files with --remove.

Usage:
    python update_gitkeep.py [--remove] [--dry-run]
"""

import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
IGNORE_NAMES = {".DS_Store", ".gitkeep", "__pycache__"}


def has_real_content(directory: Path) -> bool:
    """Return True if directory contains any file other than .gitkeep/.DS_Store."""
    for item in directory.iterdir():
        if item.name in IGNORE_NAMES:
            continue
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit and optionally remove stale .gitkeep files")
    parser.add_argument("--remove", action="store_true", help="Remove .gitkeep files from non-empty dirs")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without making changes")
    args = parser.parse_args()

    gitkeeps = sorted(REPO_ROOT.rglob(".gitkeep"))
    removable = []
    kept = []

    for gk in gitkeeps:
        parent = gk.parent
        if has_real_content(parent):
            removable.append(gk)
        else:
            kept.append(gk)

    print(f"\n{'Status':12s} {'Path':70s}")
    print("-" * 84)
    for gk in kept:
        rel = gk.relative_to(REPO_ROOT)
        print(f"  {'KEPT':10s} {str(rel)}")
    for gk in removable:
        rel = gk.relative_to(REPO_ROOT)
        print(f"  {'REMOVABLE':10s} {str(rel)}")

    print(f"\nKept: {len(kept)}   Removable: {len(removable)}")

    if args.remove:
        for gk in removable:
            if args.dry_run:
                log.info("[dry-run] Would remove: %s", gk)
            else:
                gk.unlink()
                log.info("Removed: %s", gk)


if __name__ == "__main__":
    main()
