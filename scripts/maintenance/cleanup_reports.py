#!/usr/bin/env python3
"""
Maintenance script: clean up old validation reports and build artifacts.

Keeps the N most-recent reports per category and deletes older ones.
Also removes Python __pycache__ directories and .pyc files.

Usage:
    python cleanup_reports.py [--keep <n>] [--dry-run] [--all]
"""

import argparse
import logging
import shutil
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

REPORT_DIRS = [
    REPO_ROOT / "validation" / "reports",
    REPO_ROOT / "security-compliance" / "security-testing" / "reports",
    REPO_ROOT / "security-compliance" / "penetration-testing" / "reports",
]


def cleanup_reports(report_dir: Path, keep: int, dry_run: bool) -> int:
    """Delete all but the newest `keep` JSON/HTML report files. Returns deleted count."""
    if not report_dir.exists():
        return 0

    reports = sorted(
        [f for f in report_dir.iterdir() if f.is_file() and f.suffix in {".json", ".html"}],
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )

    to_delete = reports[keep:]
    for f in to_delete:
        log.info("Deleting old report: %s", f)
        if not dry_run:
            f.unlink()
    return len(to_delete)


def cleanup_pycache(root: Path, dry_run: bool) -> int:
    """Remove all __pycache__ dirs and .pyc files under root. Returns removed count."""
    removed = 0
    for pycache in root.rglob("__pycache__"):
        if pycache.is_dir():
            log.info("Removing __pycache__: %s", pycache)
            if not dry_run:
                shutil.rmtree(pycache)
            removed += 1
    for pyc in root.rglob("*.pyc"):
        log.info("Removing .pyc: %s", pyc)
        if not dry_run:
            pyc.unlink()
        removed += 1
    return removed


def cleanup_ds_store(root: Path, dry_run: bool) -> int:
    """Remove .DS_Store files under root (macOS artifact). Returns removed count."""
    removed = 0
    for f in root.rglob(".DS_Store"):
        log.info("Removing .DS_Store: %s", f)
        if not dry_run:
            f.unlink()
        removed += 1
    return removed


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean up stale reports and build artifacts")
    parser.add_argument("--keep", type=int, default=5, help="Number of recent reports to keep per dir")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be deleted without deleting")
    parser.add_argument("--all", action="store_true", help="Also clean __pycache__ and .DS_Store files")
    args = parser.parse_args()

    total_deleted = 0

    for rd in REPORT_DIRS:
        n = cleanup_reports(rd, args.keep, args.dry_run)
        total_deleted += n

    if args.all:
        total_deleted += cleanup_pycache(REPO_ROOT, args.dry_run)
        total_deleted += cleanup_ds_store(REPO_ROOT, args.dry_run)

    action = "Would delete" if args.dry_run else "Deleted"
    log.info("%s %d item(s) total.", action, total_deleted)


if __name__ == "__main__":
    main()
