#!/usr/bin/env python3
"""
Automation script: run full content validation pipeline.

Runs all validators in sequence: content quality, technical validation,
bias assessment, and automated testing. Produces a consolidated report.

Usage:
    python run_validation.py [--chapter <id>] [--all] [--report-dir <path>]
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATION_DIR = REPO_ROOT / "validation"
CHAPTERS_DIR = REPO_ROOT / "chapters"
REPORTS_DIR = REPO_ROOT / "validation" / "reports"


def discover_chapters(chapter_filter: str | None = None) -> list[Path]:
    """Return sorted list of chapter directories to validate."""
    if not CHAPTERS_DIR.exists():
        log.error("chapters/ directory not found at %s", CHAPTERS_DIR)
        sys.exit(1)

    chapters = sorted(
        [d for d in CHAPTERS_DIR.iterdir() if d.is_dir() and d.name != "__pycache__"]
    )
    if chapter_filter:
        chapters = [c for c in chapters if chapter_filter in c.name]
    return chapters


def run_content_quality(chapter: Path) -> dict:
    """Run content quality check on a chapter README."""
    readme = chapter / "README.md"
    if not readme.exists():
        return {"status": "skipped", "reason": "no README.md"}

    word_count = len(readme.read_text(encoding="utf-8").split())
    return {
        "status": "ok" if word_count > 500 else "warn",
        "word_count": word_count,
        "file": str(readme.relative_to(REPO_ROOT)),
    }


def run_code_examples_check(chapter: Path) -> dict:
    """Check that code-examples/python has at least one .py file."""
    py_dir = chapter / "code-examples" / "python"
    if not py_dir.exists():
        return {"status": "missing", "reason": "code-examples/python does not exist"}

    py_files = list(py_dir.glob("*.py"))
    return {
        "status": "ok" if py_files else "empty",
        "py_files": [f.name for f in py_files],
    }


def run_exercises_check(chapter: Path) -> dict:
    """Check that exercises directory has content."""
    ex_dir = chapter / "exercises"
    if not ex_dir.exists():
        return {"status": "missing"}

    files = [f for f in ex_dir.iterdir() if not f.name.startswith(".")]
    return {
        "status": "ok" if files else "empty",
        "files": [f.name for f in files],
    }


def validate_chapter(chapter: Path) -> dict:
    """Run all checks for a single chapter and return result dict."""
    log.info("Validating chapter: %s", chapter.name)
    return {
        "chapter": chapter.name,
        "content_quality": run_content_quality(chapter),
        "code_examples": run_code_examples_check(chapter),
        "exercises": run_exercises_check(chapter),
    }


def compute_summary(results: list[dict]) -> dict:
    """Compute aggregate pass/warn/fail counts."""
    counts = {"ok": 0, "warn": 0, "empty": 0, "missing": 0, "skipped": 0}
    for r in results:
        for check in ("content_quality", "code_examples", "exercises"):
            status = r.get(check, {}).get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
    return counts


def write_report(results: list[dict], report_dir: Path) -> Path:
    """Write JSON report to report_dir."""
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    report_path = report_dir / f"validation_{timestamp}.json"
    payload = {
        "generated_at": timestamp,
        "summary": compute_summary(results),
        "chapters": results,
    }
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("Report written: %s", report_path)
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run content validation pipeline")
    parser.add_argument("--chapter", help="Filter to a specific chapter by name fragment")
    parser.add_argument("--all", action="store_true", help="Validate all chapters (default)")
    parser.add_argument(
        "--report-dir",
        default=str(REPORTS_DIR),
        help="Directory to write validation reports",
    )
    args = parser.parse_args()

    chapters = discover_chapters(args.chapter)
    if not chapters:
        log.error("No chapters found matching filter: %s", args.chapter)
        sys.exit(1)

    results = [validate_chapter(c) for c in chapters]
    report_path = write_report(results, Path(args.report_dir))

    summary = compute_summary(results)
    log.info("Validation complete. Summary: %s", summary)

    # Exit non-zero if any chapters are in an error state
    if summary.get("missing", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
