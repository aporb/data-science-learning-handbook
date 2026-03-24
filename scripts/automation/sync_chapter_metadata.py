#!/usr/bin/env python3
"""
Automation script: sync chapter metadata from README frontmatter to a
central manifest file at .taskmaster/docs/chapter_manifest.json.

Reads each chapter README.md, extracts YAML frontmatter (if present),
and writes a consolidated manifest that other tooling can consume.

Usage:
    python sync_chapter_metadata.py [--dry-run]
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # graceful fallback: parse simple key: value pairs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
CHAPTERS_DIR = REPO_ROOT / "chapters"
MANIFEST_PATH = REPO_ROOT / ".taskmaster" / "docs" / "chapter_manifest.json"

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter dict from markdown text."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    raw = m.group(1)
    if yaml:
        try:
            return yaml.safe_load(raw) or {}
        except yaml.YAMLError:
            pass
    # Minimal fallback: parse "key: value" lines
    result = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


def collect_chapter_metadata(chapter_dir: Path) -> dict:
    """Return metadata dict for one chapter."""
    readme = chapter_dir / "README.md"
    meta = {
        "id": chapter_dir.name,
        "path": str(chapter_dir.relative_to(REPO_ROOT)),
        "has_readme": readme.exists(),
        "frontmatter": {},
        "python_examples": [],
        "exercises": [],
    }

    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        meta["frontmatter"] = parse_frontmatter(text)
        # Derive title from first H1 if no frontmatter title
        if "title" not in meta["frontmatter"]:
            h1 = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
            if h1:
                meta["frontmatter"]["title"] = h1.group(1).strip()

    py_dir = chapter_dir / "code-examples" / "python"
    if py_dir.exists():
        meta["python_examples"] = sorted(f.name for f in py_dir.glob("*.py"))

    ex_dir = chapter_dir / "exercises"
    if ex_dir.exists():
        meta["exercises"] = sorted(
            f.name for f in ex_dir.iterdir() if f.is_file() and not f.name.startswith(".")
        )

    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync chapter metadata to manifest")
    parser.add_argument("--dry-run", action="store_true", help="Print manifest without writing")
    args = parser.parse_args()

    if not CHAPTERS_DIR.exists():
        log.error("chapters/ directory not found: %s", CHAPTERS_DIR)
        sys.exit(1)

    chapters = sorted(
        d for d in CHAPTERS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
    )
    log.info("Found %d chapter directories", len(chapters))

    manifest = {
        "schema_version": "1.0",
        "chapters": [collect_chapter_metadata(c) for c in chapters],
    }

    if args.dry_run:
        print(json.dumps(manifest, indent=2))
        return

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.info("Manifest written to %s (%d chapters)", MANIFEST_PATH, len(chapters))


if __name__ == "__main__":
    main()
