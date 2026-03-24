#!/usr/bin/env python3
"""
Maintenance script: check that all dependencies in requirements.txt are
importable in the current Python environment and flag any that are missing.

Optionally checks for known security advisories using `pip-audit` if available.

Usage:
    python check_dependencies.py [--requirements <path>] [--audit]
"""

import argparse
import importlib
import importlib.util
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIREMENTS = REPO_ROOT / "requirements.txt"

# Map pip package names → importable module names where they differ
IMPORT_NAME_MAP = {
    "scikit-learn": "sklearn",
    "pillow": "PIL",
    "python-jose": "jose",
    "python-dotenv": "dotenv",
    "pyyaml": "yaml",
    "gitpython": "git",
    "psutil": "psutil",
    "beautifulsoup4": "bs4",
    "pyopenssl": "OpenSSL",
}


def parse_requirements(path: Path) -> list[str]:
    """Return list of package names from a requirements.txt file."""
    packages = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers: requests>=2.0 → requests
        pkg = line.split(">=")[0].split("<=")[0].split("==")[0].split("~=")[0].split("[")[0]
        packages.append(pkg.strip().lower())
    return packages


def check_importable(package: str) -> bool:
    """Return True if the package can be imported."""
    module_name = IMPORT_NAME_MAP.get(package, package.replace("-", "_"))
    return importlib.util.find_spec(module_name) is not None


def run_pip_audit() -> None:
    """Run pip-audit if available and print results."""
    if importlib.util.find_spec("pip_audit") is None:
        log.info("pip-audit not installed — skipping security audit (pip install pip-audit)")
        return
    log.info("Running pip-audit security check...")
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format", "columns"],
        capture_output=False,
    )
    if result.returncode != 0:
        log.warning("pip-audit found issues (exit code %d)", result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check handbook Python dependencies")
    parser.add_argument(
        "--requirements",
        default=str(DEFAULT_REQUIREMENTS),
        help="Path to requirements.txt",
    )
    parser.add_argument("--audit", action="store_true", help="Run pip-audit security check")
    args = parser.parse_args()

    req_path = Path(args.requirements)
    if not req_path.exists():
        log.error("Requirements file not found: %s", req_path)
        sys.exit(1)

    packages = parse_requirements(req_path)
    log.info("Checking %d packages from %s", len(packages), req_path)

    missing = []
    present = []
    for pkg in packages:
        if check_importable(pkg):
            present.append(pkg)
        else:
            missing.append(pkg)

    print(f"\n{'Package':40s} {'Status':10s}")
    print("-" * 52)
    for pkg in present:
        print(f"  {pkg:38s} OK")
    for pkg in missing:
        print(f"  {pkg:38s} MISSING")

    print(f"\nPresent: {len(present)}   Missing: {len(missing)}")

    if args.audit:
        run_pip_audit()

    if missing:
        print(f"\nInstall missing packages: pip install {' '.join(missing)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
