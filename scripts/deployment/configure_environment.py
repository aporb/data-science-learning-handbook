#!/usr/bin/env python3
"""
Deployment script: configure the local or CI environment for the handbook stack.

Checks for required environment variables, validates the .env file, creates
required directories, and prints a readiness report.

Usage:
    python configure_environment.py [--env-file <path>] [--strict]
"""

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Required variables for full stack operation
REQUIRED_VARS: list[tuple[str, str]] = [
    ("POSTGRES_PASSWORD", "PostgreSQL database password"),
    ("VAULT_DEV_ROOT_TOKEN_ID", "HashiCorp Vault root token (dev mode)"),
    ("JUPYTER_TOKEN", "JupyterHub authentication token"),
]

# Optional but recommended variables
OPTIONAL_VARS: list[tuple[str, str]] = [
    ("MLFLOW_TRACKING_URI", "MLflow tracking server URI"),
    ("GRAFANA_ADMIN_PASSWORD", "Grafana admin password"),
    ("REDIS_PASSWORD", "Redis authentication password"),
    ("SMTP_HOST", "SMTP server for notification emails"),
    ("SMTP_PORT", "SMTP port"),
    ("SMTP_USER", "SMTP username"),
    ("SMTP_PASSWORD", "SMTP password"),
]

REQUIRED_DIRS = [
    "validation/reports",
    "validation/schemas",
    ".taskmaster/docs",
]


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file and return key-value pairs (does not export)."""
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def check_vars(
    env: dict[str, str], var_list: list[tuple[str, str]]
) -> tuple[list[str], list[str]]:
    """Return (present, missing) lists."""
    present, missing = [], []
    for name, _ in var_list:
        if env.get(name) or os.environ.get(name):
            present.append(name)
        else:
            missing.append(name)
    return present, missing


def create_required_dirs() -> None:
    for rel in REQUIRED_DIRS:
        d = REPO_ROOT / rel
        d.mkdir(parents=True, exist_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure handbook environment")
    parser.add_argument(
        "--env-file",
        default=str(REPO_ROOT / ".env"),
        help="Path to .env file (default: repo root .env)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if required variables are missing",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    env = load_env_file(env_path)
    print(f"Environment file: {env_path} ({'found' if env_path.exists() else 'not found'})")

    print("\n--- Required Variables ---")
    present_req, missing_req = check_vars(env, REQUIRED_VARS)
    for name in present_req:
        print(f"  [OK]      {name}")
    for name in missing_req:
        desc = next(d for n, d in REQUIRED_VARS if n == name)
        print(f"  [MISSING] {name}  ({desc})")

    print("\n--- Optional Variables ---")
    present_opt, missing_opt = check_vars(env, OPTIONAL_VARS)
    for name in present_opt:
        print(f"  [OK]      {name}")
    for name in missing_opt:
        print(f"  [unset]   {name}")

    print("\n--- Required Directories ---")
    create_required_dirs()
    for rel in REQUIRED_DIRS:
        print(f"  [OK] {rel}")

    if missing_req:
        print(f"\nWARNING: {len(missing_req)} required variable(s) missing.")
        if args.strict:
            sys.exit(1)
    else:
        print("\nEnvironment check passed.")


if __name__ == "__main__":
    main()
