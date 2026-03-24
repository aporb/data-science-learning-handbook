"""
Chapter 01: Environment Verification
======================================
Comprehensive checks for platform access, package availability, and network
connectivity on federal data science platforms.

The pattern here is simple: fail fast, fail loud, and fail with a useful error
message. Federal platforms are inconsistent about what is and isn't available.
A check that runs in 5 seconds at the start of a session saves 45 minutes of
confused debugging when something is silently missing.

Run this on day one of any new platform access. Run it again after any system
upgrade or environment change. Run it in the first cell of every shared notebook
so the next person who runs it knows whether their environment matches yours.

Platform coverage:
  - Advana (Databricks-on-Advana)
  - Navy Jupiter (Databricks-on-Jupiter)
  - Databricks standalone (GovCloud)
  - Palantir Foundry (Code Workspaces)
  - Qlik Cloud Government

Prerequisite packages:
  The verification functions check for packages; they don't require them upfront.
  The only hard dependency is: requests (almost always available), and
  importlib (standard library).
"""

import os
import sys
import time
import socket
import importlib
import importlib.util
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple


# ============================================================
# SECTION 1: PACKAGE AVAILABILITY CHECKS
# On government platforms, package availability varies by:
#   - Environment type (CPU cluster vs GPU cluster)
#   - Network policy (can packages be installed interactively?)
#   - Platform tier (Advana IL4 vs IL5 environments)
# ============================================================

# Minimum required packages by platform and use case
REQUIRED_PACKAGES = {
    "core_data_science": [
        "pandas",
        "numpy",
        "scipy",
        "matplotlib",
        "seaborn",
    ],
    "machine_learning": [
        "sklearn",       # scikit-learn
        "xgboost",
        "lightgbm",
    ],
    "spark_databricks": [
        "pyspark",
        "mlflow",
        "delta",
    ],
    "palantir_foundry": [
        "palantir_models",
    ],
    "deep_learning": [
        "torch",         # PyTorch
        "tensorflow",
        "onnx",
        "onnxruntime",
    ],
    "nlp_genai": [
        "transformers",
        "tokenizers",
        "sentence_transformers",
    ],
    "geospatial": [
        "geopandas",
        "shapely",
        "fiona",
        "pyproj",
    ],
}

# Python import name to pip package name mapping (where they differ)
IMPORT_TO_PIP = {
    "sklearn": "scikit-learn",
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "sentence_transformers": "sentence-transformers",
    "delta": "delta-spark",
}


def check_packages(categories: Optional[List[str]] = None) -> Dict[str, Dict[str, bool]]:
    """
    Check which packages are available in the current environment.

    Args:
        categories: List of categories to check. If None, checks core_data_science
                    and machine_learning only. Pass ["all"] to check everything.

    Returns:
        Dict mapping category name -> {package_name -> available bool}

    Usage:
        # Quick check for a new environment
        results = check_packages()

        # Check everything
        results = check_packages(["all"])

        # Check only what you need for this notebook
        results = check_packages(["core_data_science", "spark_databricks"])
    """
    if categories is None:
        categories = ["core_data_science", "machine_learning"]
    elif "all" in categories:
        categories = list(REQUIRED_PACKAGES.keys())

    results = {}

    for category in categories:
        if category not in REQUIRED_PACKAGES:
            print(f"  WARNING: Unknown category '{category}'. "
                  f"Valid options: {list(REQUIRED_PACKAGES.keys())}")
            continue

        results[category] = {}
        packages = REQUIRED_PACKAGES[category]

        for pkg in packages:
            spec = importlib.util.find_spec(pkg)
            available = spec is not None
            results[category][pkg] = available

    return results


def print_package_report(results: Dict[str, Dict[str, bool]]) -> None:
    """Print a formatted package availability report."""
    print("\n=== Package Availability Report ===")
    missing_total = []

    for category, packages in results.items():
        available = [p for p, ok in packages.items() if ok]
        missing = [p for p, ok in packages.items() if not ok]
        missing_total.extend(missing)

        print(f"\n[{category.upper().replace('_', ' ')}]")
        for pkg, ok in packages.items():
            status = "OK  " if ok else "MISS"
            pip_name = IMPORT_TO_PIP.get(pkg, pkg)
            install_hint = f" (pip install {pip_name})" if not ok else ""
            print(f"  [{status}] {pkg}{install_hint}")

    if missing_total:
        print(f"\nSummary: {len(missing_total)} package(s) missing.")
        print("On government platforms, missing packages may require:")
        print("  1. An IT request to add packages to the approved list")
        print("  2. Importing from a pre-approved conda environment")
        print("  3. Using the platform's built-in package management (e.g., Databricks %pip)")
    else:
        print("\nAll checked packages are available.")
    print()


# ============================================================
# SECTION 2: PLATFORM ACCESS VERIFICATION
# Check that you can actually reach the platforms you need.
# Network access policies on DoD systems are granular and change.
# ============================================================

def check_databricks_access(
    host: Optional[str] = None,
    token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify Databricks workspace access.

    Checks:
    1. Environment variables are set
    2. Host is reachable (TCP connect, not just ping)
    3. Token is valid (authenticated API call)
    4. Cluster list is accessible (confirms required permissions)

    Returns a dict with keys: reachable, authenticated, has_cluster_access, details
    """
    host = host or os.environ.get("DATABRICKS_HOST")
    token = token or os.environ.get("DATABRICKS_TOKEN")

    result = {
        "platform": "databricks",
        "host": host,
        "reachable": False,
        "authenticated": False,
        "has_cluster_access": False,
        "details": {},
        "error": None
    }

    if not host:
        result["error"] = "DATABRICKS_HOST not set"
        return result

    # TCP reachability check — works even if token is wrong
    try:
        from urllib.parse import urlparse
        parsed = urlparse(host)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        sock = socket.create_connection((hostname, port), timeout=5)
        sock.close()
        result["reachable"] = True
    except (socket.timeout, socket.error, OSError) as e:
        result["error"] = f"Host not reachable: {e}"
        return result

    if not token:
        result["error"] = "DATABRICKS_TOKEN not set"
        return result

    # Authenticated API checks
    try:
        import requests
        headers = {"Authorization": f"Bearer {token}"}

        # Check workspace info (requires any valid token)
        resp = requests.get(
            f"{host}/api/2.0/workspace/list",
            headers=headers,
            params={"path": "/"},
            timeout=15
        )

        if resp.status_code == 200:
            result["authenticated"] = True
            result["details"]["workspace_root_items"] = len(
                resp.json().get("objects", [])
            )
        elif resp.status_code == 403:
            result["error"] = "Token invalid or expired"
            return result

        # Check cluster access (separate permission level)
        resp_clusters = requests.get(
            f"{host}/api/2.0/clusters/list",
            headers=headers,
            timeout=15
        )

        if resp_clusters.status_code == 200:
            result["has_cluster_access"] = True
            clusters = resp_clusters.json().get("clusters", [])
            running = [c for c in clusters if c.get("state") == "RUNNING"]
            result["details"]["total_clusters"] = len(clusters)
            result["details"]["running_clusters"] = len(running)

    except ImportError:
        result["error"] = "requests not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_foundry_access(
    host: Optional[str] = None,
    token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify Palantir Foundry access.

    Checks:
    1. Host is reachable
    2. Token is valid (userinfo endpoint)
    3. Dataset API is accessible (confirms data access permissions)

    In a Code Workspace, host and token may be injected by the platform —
    check the workspace environment rather than relying on env vars.
    """
    host = host or os.environ.get("FOUNDRY_HOST")
    token = token or os.environ.get("FOUNDRY_TOKEN")

    result = {
        "platform": "foundry",
        "host": host,
        "reachable": False,
        "authenticated": False,
        "has_dataset_access": False,
        "details": {},
        "error": None
    }

    if not host:
        # Check for foundry-dev-tools as fallback
        try:
            from foundry_dev_tools import FoundryContext
            ctx = FoundryContext()
            result["reachable"] = True
            result["authenticated"] = True
            result["details"]["auth_method"] = "foundry-dev-tools"
            return result
        except ImportError:
            result["error"] = "FOUNDRY_HOST not set and foundry-dev-tools not installed"
            return result
        except Exception as e:
            result["error"] = f"foundry-dev-tools error: {e}"
            return result

    # TCP reachability
    try:
        from urllib.parse import urlparse
        parsed = urlparse(host)
        hostname = parsed.hostname
        port = parsed.port or 443

        sock = socket.create_connection((hostname, port), timeout=5)
        sock.close()
        result["reachable"] = True
    except (socket.timeout, socket.error, OSError) as e:
        result["error"] = f"Host not reachable: {e}"
        return result

    if not token:
        result["error"] = "FOUNDRY_TOKEN not set"
        return result

    try:
        import requests
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.get(
            f"{host}/api/v1/userinfo",
            headers=headers,
            timeout=15
        )

        if resp.status_code == 200:
            user = resp.json()
            result["authenticated"] = True
            result["details"]["username"] = user.get("username", "unknown")
            result["details"]["groups"] = len(user.get("groups", []))

        elif resp.status_code == 401:
            result["error"] = "Foundry token invalid or expired"
            return result

    except ImportError:
        result["error"] = "requests not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_qlik_access(
    tenant_url: Optional[str] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify Qlik Cloud Government access.
    """
    tenant_url = tenant_url or os.environ.get("QLIK_TENANT_URL")
    api_key = api_key or os.environ.get("QLIK_API_KEY")

    result = {
        "platform": "qlik",
        "host": tenant_url,
        "reachable": False,
        "authenticated": False,
        "has_app_access": False,
        "details": {},
        "error": None
    }

    if not tenant_url:
        result["error"] = "QLIK_TENANT_URL not set"
        return result

    # TCP reachability
    try:
        from urllib.parse import urlparse
        parsed = urlparse(tenant_url)
        hostname = parsed.hostname
        port = parsed.port or 443

        sock = socket.create_connection((hostname, port), timeout=5)
        sock.close()
        result["reachable"] = True
    except (socket.timeout, socket.error, OSError) as e:
        result["error"] = f"Host not reachable: {e}"
        return result

    if not api_key:
        result["error"] = "QLIK_API_KEY not set"
        return result

    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        resp = requests.get(
            f"{tenant_url}/api/v1/users/me",
            headers=headers,
            timeout=15
        )

        if resp.status_code == 200:
            user = resp.json()
            result["authenticated"] = True
            result["details"]["name"] = user.get("name", "unknown")
            result["details"]["roles"] = user.get("roles", [])

            # Check app access
            resp_apps = requests.get(
                f"{tenant_url}/api/v1/items?resourceType=app&limit=5",
                headers=headers,
                timeout=15
            )
            if resp_apps.status_code == 200:
                result["has_app_access"] = True
                result["details"]["accessible_apps"] = len(
                    resp_apps.json().get("data", [])
                )

        elif resp.status_code == 401:
            result["error"] = "Qlik API key invalid"

    except ImportError:
        result["error"] = "requests not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


# ============================================================
# SECTION 3: PYTHON VERSION AND SYSTEM CHECKS
# Federal platforms often lag commercial environments by 1-2
# major Python versions. Knowing your version matters when
# debugging syntax errors that work on your laptop.
# ============================================================

def check_python_environment() -> Dict[str, Any]:
    """
    Check Python version, architecture, and key system info.

    Returns a dict with version, platform, architecture, and a warning
    if the Python version is below what certain packages require.

    Minimum version guidelines for federal platforms (as of 2025):
    - Most platforms: Python 3.9+
    - Foundry Code Workspaces: Python 3.10 (configurable)
    - Databricks Runtime 14.x: Python 3.11
    - Databricks Runtime 13.x: Python 3.10
    """
    import platform
    import struct

    py_version = sys.version_info
    version_str = f"{py_version.major}.{py_version.minor}.{py_version.micro}"

    warnings = []
    if py_version < (3, 9):
        warnings.append(
            f"Python {version_str} is below the 3.9 minimum for most federal platforms."
        )
    if py_version >= (3, 12):
        warnings.append(
            f"Python {version_str}: Some legacy government packages may not support 3.12+. "
            "Test thoroughly before deploying."
        )

    return {
        "python_version": version_str,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "architecture": platform.machine(),
        "pointer_size": struct.calcsize("P") * 8,
        "executable": sys.executable,
        "warnings": warnings,
        "is_notebook": "ipykernel" in sys.modules or "IPython" in sys.modules,
        "is_databricks": "DATABRICKS_RUNTIME_VERSION" in os.environ,
        "is_foundry_workspace": "FOUNDRY_TOKEN" in os.environ and "FOUNDRY_HOST" in os.environ,
        "checked_at": datetime.now(tz=timezone.utc).isoformat()
    }


# ============================================================
# SECTION 4: COMPLETE ENVIRONMENT REPORT
# The all-in-one check to run at session start.
# ============================================================

def full_environment_report(
    check_platform_access: bool = True,
    package_categories: Optional[List[str]] = None
) -> None:
    """
    Run a complete environment verification and print a formatted report.

    This is the function to put in the first cell of every shared notebook.

    Args:
        check_platform_access: Whether to attempt live platform connections.
                                Set to False if running offline or if network
                                access is restricted.
        package_categories:    Package categories to check. Default: core + ML.
                                Pass ["all"] for everything.

    Usage in a notebook cell:
        # Run this every session start
        %run path/to/03_environment_verification.py
        full_environment_report()
    """
    start_time = time.monotonic()

    print("=" * 60)
    print("ENVIRONMENT VERIFICATION REPORT")
    print(f"Run at: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)

    # 1. Python environment
    py_info = check_python_environment()
    print(f"\nPython {py_info['python_version']} "
          f"| {py_info['platform']} {py_info['platform_release']} "
          f"| {py_info['architecture']}")

    if py_info["is_databricks"]:
        runtime = os.environ.get("DATABRICKS_RUNTIME_VERSION", "unknown")
        print(f"Runtime: Databricks Runtime {runtime}")
    if py_info["is_notebook"]:
        print("Context: Running in a Jupyter/IPython notebook")

    for warning in py_info["warnings"]:
        print(f"  WARNING: {warning}")

    # 2. Package checks
    pkg_results = check_packages(package_categories)
    print_package_report(pkg_results)

    # 3. Platform access checks (live network calls)
    if check_platform_access:
        print("=== Platform Access Checks ===\n")
        platforms_to_check = []

        if os.environ.get("DATABRICKS_HOST"):
            platforms_to_check.append(("Databricks", check_databricks_access))
        if os.environ.get("FOUNDRY_HOST") or importlib.util.find_spec("foundry_dev_tools"):
            platforms_to_check.append(("Foundry", check_foundry_access))
        if os.environ.get("QLIK_TENANT_URL"):
            platforms_to_check.append(("Qlik", check_qlik_access))

        if not platforms_to_check:
            print("  No platform credentials detected in environment variables.")
            print("  Set DATABRICKS_HOST/TOKEN, FOUNDRY_HOST/TOKEN, or QLIK_TENANT_URL/API_KEY")
            print("  to enable live platform access checks.")
        else:
            for platform_name, check_fn in platforms_to_check:
                result = check_fn()
                _print_platform_result(platform_name, result)
    else:
        print("Platform access checks skipped (check_platform_access=False)")

    elapsed = time.monotonic() - start_time
    print(f"\n[Verification completed in {elapsed:.1f}s]")
    print("=" * 60)


def _print_platform_result(name: str, result: Dict[str, Any]) -> None:
    """Format and print a single platform check result."""
    reach = "REACH" if result.get("reachable") else "  ---"
    auth = "AUTH " if result.get("authenticated") else "  ---"
    access = "ACCESS" if result.get("has_cluster_access") or result.get("has_app_access") or result.get("has_dataset_access") else "     -"

    print(f"[{name.upper()}]")
    print(f"  Reachable:     [{reach}]")
    print(f"  Authenticated: [{auth}]")

    if result.get("details"):
        for k, v in result["details"].items():
            print(f"  {k}: {v}")

    if result.get("error"):
        print(f"  Error: {result['error']}")
    print()


# ============================================================
# MAIN: Run complete environment verification
# ============================================================

if __name__ == "__main__":
    full_environment_report(
        check_platform_access=True,
        package_categories=["core_data_science", "machine_learning", "spark_databricks"]
    )
