"""
Chapter 02: Python and R Foundations for Federal Platforms
Code Example 01: Environment Setup and Verification

Purpose:
    Verify your Python environment on any of the five federal platforms.
    Run this at the start of a new project to document your baseline and
    catch version mismatches before they become problems mid-project.

Platform compatibility:
    - Databricks (Advana, Jupiter, Databricks GovCloud) — run as a notebook cell
    - Palantir Foundry Code Workspaces — run as a .py file
    - Local Jupyter — run normally (useful for comparing against platform environment)

Usage:
    On Databricks: paste into a Python cell and run
    On Foundry: open in Code Workspace terminal or editor
    Locally: python 01_environment_setup.py
"""

import sys
import importlib
import platform
import os


def check_package(package_name: str, min_version: str = None) -> dict:
    """
    Check whether a package is installed and optionally validate its version.

    Args:
        package_name: The importable name of the package (e.g., "sklearn" for scikit-learn)
        min_version: If provided, warn if installed version is below this string

    Returns:
        dict with keys: name, installed, version, version_ok, note
    """
    result = {
        "name": package_name,
        "installed": False,
        "version": None,
        "version_ok": True,
        "note": "",
    }

    try:
        mod = importlib.import_module(package_name)
        result["installed"] = True
        result["version"] = getattr(mod, "__version__", "unknown")

        if min_version and result["version"] != "unknown":
            # Simple string comparison works for most semver cases
            # For production use, consider packaging.version.parse
            if result["version"] < min_version:
                result["version_ok"] = False
                result["note"] = f"Installed {result['version']}, expected >= {min_version}"

    except ImportError:
        result["note"] = "NOT INSTALLED — submit package request if needed"

    return result


def detect_platform_context() -> str:
    """
    Detect which platform environment this code is running in.

    Returns a string describing the likely execution context.
    This is heuristic-based — verify against your actual platform config.
    """
    # Databricks sets a specific environment variable
    if os.environ.get("DATABRICKS_RUNTIME_VERSION"):
        dbr_version = os.environ.get("DATABRICKS_RUNTIME_VERSION", "unknown")
        return f"Databricks Runtime {dbr_version}"

    # Foundry Code Workspaces set this
    if os.environ.get("FOUNDRY_CODE_WORKSPACES"):
        return "Palantir Foundry Code Workspace"

    # Foundry Transforms set a different variable
    if os.environ.get("FOUNDRY_TRANSFORMS"):
        return "Palantir Foundry Transform"

    # Jupyter / JupyterLab sets this when running notebook kernel
    if os.environ.get("JPY_SESSION_NAME") or os.environ.get("JUPYTER_SERVER_URL"):
        return "Jupyter Notebook / JupyterLab"

    return "Local Python / Unknown"


def check_databricks_connectivity() -> dict:
    """
    If running on Databricks, check connectivity to key platform components.
    Returns an empty dict if not on Databricks.
    """
    result = {}

    if not os.environ.get("DATABRICKS_RUNTIME_VERSION"):
        return result

    # Try to get an active SparkSession
    try:
        from pyspark.sql import SparkSession
        spark = SparkSession.getActiveSession()
        if spark:
            result["spark"] = "Active SparkSession found"
            result["spark_version"] = spark.version
        else:
            result["spark"] = "No active SparkSession — start a cluster"
    except ImportError:
        result["spark"] = "PySpark not available"

    # Try dbutils (Databricks utility functions)
    try:
        # dbutils is injected into the namespace by Databricks
        # It's not importable via standard import mechanisms
        import IPython
        ip = IPython.get_ipython()
        if ip and "dbutils" in ip.user_ns:
            result["dbutils"] = "Available"
        else:
            result["dbutils"] = "Not in namespace (expected in Databricks notebooks)"
    except Exception:
        result["dbutils"] = "Could not check"

    return result


def main():
    print("=" * 60)
    print("Federal Platform Python Environment Verification")
    print("=" * 60)

    # System basics
    print(f"\n[Python Runtime]")
    print(f"  Python version : {sys.version}")
    print(f"  Executable     : {sys.executable}")
    print(f"  Platform       : {platform.platform()}")
    print(f"  Detected env   : {detect_platform_context()}")

    # Key packages to verify
    # Format: (importable_name, display_name, minimum_version_to_warn)
    packages_to_check = [
        # Core data science
        ("pandas",       "pandas",            "1.5.0"),
        ("numpy",        "numpy",             "1.23.0"),
        ("scipy",        "scipy",             "1.9.0"),
        ("sklearn",      "scikit-learn",      "1.2.0"),
        ("statsmodels",  "statsmodels",       "0.13.0"),
        # Spark / Databricks
        ("pyspark",      "PySpark",           "3.3.0"),
        ("delta",        "delta-spark",       None),
        ("mlflow",       "MLflow",            "2.0.0"),
        # Visualization
        ("matplotlib",   "matplotlib",        "3.5.0"),
        ("seaborn",      "seaborn",           "0.12.0"),
        # Utilities
        ("pyarrow",      "pyarrow",           "10.0.0"),
        ("requests",     "requests",          "2.28.0"),
        # Platform SDKs (may not be available everywhere)
        ("databricks.sdk", "databricks-sdk",  None),
        ("transforms",   "foundry-transforms", None),
    ]

    print(f"\n[Installed Packages]")
    print(f"  {'Package':<25} {'Version':<15} {'Status'}")
    print(f"  {'-'*25} {'-'*15} {'-'*30}")

    missing = []
    version_warnings = []

    for import_name, display_name, min_ver in packages_to_check:
        result = check_package(import_name, min_ver)

        if result["installed"]:
            status = "OK" if result["version_ok"] else f"VERSION WARNING: {result['note']}"
            print(f"  {display_name:<25} {result['version']:<15} {status}")
            if not result["version_ok"]:
                version_warnings.append(display_name)
        else:
            print(f"  {display_name:<25} {'---':<15} {result['note']}")
            missing.append(display_name)

    # Databricks-specific checks
    db_status = check_databricks_connectivity()
    if db_status:
        print(f"\n[Databricks Platform Status]")
        for key, value in db_status.items():
            print(f"  {key:<20}: {value}")

    # Summary
    print(f"\n[Summary]")
    if missing:
        print(f"  Missing packages ({len(missing)}): {', '.join(missing)}")
        print(f"  Action: Submit package request to platform team if needed")
    else:
        print(f"  All checked packages are installed")

    if version_warnings:
        print(f"  Version warnings ({len(version_warnings)}): {', '.join(version_warnings)}")
        print(f"  Action: Test your code against installed versions — do not assume new features are available")
    else:
        print(f"  No version warnings")

    print(f"\n  Run this script at the start of every new project.")
    print(f"  Save the output as a comment in your project README notebook.")
    print("=" * 60)


if __name__ == "__main__":
    main()


# =============================================================================
# Databricks-specific: running as a notebook cell
# =============================================================================
# If you're pasting this into a Databricks notebook cell instead of running
# as a .py file, replace the __main__ guard with a direct call:
#
#   main()
#
# Or paste just the section you need and run inline.
# =============================================================================


# =============================================================================
# Foundry Code Workspace: checking conda environment
# =============================================================================
# In a Foundry Code Workspace, you can also check your conda environment
# from the terminal:
#
#   conda list | grep -E "pandas|numpy|sklearn|scipy|mlflow"
#
# To create a reproducible environment spec for your team:
#
#   conda env export > environment.yml
#
# Commit environment.yml to your Foundry repository so teammates can
# reproduce your exact environment.
# =============================================================================


# =============================================================================
# Submitting a package request (Advana/Jupiter)
# =============================================================================
# If a package you need is missing:
#
# 1. Check the Databricks Runtime release notes for your DBR version:
#    https://docs.databricks.com/release-notes/runtime/
#    Many packages are pre-installed but you need to know the exact import name.
#
# 2. If genuinely missing, options:
#    a. Submit a help desk ticket to the platform team requesting the package
#       at the cluster policy level
#    b. Download the .whl file through approved channels, upload to DBFS:
#          dbutils.fs.cp("file:/local/path/package.whl", "dbfs:/packages/package.whl")
#       Then install:
#          %pip install /dbfs/packages/package.whl
#    c. For Unity Catalog workspaces, upload to a UC Volume and reference that path
#
# 3. Document the package version you're using in your project README so
#    future maintainers know what environment the code was developed against.
# =============================================================================
