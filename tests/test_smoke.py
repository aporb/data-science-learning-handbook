"""
Smoke tests — verify that key standard-library and common data-science
modules are importable.  These tests require no project-specific fixtures
and act as a fast sanity check in CI.
"""

import importlib
import sys


def _importable(module_name: str) -> bool:
    """Return True if *module_name* can be imported, False otherwise."""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------

def test_stdlib_json():
    assert _importable("json"), "json (stdlib) must be importable"


def test_stdlib_os():
    assert _importable("os"), "os (stdlib) must be importable"


def test_stdlib_pathlib():
    assert _importable("pathlib"), "pathlib (stdlib) must be importable"


def test_stdlib_logging():
    assert _importable("logging"), "logging (stdlib) must be importable"


# ---------------------------------------------------------------------------
# Data science / ML ecosystem (soft checks — skip if not installed)
# ---------------------------------------------------------------------------

def test_numpy_importable():
    """numpy is a core dependency; warn but do not fail if absent."""
    if not _importable("numpy"):
        import pytest
        pytest.skip("numpy not installed — skipping smoke test")
    import numpy as np  # noqa: F401
    assert hasattr(np, "array")


def test_pandas_importable():
    if not _importable("pandas"):
        import pytest
        pytest.skip("pandas not installed — skipping smoke test")
    import pandas as pd  # noqa: F401
    assert hasattr(pd, "DataFrame")


def test_sklearn_importable():
    if not _importable("sklearn"):
        import pytest
        pytest.skip("scikit-learn not installed — skipping smoke test")
    import sklearn  # noqa: F401


def test_matplotlib_importable():
    if not _importable("matplotlib"):
        import pytest
        pytest.skip("matplotlib not installed — skipping smoke test")
    import matplotlib  # noqa: F401


# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

def test_python_version():
    """Require Python >= 3.9 (3.8 is EOL October 2024)."""
    assert sys.version_info >= (3, 9), (
        f"Python 3.9+ required, got {sys.version_info.major}.{sys.version_info.minor}"
    )
