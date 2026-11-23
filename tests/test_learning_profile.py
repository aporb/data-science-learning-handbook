"""Synthetic local checks. No government data, platform credentials, or live targets."""
import ast
import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_example(chapter, name):
    path = ROOT / "chapters" / chapter / "code-examples" / "python" / name
    spec = importlib.util.spec_from_file_location("example_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def bias():
    return load_example("12-ethics-governance", "01_bias_audit.py")


@pytest.fixture(scope="module")
def registry():
    return load_example("09-mlops", "02_model_registry_deployment.py")


def synthetic_outcomes():
    truth = np.tile([0, 1], 60)
    scores = np.r_[np.ones(24), np.zeros(36), np.ones(48), np.zeros(12)]
    groups = pd.Series(["A"] * 60 + ["B"] * 60)
    return truth, scores, groups


def test_bias_flags_favorable_outcome_disparity(bias):
    result = bias.bias_audit_report(*synthetic_outcomes()).set_index("group")
    assert result.loc["A", "favorable_rate"] == pytest.approx(0.6)
    assert result.loc["B", "favorable_rate"] == pytest.approx(0.2)
    assert result.loc["B", "dp_ratio"] == pytest.approx(1 / 3)
    assert result.loc["B", "dp_ratio"] < 0.8


def test_bias_small_groups_are_not_a_pass(bias):
    result = bias.bias_audit_report(np.zeros(4), np.zeros(4), pd.Series(["A"] * 4))
    assert result.empty
    assert "dp_ratio" in result
    assert not bias.equalized_odds_check(result)


def test_bias_undefined_rates_are_not_zero(bias):
    result = bias.bias_audit_report(np.ones(60), np.zeros(60), pd.Series(["A"] * 30 + ["B"] * 30))
    assert result["fpr"].isna().all()
    assert result["fpr_ratio"].isna().all()
    assert not bias.equalized_odds_check(result)


def test_bias_zero_favorable_reference_is_undefined(bias):
    result = bias.bias_audit_report(np.ones(30), np.ones(30), pd.Series(["A"] * 30))
    assert result["dp_ratio"].isna().all()


def test_bias_rejects_unknown_reference(bias):
    with pytest.raises(ValueError, match="Reference group"):
        bias.bias_audit_report(*synthetic_outcomes(), reference_group="missing")


@pytest.mark.parametrize("scores", [[1.5] * 30, [float("nan")] * 30])
def test_bias_rejects_invalid_probabilities(bias, scores):
    with pytest.raises(ValueError):
        bias.bias_audit_report(np.zeros(30), scores, pd.Series(["A"] * 30))


def test_prose_bias_functions_execute_and_match_the_example(bias):
    text = (ROOT / "chapters/12-ethics-governance/README.md").read_text()
    blocks = re.findall(r"```python\n(.*?)\n```", text, re.S)
    block = next(code for code in blocks if "def bias_audit_report(" in code)
    # Execute imports and definitions only. The surrounding notebook context is not supplied.
    tree = ast.parse(block, feature_version=(3, 11))
    definitions = ast.Module(body=[n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))], type_ignores=[])
    namespace = {}
    exec(compile(definitions, "chapter-12-prose", "exec"), namespace)
    actual = namespace["bias_audit_report"](*synthetic_outcomes())
    expected = bias.bias_audit_report(*synthetic_outcomes())
    pd.testing.assert_frame_equal(actual, expected)
    assert not namespace["equalized_odds_check"](actual)


def test_uc_uses_aliases_not_stages(registry):
    client = Mock()
    client.get_model_version_by_alias.return_value = SimpleNamespace(version="7")
    with patch.object(registry, "MlflowClient", return_value=client):
        manager = registry.ModelRegistryManager("catalog.schema.model")
        assert manager.get_current_production_version() == "7"
        client.get_model_version_by_alias.assert_called_once_with("catalog.schema.model", "champion")
        client.get_latest_versions.assert_not_called()
        manager.promote_to_production("8", "Synthetic reviewer", "Synthetic test approval")
        client.set_registered_model_alias.assert_called_once_with("catalog.schema.model", "champion", "8")
        client.transition_model_version_stage.assert_not_called()
        calls = [call[0] for call in client.mock_calls]
        assert calls.index("update_model_version") < calls.index("set_registered_model_alias")


def test_legacy_backend_is_explicit(registry):
    client = Mock()
    client.get_latest_versions.return_value = [SimpleNamespace(version="2")]
    with patch.object(registry, "MlflowClient", return_value=client):
        manager = registry.ModelRegistryManager("old-model", registry_backend="legacy")
        assert manager.get_current_production_version() == "2"
        manager.promote_to_production("3", "Synthetic reviewer", "Synthetic approval")
        client.transition_model_version_stage.assert_called_once_with(
            name="old-model", version="3", stage="Production", archive_existing_versions=True
        )
        client.set_registered_model_alias.assert_not_called()


def test_uc_permission_failure_is_not_reported_as_absent(registry):
    from mlflow.exceptions import MlflowException
    from mlflow.protos.databricks_pb2 import PERMISSION_DENIED, RESOURCE_DOES_NOT_EXIST
    client = Mock()
    client.get_model_version_by_alias.side_effect = MlflowException("Synthetic denial", error_code=PERMISSION_DENIED)
    with patch.object(registry, "MlflowClient", return_value=client):
        manager = registry.ModelRegistryManager("catalog.schema.model")
        with pytest.raises(MlflowException):
            manager.get_current_production_version()


def test_uc_missing_alias_returns_none(registry):
    from mlflow.exceptions import MlflowException
    from mlflow.protos.databricks_pb2 import PERMISSION_DENIED, RESOURCE_DOES_NOT_EXIST
    client = Mock()
    client.get_model_version_by_alias.side_effect = MlflowException("Synthetic missing alias", error_code=RESOURCE_DOES_NOT_EXIST)
    with patch.object(registry, "MlflowClient", return_value=client):
        assert registry.ModelRegistryManager("catalog.schema.model").get_current_production_version() is None


@pytest.mark.parametrize("backend, expected", [("unity_catalog", "models:/catalog.schema.model@champion"), ("legacy", "models:/catalog.schema.model/Production")])
def test_registry_loading_uses_correct_uri(registry, backend, expected):
    with patch.object(registry.mlflow.sklearn, "load_model") as load:
        registry.load_production_model("catalog.schema.model", registry_backend=backend)
        load.assert_called_once_with(expected)


def test_uc_requires_three_part_name(registry):
    with pytest.raises(ValueError, match="three|catalog.schema.model"):
        registry.ModelRegistryManager("unqualified")


def test_profile_dataframe_on_synthetic_records():
    profiling = load_example("05-exploratory-analysis", "01_statistical_profiling.py")
    frame = pd.DataFrame({"amount": [1.0, np.nan, 3.0], "office": ["A", "A", "B"]})
    report = profiling.profile_dataframe(frame)
    assert report["shape"] == {"rows": 3, "columns": 2}
    assert report["null_analysis"]["null_count"]["amount"] == 1
    assert report["categorical_stats"]["office"]["unique_values"] == 2
