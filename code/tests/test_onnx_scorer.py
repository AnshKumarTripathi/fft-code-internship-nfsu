"""Unit tests for Phase 53 ONNX scorer + attribution helpers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from src.detectors.ml.attribution import (
    attribution_from_residuals,
    feature_names,
    rank_contributions,
)
from src.detectors.ml.isolation_forest import FeatureVocab, TemplateWindow
from src.detectors.ml.onnx_scorer import (
    ModelNotConfiguredError,
    score_windows_onnx,
    sidecar_path_for,
)


def _windows(n: int = 12) -> list[TemplateWindow]:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    rows: list[TemplateWindow] = []
    for i in range(n):
        rows.append(
            TemplateWindow(
                entity_id="user:bob",
                window_start=start + timedelta(hours=i),
                window_end=start + timedelta(hours=i + 1),
                template_ids=("t_a", "t_b", "t_a", "t_b", "t_a"),
            )
        )
    return rows


def _write_identity_onnx(path: Path, n_features: int) -> None:
    from onnx import TensorProto, helper, save

    x = helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, n_features])
    y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, n_features])
    node = helper.make_node("Identity", ["X"], ["Y"])
    graph = helper.make_graph([node], "ae_identity", [x], [y])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    path.parent.mkdir(parents=True, exist_ok=True)
    save(model, str(path))


def test_attribution_rank_stable() -> None:
    names = ["tmpl:a", "tmpl:b", "seq_len"]
    ranked = rank_contributions(np.asarray([0.1, 0.9, 0.2]), names, top_k=2)
    assert ranked[0]["name"] == "tmpl:b"
    assert ranked[1]["name"] == "seq_len"


def test_attribution_from_residuals_maps_templates() -> None:
    vocab = FeatureVocab(top_templates=("t_a", "t_b"), top_bigrams=(("t_a", "t_b"),))
    names = feature_names(vocab)
    residuals = np.zeros(len(names), dtype=np.float64)
    residuals[0] = 3.0  # tmpl:t_a
    payload = attribution_from_residuals(residuals, vocab, top_k=3)
    templates = payload["top_templates"]
    assert templates
    assert templates[0]["template_id"] == "t_a"


def test_onnx_missing_path_raises() -> None:
    with pytest.raises(ModelNotConfiguredError, match="onnx_model_path"):
        score_windows_onnx(_windows(), onnx_model_path=None)


def test_onnx_identity_scores_end_to_end(tmp_path: Path) -> None:
    vocab = FeatureVocab(top_templates=("t_a", "t_b"), top_bigrams=(("t_a", "t_b"),))
    names = feature_names(vocab)
    n_features = len(names)
    model_path = tmp_path / "ae.onnx"
    _write_identity_onnx(model_path, n_features)
    sidecar = {
        "score_kind": "ae_mse",
        "input_name": "X",
        "output_index": 0,
        "top_templates": list(vocab.top_templates),
        "top_bigrams": [list(pair) for pair in vocab.top_bigrams],
        "feature_names": names,
        "scaler_mean": [0.0] * n_features,
        "scaler_scale": [1.0] * n_features,
    }
    sidecar_path_for(model_path).write_text(json.dumps(sidecar), encoding="utf-8")

    rows = score_windows_onnx(
        _windows(),
        onnx_model_path=model_path,
        flagging="mad_threshold",
        mad_k=4.0,
    )
    assert len(rows) == 12
    # Perfect reconstruction → MSE ~ 0
    assert all(row.model_score == pytest.approx(0.0, abs=1e-5) for row in rows)
