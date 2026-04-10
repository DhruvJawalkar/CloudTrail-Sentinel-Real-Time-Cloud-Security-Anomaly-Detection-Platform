from __future__ import annotations

import json
import math
import pickle
from pathlib import Path

import pandas as pd

from model_training.dataset import FEATURE_COLUMNS
from shared.models import FeatureSnapshot, ModelMetadata, ModelScore

ARTIFACTS_DIR = Path("model_training/artifacts")
MODEL_PATH = ARTIFACTS_DIR / "isolation_forest.pkl"
METADATA_PATH = ARTIFACTS_DIR / "metadata.json"


class ModelScoringService:
    def __init__(self) -> None:
        self.model = None
        self.metadata: dict[str, object] = {}
        self._load()

    def score(self, features: FeatureSnapshot) -> ModelScore:
        if self.model is None:
            return ModelScore(
                anomaly_score=0.0,
                confidence=0.0,
                predicted_anomaly=False,
                model_version="unavailable",
                top_contributors=[],
            )

        X = self._to_frame(features)
        raw_score = float(self.model.decision_function(X)[0])
        predicted_anomaly = bool(self.model.predict(X)[0] == -1)
        anomaly_score = round(1.0 / (1.0 + math.exp(raw_score * 3.5)), 4)
        confidence = round(abs(raw_score) / (abs(raw_score) + 0.5), 4)

        return ModelScore(
            anomaly_score=anomaly_score,
            confidence=confidence,
            predicted_anomaly=predicted_anomaly,
            model_version=str(self.metadata.get("model_version", "unknown")),
            top_contributors=self._top_contributors(features),
        )

    def _load(self) -> None:
        self.model = None
        self.metadata = {}
        if not MODEL_PATH.exists() or not METADATA_PATH.exists():
            return
        with MODEL_PATH.open("rb") as handle:
            self.model = pickle.load(handle)
        self.metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))

    def reload(self) -> ModelMetadata:
        self._load()
        return self.get_metadata()

    def get_metadata(self) -> ModelMetadata:
        return ModelMetadata(
            model_type=str(self.metadata.get("model_type", "IsolationForest")),
            model_version=str(self.metadata.get("model_version", "unavailable")),
            feature_columns=list(self.metadata.get("feature_columns", [])),
            training_rows=int(self.metadata.get("training_rows", 0)),
            contamination=float(self.metadata.get("contamination", 0.0)),
            artifact_present=bool(self.model is not None),
            trained_at=(
                str(self.metadata.get("trained_at"))
                if self.metadata.get("trained_at") is not None
                else None
            ),
        )

    def _to_frame(self, features: FeatureSnapshot) -> pd.DataFrame:
        values = features.model_dump(mode="json")
        row = {
            column: int(values[column]) if isinstance(values[column], bool) else values[column]
            for column in FEATURE_COLUMNS
        }
        return pd.DataFrame([row], columns=FEATURE_COLUMNS)

    def _top_contributors(self, features: FeatureSnapshot) -> list[str]:
        medians = self.metadata.get("medians", {})
        stds = self.metadata.get("stds", {})
        values = features.model_dump(mode="json")
        scored: list[tuple[str, float, object]] = []
        for column in FEATURE_COLUMNS:
            value = int(values[column]) if isinstance(values[column], bool) else float(values[column])
            median = float(medians.get(column, 0.0))
            std = float(stds.get(column, 1.0)) or 1.0
            scored.append((column, abs(value - median) / std, values[column]))

        scored.sort(key=lambda item: item[1], reverse=True)
        return [f"{column}={value}" for column, _, value in scored[:3]]
