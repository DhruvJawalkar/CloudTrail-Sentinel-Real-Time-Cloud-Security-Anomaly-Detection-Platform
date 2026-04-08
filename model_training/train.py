from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

from model_training.dataset import FEATURE_COLUMNS, build_training_dataframe

ARTIFACTS_DIR = Path("model_training/artifacts")
MODEL_PATH = ARTIFACTS_DIR / "isolation_forest.pkl"
METADATA_PATH = ARTIFACTS_DIR / "metadata.json"
DATASET_PATH = ARTIFACTS_DIR / "training_dataset.csv"


def train_model(num_events: int = 5000) -> dict[str, str]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    df = build_training_dataframe(num_events=num_events)
    df.to_csv(DATASET_PATH, index=False)

    X = _prepare_features(df)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
    )
    model.fit(X)

    medians = {column: float(X[column].median()) for column in FEATURE_COLUMNS}
    stds = {
        column: float(X[column].std(ddof=0)) if float(X[column].std(ddof=0)) > 1e-9 else 1.0
        for column in FEATURE_COLUMNS
    }

    with MODEL_PATH.open("wb") as handle:
        pickle.dump(model, handle)

    metadata = {
        "model_type": "IsolationForest",
        "model_version": datetime.now(timezone.utc).strftime("iforest-%Y%m%d%H%M%S"),
        "feature_columns": FEATURE_COLUMNS,
        "training_rows": len(df),
        "contamination": 0.08,
        "medians": medians,
        "stds": stds,
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {
        "model_path": str(MODEL_PATH),
        "metadata_path": str(METADATA_PATH),
        "dataset_path": str(DATASET_PATH),
        "model_version": metadata["model_version"],
    }


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURE_COLUMNS].copy()
    bool_columns = ["is_new_country_for_user", "is_new_ip_for_user"]
    for column in bool_columns:
        X[column] = X[column].astype(int)
    return X


if __name__ == "__main__":
    result = train_model()
    print(json.dumps(result, indent=2))
