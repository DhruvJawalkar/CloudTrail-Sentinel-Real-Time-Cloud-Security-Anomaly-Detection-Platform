from __future__ import annotations

import argparse
import json
import math
import pickle
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

from model_training.dataset import (
    FEATURE_COLUMNS,
    build_training_dataframe,
    build_training_dataframe_from_delta,
)
from shared.config import OFFLINE_FEATURES_DELTA_PATH

ARTIFACTS_DIR = Path("model_training/artifacts")
MODEL_PATH = ARTIFACTS_DIR / "isolation_forest.pkl"
METADATA_PATH = ARTIFACTS_DIR / "metadata.json"
DATASET_PATH = ARTIFACTS_DIR / "training_dataset.csv"


def train_model(
    num_events: int = 5000,
    contamination: float = 0.08,
    source: str = "synthetic",
    delta_path: str = OFFLINE_FEATURES_DELTA_PATH,
    delta_limit: int | None = None,
) -> dict[str, str]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    if source == "delta":
        df = build_training_dataframe_from_delta(delta_path=delta_path, limit=delta_limit)
    else:
        df = build_training_dataframe(num_events=num_events)
    df.to_csv(DATASET_PATH, index=False)

    X = _prepare_features(df)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)
    predictions = model.predict(X)
    anomaly_fraction = float((predictions == -1).mean())
    raw_scores = model.decision_function(X)
    anomaly_scores = 1.0 / (1.0 + pd.Series(raw_scores).mul(3.5).map(math.exp))

    medians = {column: float(X[column].median()) for column in FEATURE_COLUMNS}
    stds = {
        column: float(X[column].std(ddof=0)) if float(X[column].std(ddof=0)) > 1e-9 else 1.0
        for column in FEATURE_COLUMNS
    }
    scenario_breakdown = _scenario_breakdown(df, predictions)
    percentiles = {
        "p50": float(anomaly_scores.quantile(0.50)),
        "p90": float(anomaly_scores.quantile(0.90)),
        "p95": float(anomaly_scores.quantile(0.95)),
        "p99": float(anomaly_scores.quantile(0.99)),
    }

    with MODEL_PATH.open("wb") as handle:
        pickle.dump(model, handle)

    metadata = {
        "model_type": "IsolationForest",
        "model_version": datetime.now(timezone.utc).strftime("iforest-%Y%m%d%H%M%S"),
        "feature_columns": FEATURE_COLUMNS,
        "training_rows": len(df),
        "contamination": contamination,
        "training_source": source,
        "observed_anomaly_fraction": anomaly_fraction,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "scenario_breakdown": scenario_breakdown,
        "anomaly_score_percentiles": percentiles,
        "medians": medians,
        "stds": stds,
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {
        "model_path": str(MODEL_PATH),
        "metadata_path": str(METADATA_PATH),
        "dataset_path": str(DATASET_PATH),
        "model_version": metadata["model_version"],
        "training_rows": str(len(df)),
        "contamination": str(contamination),
        "training_source": source,
    }


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURE_COLUMNS].copy()
    bool_columns = ["is_new_country_for_user", "is_new_ip_for_user"]
    for column in bool_columns:
        X[column] = X[column].astype(int)
    return X


def _scenario_breakdown(df: pd.DataFrame, predictions) -> dict[str, dict[str, float]]:
    tmp = df[["scenario"]].copy()
    tmp["predicted_anomaly"] = (predictions == -1).astype(int)
    grouped = tmp.groupby("scenario").agg(
        count=("scenario", "size"),
        predicted_anomalies=("predicted_anomaly", "sum"),
    )
    result: dict[str, dict[str, float]] = {}
    for scenario, row in grouped.iterrows():
        count = int(row["count"])
        predicted = int(row["predicted_anomalies"])
        result[str(scenario)] = {
            "count": count,
            "predicted_anomalies": predicted,
            "predicted_anomaly_rate": round(predicted / count, 4) if count else 0.0,
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the CloudTrail Sentinel Isolation Forest model.")
    parser.add_argument(
        "--num-events",
        type=int,
        default=5000,
        help="Number of simulated events to generate for training.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.08,
        help="Expected anomaly fraction for Isolation Forest.",
    )
    parser.add_argument(
        "--source",
        choices=["synthetic", "delta"],
        default="synthetic",
        help="Whether to train from freshly simulated features or the offline Delta table.",
    )
    parser.add_argument(
        "--delta-path",
        default=OFFLINE_FEATURES_DELTA_PATH,
        help="Path to the offline Delta feature table.",
    )
    parser.add_argument(
        "--delta-limit",
        type=int,
        default=None,
        help="Optional number of most recent Delta rows to train on.",
    )
    args = parser.parse_args()
    result = train_model(
        num_events=args.num_events,
        contamination=args.contamination,
        source=args.source,
        delta_path=args.delta_path,
        delta_limit=args.delta_limit,
    )
    print(json.dumps(result, indent=2))
