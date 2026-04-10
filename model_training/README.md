# Phase 3 Training Pipeline

This package now contains the offline training workflow for the anomaly model.

Current implementation:

- `dataset.py` generates feature rows from simulated events using an in-memory feature store
- `train.py` trains an Isolation Forest model
- artifacts include the serialized model, feature column list, metadata, and a training dataset snapshot

Typical usage:

- `py -3 -m model_training.train`
- `py -3 -m model_training.train --num-events 8000 --contamination 0.06`

Artifacts are written to:

- `model_training/artifacts/isolation_forest.pkl`
- `model_training/artifacts/metadata.json`
- `model_training/artifacts/training_dataset.csv`

Metadata includes:

- model version
- training row count
- contamination setting
- observed anomaly fraction
- feature medians and standard deviations used for explanation hints
