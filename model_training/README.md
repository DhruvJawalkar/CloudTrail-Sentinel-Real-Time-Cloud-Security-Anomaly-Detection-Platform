# Phase 3 Training Pipeline

This package now contains the offline training workflow for the anomaly model.

Current implementation:

- `dataset.py` generates feature rows from simulated events using an in-memory feature store
- `train.py` trains an Isolation Forest model
- artifacts include the serialized model, feature column list, metadata, and a training dataset snapshot

Typical usage:

- `python -m model_training.train`
