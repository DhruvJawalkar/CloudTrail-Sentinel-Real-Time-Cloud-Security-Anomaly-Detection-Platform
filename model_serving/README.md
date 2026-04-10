# Phase 3 Model Serving

This package exposes the trained anomaly model for online inference.

Current implementation:

- `app.py` provides a FastAPI scoring API
- `service.py` loads the Isolation Forest artifact and metadata
- `/score` returns anomaly score, confidence, model version, top contributor hints, and a short explanation string

Expected workflow:

- Generate artifacts first with `py -3 -m model_training.train`
- Then start `model_serving`
- If artifacts are missing, the service stays up but reports a degraded health state and returns an unavailable model score

Useful endpoints:

- `/health` for readiness and artifact presence
- `/metadata` for model version, anomaly score percentiles, and scenario-level evaluation metadata
- `/reload` to force the service to reload the current artifact files
