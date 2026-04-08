# Phase 3 Model Serving

This package exposes the trained anomaly model for online inference.

Current implementation:

- `app.py` provides a FastAPI scoring API
- `service.py` loads the Isolation Forest artifact and metadata
- `/score` returns anomaly score, confidence, model version, and top contributor hints
