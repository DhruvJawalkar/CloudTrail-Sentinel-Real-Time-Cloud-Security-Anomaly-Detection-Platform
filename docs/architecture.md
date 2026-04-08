# CloudTrail Sentinel Architecture

## Current Architecture

1. `producer` emits simulated cloud security events into Redpanda/Kafka.
2. `stream_processor` consumes raw events, updates Redis-backed rolling features, and evaluates detection rules.
3. `api` persists alerts plus feature context in SQLite and exposes them through FastAPI.
4. `dashboard` reads the API and presents analyst-facing alert views with feature snapshots.

## Implemented Phase 2

- Redis-backed rolling feature state.
- Per-user, per-IP, and per-account windows.
- Feature snapshots attached to alerts for drill-down.

## Planned Phase 3

- Add offline training data in Parquet or Delta.
- Train an Isolation Forest model.
- Serve the model through FastAPI or embedded inference.
- Blend ML score with rule outputs.

## Implemented Phase 3 Core

- Offline synthetic feature dataset generation.
- Isolation Forest training artifact generation.
- FastAPI model-serving endpoint for online scoring.
- Hybrid rule plus ML detection with alert metadata.

## Planned Phase 4

- Add schema validation, dead-letter handling, retries, metrics, and alert suppression.
- Introduce observability around consumer lag, scoring latency, and alert rates.
