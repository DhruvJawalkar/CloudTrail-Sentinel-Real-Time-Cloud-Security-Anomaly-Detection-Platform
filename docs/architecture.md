# CloudTrail Sentinel Architecture

## System Overview

CloudTrail Sentinel has two paths:

- a streaming path for low-latency detection and analyst-facing alerts
- a batch path for offline training, replay, and reproducible model updates

```text
streaming path
producer -> Redpanda/Kafka -> stream_processor -> FastAPI API -> Streamlit dashboard
                             |                 |
                             |                 -> SQLite alert store + dead-letter store
                             |
                             -> Redis online features
                             -> Delta offline features
                             -> model_serving
                             -> raw JSONL archive
                             -> Kafka DLQ

batch path
simulator/features -> model_training -> Isolation Forest artifact -> model_serving
raw JSONL archive -> stream_processor.replay -> Redpanda/Kafka -> stream_processor
```

## Component Roles

### `producer`

- emits baseline and attack-like cloud security events
- supports realistic scenarios like failed login bursts, delete bursts, privileged new-country activity, and low-and-slow ML-friendly anomalies

### `stream_processor`

- consumes raw events from Kafka
- archives each raw payload before validation
- validates events with the shared schema
- updates Redis-backed rolling features
- requests online ML scoring from `model_serving`
- evaluates hybrid detection logic in `detector.py`
- emits alerts to the API
- routes failed records to Kafka and API-backed dead-letter handling
- exposes hot-path metrics on port `9101`

### `Redis`

- stores low-latency online features and recent behavioral state
- supports per-user, per-IP, and per-account windows
- enables hot-path inference without scanning historical storage

### `Delta offline features`

- persists validated per-event feature rows from the stream path
- supports offline retraining from historical feature data
- complements Redis by acting as the simple offline feature store for this project

### `model_training`

- generates synthetic feature datasets offline
- trains an Isolation Forest artifact
- writes model metadata, feature stats, and training snapshots

### `model_serving`

- loads the locally trained artifact
- performs online scoring for each event feature snapshot
- returns anomaly score, confidence, explanation, and model version
- exposes metadata and scoring metrics

### `api`

- persists alerts and dead-letter records
- applies suppression and idempotent alert writes
- exposes alerts, summaries, dead letters, and API metrics

### `dashboard`

- shows alert severity, hybrid detection mix, ML details, and feature context
- shows service health, operational metrics, and dead-letter activity
- gives analysts enough context to triage without digging through logs

## Detection Flow

1. A raw event lands in Kafka.
2. The stream processor archives the payload to `data/raw_events.jsonl`.
3. The shared `SecurityEvent` schema validates the payload.
4. Redis rolling features are updated and returned as a `FeatureSnapshot`.
5. The feature snapshot is scored by the Isolation Forest model service.
6. The rules engine combines rules plus ML context to generate:
   - `rule-only`
   - `rule+ml`
   - `ml-only`
7. The API persists alerts with suppression and idempotency controls.
8. The dashboard renders alerts, metrics, and DLQ activity.

## Reliability Controls

- startup dependency gating for Redpanda, Redis, API, and model service
- dead-letter handling for validation, processing, and delivery failures
- idempotent alert writes for exact retries
- suppression windows for repetitive alerts
- raw-event archive plus replay/backfill support
- JSON metrics endpoints for the API, model service, and stream processor

## Current Maturity By Phase

### Phase 1 Implemented

- event generator
- Kafka-compatible ingestion
- rule-based detection
- alert API
- dashboard

### Phase 2 Implemented

- Redis-backed online feature store
- rolling windows across user, IP, and account dimensions
- feature context attached to alerts

### Phase 3 Implemented

- offline feature dataset generation
- Isolation Forest training
- online model serving
- hybrid rule plus ML alerts
- model metadata and explanation flow

### Phase 4 Implemented So Far

- schema validation
- dead-letter handling
- suppression and deduplication
- idempotent writes
- operational metrics
- replay/backfill support

## Next Logical Extensions

- store historical raw and curated data in Parquet or Delta Lake
- add a model promotion workflow and artifact history
- add analyst feedback labeling for supervised refinement
- add richer evaluation and explanation views
