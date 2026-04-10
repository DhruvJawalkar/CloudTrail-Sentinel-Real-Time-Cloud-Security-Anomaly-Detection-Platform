# CloudTrail Sentinel

CloudTrail Sentinel is a production-style cloud security anomaly detection platform that ingests simulated cloud events, evaluates them in near real time, and surfaces alerts for analyst triage.

## Current status

This repository now implements **Phase 1 MVP**, **Phase 2 rolling features**, and the core of **Phase 3 hybrid ML scoring** from the phased plan:

- event generator with baseline and attack-like scenarios
- Kafka-compatible event ingestion with Redpanda
- Redis-backed rolling feature computation
- rules-based stream processing using online features
- offline Isolation Forest training pipeline
- FastAPI-based model serving for online scoring
- FastAPI alert persistence and retrieval
- Streamlit analyst dashboard

The repo structure also reserves the seams for the rest of Phase 3 and Phase 4:

- Parquet or Delta offline feature storage
- Isolation Forest-based anomaly scoring
- production hardening with DLQ, suppression, and metrics

## Architecture

```text
producer -> Redpanda/Kafka -> stream_processor -> FastAPI API -> Streamlit dashboard
                             |                 |
                             -> Redis          -> SQLite alert store
                             -> model_serving

batch path: simulator/features -> model_training -> Isolation Forest artifact -> model_serving
```

More detail lives in `docs/architecture.md`.

## Why This Project Works

This project is intentionally shaped to demonstrate the kinds of design trade-offs that come up in cloud, streaming, ML, and security interviews:

- streaming vs batch architecture
- online vs offline feature storage
- false positives vs false negatives
- low-latency model inference
- replay, reliability, and operational observability

## Event schema

Core event fields are defined in `shared/models.py` and include:

- `event_id`
- `timestamp`
- `account_id`
- `user_id`
- `principal_type`
- `source_ip`
- `geo_country`
- `region`
- `service_name`
- `api_action`
- `auth_result`
- `bytes_sent`
- `bytes_received`
- `is_privileged_action`

## Detection logic in Phase 3

The platform uses a deterministic rules engine in `stream_processor/detector.py`, Redis-backed rolling features, and an Isolation Forest model served through `model_serving` to detect:

- failed login bursts
- privileged actions from unseen countries
- deletion or terminate spikes
- unusually large data transfers
- contextual behavioral anomalies surfaced by the ML layer

The current feature snapshot includes:

- failed logins in 5 minutes and 1 hour
- request count in 5 minutes
- distinct IPs, countries, and regions in 24 hours
- privileged actions in 1 hour
- users seen from an IP in 24 hours
- IP failed auth rate in 5 minutes
- account delete actions in 10 minutes
- account service entropy in 1 hour
- account bytes received in 1 hour

Online features live in Redis for low-latency scoring, while validated event feature rows can now also be persisted into a local Delta table under `data/offline_features_delta` for offline training and backfills.

Each alert includes:

- severity
- anomaly score
- confidence
- reasons
- recommended actions
- feature context
- detection sources
- ML anomaly score, explanation, and model version
- full triggering event payload

Phase 3 alert types now include:

- `rule-only` alerts for deterministic detections without model corroboration
- `rule+ml` alerts when the model also flags the event and can elevate severity
- `ml-only` alerts for contextual outliers that are unusual in feature space but do not match a hardcoded rule

## Startup Hardening

The local Compose stack now includes healthchecks and dependency gating for Redis, Redpanda, the API, and the model service. The `stream_processor` also waits and retries on startup so it does not crash if Kafka or the model service takes a little longer to become ready.

## Alert Suppression

The API now applies a short suppression window so repeated alerts with the same fingerprint are collapsed into a single alert row instead of flooding the dashboard. Within the suppression window, the stored alert keeps:

- the original `created_at`
- an updated `last_seen_at`
- a `suppression_count` showing how many repeat alerts were collapsed
- the latest event and feature context for triage

The suppression window defaults to 5 minutes and can be tuned with `ALERT_SUPPRESSION_WINDOW_SECONDS`.

## Dead-Letter Handling

The `stream_processor` now routes failed events into a dead-letter path instead of relying only on logs.

- validation failures are written to a Kafka DLQ topic and persisted through the API
- processing or alert-delivery failures are also captured with stage, error type, retryability, and the raw payload
- the API exposes `/dead-letters` and `/dead-letters/summary` so failures can be inspected without building a separate DLQ consumer first

The DLQ topic defaults to `cloud-security-events-dlq` and can be tuned with `DEAD_LETTER_TOPIC`.

## Schema Validation And Idempotent Writes

The shared event schema now applies stricter validation before an event enters the detection flow. In addition to required fields, the model validates:

- non-empty identifiers and action fields
- valid IP address formatting
- 2-letter country codes
- non-negative byte counts
- timezone-aware timestamps

Alert writes are also idempotent for exact retries. If the same event-driven alert is delivered to the API more than once, the repository reuses the existing alert row instead of inserting a duplicate. This is separate from suppression:

- idempotency handles exact retry of the same alert
- suppression handles repeated similar alerts across different events within a short window

## Operational Metrics

The platform now exposes lightweight JSON metrics for the hot path:

- `api` exposes `/metrics` with alert-write, dead-letter, and persisted inventory counters
- `model_serving` exposes `/metrics` with scoring volume, anomaly counts, artifact state, and scoring latency
- `stream_processor` exposes `/metrics` on port `9101` with event-consumption rate, alert mix, DLQ activity, and end-to-end processing latency

The dashboard surfaces these metrics so you can demonstrate:

- ingest and alert throughput
- rule-only vs hybrid vs ML-only alert mix
- scoring latency
- DLQ activity and API persistence counts
- service health, recent dead-letter events, and raw failure payloads for triage

## Replay And Backfill

The `stream_processor` now archives every consumed raw payload to `data/raw_events.jsonl` before validation. That gives the project a simple replay and backfill path:

- valid and malformed events are both preserved in the raw archive
- the archive persists on the host through the Compose `data` volume
- archived events can be replayed back into Kafka with `python -m stream_processor.replay`

Example replay commands:

```bash
python -m stream_processor.replay --limit 100
python -m stream_processor.replay --start-line 500 --limit 200 --sleep-seconds 0.05
```

This is useful for:

- reprocessing historical events after detector changes
- reproducing bugs from captured payloads
- demonstrating a simple batch-to-stream replay workflow

## Offline Training Workflow

Model training is intentionally separate from `model_serving`.

- Run `py -3 -m model_training.train` during local development to generate artifacts directly under `model_training/artifacts/`
- Train from historically persisted Delta features with `py -3 -m model_training.train --source delta`
- `model_serving` now mounts `./model_training/artifacts` directly in Docker Compose, so freshly trained local artifacts are used without rebuilding the image
- If artifacts are missing, `model_serving` starts in a degraded state and reports that through `/health`
- `model_serving` also exposes `/metadata` and `/reload` for inspecting or reloading the currently available artifact

## Local run

### Option 1: Docker Compose

```bash
docker compose up --build
```

Then open:

- API docs: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501`

## Demo Script

A clean demo flow is:

1. Start the stack with `docker compose up --build`
2. Open the dashboard and show:
   - severity distribution
   - `rule-only`, `rule+ml`, and `ml-only` alert mix
   - ML explanation and feature context on a selected alert
3. Open the operational metrics section and show:
   - stream throughput
   - model scoring latency
   - dead-letter counts
4. Trigger one malformed event to show the DLQ path
5. Point to `data/raw_events.jsonl` and explain replay/backfill with `python -m stream_processor.replay`
6. Mention that the model artifact is trained offline and reloaded online through `model_serving`

## Suggested Screenshots

If you want to make the repo feel even more polished, add screenshots under `docs/` for:

- dashboard overview
- alert detail with ML explanation
- dead-letter activity panel
- operational metrics panel

## Strong Resume Bullets

- Built a production-style real-time cloud security anomaly detection platform using Redpanda/Kafka, Redis, FastAPI, and Streamlit to detect suspicious authentication and API behavior in near real time.
- Designed a hybrid detection pipeline combining deterministic security rules with Isolation Forest scoring, enabling `rule-only`, `rule+ml`, and `ml-only` alerts with feature-level explanations.
- Implemented production-hardening controls including schema validation, dead-letter handling, alert suppression, idempotent writes, service metrics, and replayable raw-event archiving for debugging and backfills.

## Interview Talking Points

### How do you process high event volumes?

Use partitioned Kafka topics, horizontally scaled processors, lightweight Redis feature lookups, and compact online inference. The demo runs locally, but the architecture is designed around horizontal scale rather than vertical scale.

### How do you manage false positives and false negatives?

Use layered detection:

- deterministic rules for high-confidence threats
- ML anomaly scoring for broader behavioral coverage
- suppression windows to reduce repetitive noise
- severity calibration when both rule and ML signals agree

### Why both batch and streaming?

Streaming is for real-time detection and alerting. Batch is for training, replay, backfills, and longer-horizon analysis. In practice the system needs both.

### Where do features live?

Hot online features live in Redis for low-latency scoring. Offline training features are generated for model training and can later move to Parquet or Delta for richer historical storage.

### How do you do model inference at scale?

Keep inference lightweight by scoring precomputed rolling features with a compact model service. If latency grows, move toward micro-batched or asynchronous scoring while keeping rule-based detection in the hot path.

### Option 2: Run services locally

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Start Redis plus a local Kafka-compatible broker such as Redpanda.
3. Run the API:

```bash
uvicorn api.app:app --reload
```

4. Run the stream processor:

```bash
python -m stream_processor.app
```

5. Run the producer:

```bash
python -m producer.app
```

6. Train the model locally so artifacts are written into the repo:

```bash
py -3 -m model_training.train
```

Optional tuning:

```bash
py -3 -m model_training.train --num-events 8000 --contamination 0.06
```

This creates:

- `model_training/artifacts/isolation_forest.pkl`
- `model_training/artifacts/metadata.json`
- `model_training/artifacts/training_dataset.csv`

7. Run the model service:

```bash
uvicorn model_serving.app:app --reload --port 8010
```

Useful endpoints:

- `http://localhost:8010/health`
- `http://localhost:8010/metadata`
- `http://localhost:8010/reload`

8. Run the dashboard:

```bash
streamlit run dashboard/app.py
```

## Repo layout

```text
api/                 FastAPI service for alert storage and retrieval
dashboard/           Streamlit analyst UI
docs/                Architecture and design notes
feature_store/       Redis-backed online feature logic
infra/               Infrastructure notes and future deployment assets
model_serving/       Online anomaly model serving
model_training/      Offline dataset generation and model training
producer/            Simulated cloud event producer
shared/              Shared schema and configuration
stream_processor/    Streaming rules engine
docker-compose.yml   Local development stack
requirements.txt     Python dependencies
```

## Planned next phases

### Phase 3 Next

- persist historical training data in Parquet or Delta
- add richer model evaluation and version promotion workflow
- introduce SHAP-like explanation or better feature attribution

### Phase 4: Production Hardening

- dead-letter queue
- retries and idempotency
- schema validation
- alert suppression
- metrics and operational dashboards

## Resume and interview story

This project is intentionally shaped to support discussion around:

- horizontal scaling for high event throughput
- batch plus streaming trade-offs
- online vs offline feature storage
- low-latency inference design
- false positive vs false negative controls
