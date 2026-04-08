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

Each alert includes:

- severity
- anomaly score
- confidence
- reasons
- recommended actions
- feature context
- detection sources
- ML anomaly score and model version
- full triggering event payload

## Local run

### Option 1: Docker Compose

```bash
docker compose up --build
```

Then open:

- API docs: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501`

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

6. Train the model:

```bash
python -m model_training.train
```

7. Run the model service:

```bash
uvicorn model_serving.app:app --reload --port 8010
```

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
