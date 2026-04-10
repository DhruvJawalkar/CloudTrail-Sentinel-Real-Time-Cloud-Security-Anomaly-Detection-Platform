from __future__ import annotations

import atexit
import json
import logging
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import requests
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable
from pydantic import ValidationError

from feature_store.offline_delta import OfflineDeltaFeatureStore
from feature_store.redis_store import RedisFeatureStore
from shared.archive import append_jsonl
from shared.config import (
    ALERT_API_BASE_URL,
    DEAD_LETTER_TOPIC,
    KAFKA_BOOTSTRAP_SERVERS,
    MODEL_API_BASE_URL,
    OFFLINE_FEATURES_DELTA_PATH,
    OFFLINE_FEATURES_FLUSH_ROWS,
    RAW_EVENTS_TOPIC,
    RAW_EVENT_ARCHIVE_PATH,
    STREAM_PROCESSOR_METRICS_PORT,
)
from shared.metrics import MetricsCollector
from shared.models import DeadLetterCreate, ModelScore, SecurityEvent
from stream_processor.detector import RulesEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger(__name__)
STARTUP_RETRY_SECONDS = 2
STARTUP_MAX_ATTEMPTS = 30
METRICS = MetricsCollector(service_name="stream_processor")


def main() -> None:
    _start_metrics_server()
    _wait_for_http_dependency(f"{ALERT_API_BASE_URL}/health", "alert API")
    _wait_for_http_dependency(f"{MODEL_API_BASE_URL}/health", "model service")
    feature_store = _build_feature_store_with_retry()
    offline_feature_store = OfflineDeltaFeatureStore(
        delta_path=OFFLINE_FEATURES_DELTA_PATH,
        flush_rows=OFFLINE_FEATURES_FLUSH_ROWS,
    )
    atexit.register(offline_feature_store.flush)
    consumer = _build_consumer_with_retry()
    dlq_producer = _build_producer_with_retry()
    rules_engine = RulesEngine()

    for record in consumer:
        event_started = time.perf_counter()
        try:
            METRICS.increment("events_consumed")
            append_jsonl(RAW_EVENT_ARCHIVE_PATH, _normalize_raw_payload(record.value))
            METRICS.increment("events_archived")
            event = SecurityEvent.model_validate(record.value)
            features = feature_store.ingest_event(event)
            offline_feature_store.ingest_event(event, features)
            METRICS.increment("offline_feature_rows_buffered")
            scoring_started = time.perf_counter()
            model_score = _score_event(features)
            METRICS.record_latency("model_scoring", time.perf_counter() - scoring_started)
            if model_score.model_version == "unavailable":
                METRICS.increment("model_unavailable")
            alerts = rules_engine.evaluate(event, features, model_score)
            METRICS.set_gauge("last_event_alert_count", len(alerts))
            for alert in alerts:
                try:
                    response = requests.post(
                        f"{ALERT_API_BASE_URL}/alerts",
                        json=alert.model_dump(mode="json"),
                        timeout=5,
                    )
                    response.raise_for_status()
                    LOGGER.info(
                        "Alert emitted severity=%s title=%s event_id=%s",
                        alert.severity,
                        alert.title,
                        event.event_id,
                    )
                    METRICS.increment("alerts_emitted")
                    METRICS.increment(f"alerts_emitted_{alert.severity}")
                    category = _alert_metric_category(alert.detection_sources)
                    METRICS.increment(f"alerts_emitted_{category}")
                except requests.RequestException as exc:
                    LOGGER.warning("Alert API unavailable, routing event to dead-letter queue: %s", exc)
                    METRICS.increment("alert_delivery_failures")
                    _publish_dead_letter(
                        dlq_producer,
                        DeadLetterCreate(
                            failed_at=datetime.now(timezone.utc),
                            source_topic=RAW_EVENTS_TOPIC,
                            stage="alert_delivery",
                            error_type=type(exc).__name__,
                            error_message=str(exc),
                            raw_payload=record.value,
                            event_id=event.event_id,
                            retryable=True,
                        ),
                    )
                    time.sleep(1)
        except ValidationError as exc:
            LOGGER.warning("Event validation failed, routing to dead-letter queue: %s", exc)
            METRICS.increment("validation_failures")
            _publish_dead_letter(
                dlq_producer,
                DeadLetterCreate(
                    failed_at=datetime.now(timezone.utc),
                    source_topic=RAW_EVENTS_TOPIC,
                    stage="validation",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    raw_payload=record.value,
                    event_id=record.value.get("event_id") if isinstance(record.value, dict) else None,
                    retryable=False,
                ),
            )
        except Exception as exc:
            LOGGER.exception("Failed to process event: %s", exc)
            METRICS.increment("stream_processing_failures")
            _publish_dead_letter(
                dlq_producer,
                DeadLetterCreate(
                    failed_at=datetime.now(timezone.utc),
                    source_topic=RAW_EVENTS_TOPIC,
                    stage="stream_processing",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    raw_payload=record.value if isinstance(record.value, dict) else {"raw": str(record.value)},
                    event_id=record.value.get("event_id") if isinstance(record.value, dict) else None,
                    retryable=True,
                ),
            )
        finally:
            METRICS.record_latency("event_processing", time.perf_counter() - event_started)


def _score_event(features) -> ModelScore:
    try:
        response = requests.post(
            f"{MODEL_API_BASE_URL}/score",
            json=features.model_dump(mode="json"),
            timeout=5,
        )
        response.raise_for_status()
        return ModelScore.model_validate(response.json())
    except requests.RequestException as exc:
        LOGGER.warning("Model service unavailable, proceeding with rules only: %s", exc)
        return ModelScore()


def _wait_for_http_dependency(url: str, service_name: str) -> None:
    for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
        try:
            response = requests.get(url, timeout=3)
            response.raise_for_status()
            LOGGER.info("%s is ready", service_name)
            return
        except requests.RequestException as exc:
            LOGGER.info(
                "Waiting for %s (attempt %s/%s): %s",
                service_name,
                attempt,
                STARTUP_MAX_ATTEMPTS,
                exc,
            )
            time.sleep(STARTUP_RETRY_SECONDS)
    raise RuntimeError(f"{service_name} did not become ready in time")


def _build_feature_store_with_retry() -> RedisFeatureStore:
    for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
        try:
            feature_store = RedisFeatureStore()
            feature_store.client.ping()
            LOGGER.info("redis feature store is ready")
            return feature_store
        except Exception as exc:
            LOGGER.info(
                "Waiting for redis feature store (attempt %s/%s): %s",
                attempt,
                STARTUP_MAX_ATTEMPTS,
                exc,
            )
            time.sleep(STARTUP_RETRY_SECONDS)
    raise RuntimeError("redis feature store did not become ready in time")


def _build_consumer_with_retry() -> KafkaConsumer:
    for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
        try:
            consumer = KafkaConsumer(
                RAW_EVENTS_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                group_id="cloudtrail-sentinel-rules",
            )
            LOGGER.info("kafka consumer is ready")
            return consumer
        except NoBrokersAvailable as exc:
            LOGGER.info(
                "Waiting for Kafka broker (attempt %s/%s): %s",
                attempt,
                STARTUP_MAX_ATTEMPTS,
                exc,
            )
            time.sleep(STARTUP_RETRY_SECONDS)
    raise RuntimeError("Kafka broker did not become ready in time")


def _build_producer_with_retry() -> KafkaProducer:
    for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            )
            LOGGER.info("kafka producer is ready")
            return producer
        except NoBrokersAvailable as exc:
            LOGGER.info(
                "Waiting for Kafka producer (attempt %s/%s): %s",
                attempt,
                STARTUP_MAX_ATTEMPTS,
                exc,
            )
            time.sleep(STARTUP_RETRY_SECONDS)
    raise RuntimeError("Kafka producer did not become ready in time")


def _publish_dead_letter(producer: KafkaProducer, payload: DeadLetterCreate) -> None:
    body = payload.model_dump(mode="json")
    try:
        producer.send(DEAD_LETTER_TOPIC, body)
        producer.flush()
        METRICS.increment("dead_letters_published")
        METRICS.increment(f"dead_letters_published_{payload.stage}")
    except Exception as exc:
        LOGGER.exception("Failed to publish dead-letter message to Kafka: %s", exc)

    try:
        response = requests.post(
            f"{ALERT_API_BASE_URL}/dead-letters",
            json=body,
            timeout=5,
        )
        response.raise_for_status()
        METRICS.increment("dead_letters_persisted")
    except requests.RequestException as exc:
        LOGGER.warning("Failed to persist dead-letter record via API: %s", exc)


def _normalize_raw_payload(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {"raw": str(value)}


def _alert_metric_category(detection_sources: list[str]) -> str:
    sources = set(detection_sources)
    if sources == {"ml"}:
        return "ml_only"
    if sources == {"rule"}:
        return "rule_only"
    if "rule" in sources and "ml" in sources:
        return "rule_plus_ml"
    return "unknown"


def _start_metrics_server() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", STREAM_PROCESSOR_METRICS_PORT), _MetricsHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    LOGGER.info("stream processor metrics server listening on port %s", STREAM_PROCESSOR_METRICS_PORT)


class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(METRICS.snapshot()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


if __name__ == "__main__":
    main()
