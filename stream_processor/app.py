from __future__ import annotations

import json
import logging
import time

import requests
from kafka.errors import NoBrokersAvailable
from kafka import KafkaConsumer

from feature_store.redis_store import RedisFeatureStore
from shared.config import (
    ALERT_API_BASE_URL,
    KAFKA_BOOTSTRAP_SERVERS,
    MODEL_API_BASE_URL,
    RAW_EVENTS_TOPIC,
)
from shared.models import ModelScore, SecurityEvent
from stream_processor.detector import RulesEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger(__name__)
STARTUP_RETRY_SECONDS = 2
STARTUP_MAX_ATTEMPTS = 30


def main() -> None:
    _wait_for_http_dependency(f"{ALERT_API_BASE_URL}/health", "alert API")
    _wait_for_http_dependency(f"{MODEL_API_BASE_URL}/health", "model service")
    feature_store = _build_feature_store_with_retry()
    consumer = _build_consumer_with_retry()
    rules_engine = RulesEngine()

    for record in consumer:
        try:
            event = SecurityEvent.model_validate(record.value)
            features = feature_store.ingest_event(event)
            model_score = _score_event(features)
            alerts = rules_engine.evaluate(event, features, model_score)
            for alert in alerts:
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
        except requests.RequestException as exc:
            LOGGER.warning("Alert API unavailable, retrying event later: %s", exc)
            time.sleep(1)
        except Exception as exc:
            LOGGER.exception("Failed to process event: %s", exc)


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


if __name__ == "__main__":
    main()
