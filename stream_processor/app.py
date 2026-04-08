from __future__ import annotations

import json
import logging
import time

import requests
from kafka import KafkaConsumer

from feature_store.redis_store import RedisFeatureStore
from shared.config import ALERT_API_BASE_URL, KAFKA_BOOTSTRAP_SERVERS, RAW_EVENTS_TOPIC
from shared.models import SecurityEvent
from stream_processor.detector import RulesEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger(__name__)


def main() -> None:
    consumer = KafkaConsumer(
        RAW_EVENTS_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        group_id="cloudtrail-sentinel-rules",
    )
    rules_engine = RulesEngine()
    feature_store = RedisFeatureStore()

    for record in consumer:
        try:
            event = SecurityEvent.model_validate(record.value)
            features = feature_store.ingest_event(event)
            alerts = rules_engine.evaluate(event, features)
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


if __name__ == "__main__":
    main()
