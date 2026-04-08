from __future__ import annotations

import os


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "redpanda:9092")
RAW_EVENTS_TOPIC = os.getenv("RAW_EVENTS_TOPIC", "cloud-security-events")
ALERT_API_BASE_URL = os.getenv("ALERT_API_BASE_URL", "http://api:8000")
MODEL_API_BASE_URL = os.getenv("MODEL_API_BASE_URL", "http://model_serving:8010")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
EVENT_GENERATION_RATE = float(os.getenv("EVENT_GENERATION_RATE", "8"))
EVENT_GENERATION_BURST_PROBABILITY = float(
    os.getenv("EVENT_GENERATION_BURST_PROBABILITY", "0.08")
)
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "data/alerts.db")
