from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from kafka import KafkaProducer

from shared.config import KAFKA_BOOTSTRAP_SERVERS, RAW_EVENTS_TOPIC, RAW_EVENT_ARCHIVE_PATH


def replay_archive(
    path: str = RAW_EVENT_ARCHIVE_PATH,
    topic: str = RAW_EVENTS_TOPIC,
    limit: int | None = None,
    start_line: int = 1,
    sleep_seconds: float = 0.0,
) -> int:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    archive_path = Path(path)
    count = 0
    with archive_path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            if index < start_line:
                continue
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            producer.send(topic, payload)
            count += 1
            if limit is not None and count >= limit:
                break
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
    producer.flush()
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay archived raw events into Kafka.")
    parser.add_argument(
        "--path",
        default=RAW_EVENT_ARCHIVE_PATH,
        help="Path to the archived JSONL file.",
    )
    parser.add_argument(
        "--topic",
        default=RAW_EVENTS_TOPIC,
        help="Kafka topic to replay events into.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of events to replay.",
    )
    parser.add_argument(
        "--start-line",
        type=int,
        default=1,
        help="Line number to start replaying from.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.0,
        help="Optional delay between replayed events.",
    )
    args = parser.parse_args()
    replayed = replay_archive(
        path=args.path,
        topic=args.topic,
        limit=args.limit,
        start_line=args.start_line,
        sleep_seconds=args.sleep_seconds,
    )
    print(
        json.dumps(
            {
                "replayed_events": replayed,
                "path": args.path,
                "topic": args.topic,
            },
            indent=2,
        )
    )
