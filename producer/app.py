from __future__ import annotations

import json
import random
import time

from kafka import KafkaProducer

from producer.simulator import EventSimulator
from shared.config import (
    EVENT_GENERATION_BURST_PROBABILITY,
    EVENT_GENERATION_RATE,
    KAFKA_BOOTSTRAP_SERVERS,
    RAW_EVENTS_TOPIC,
)


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    simulator = EventSimulator()

    while True:
        events_this_tick = 4 if random.random() < EVENT_GENERATION_BURST_PROBABILITY else 1
        for _ in range(events_this_tick):
            event = simulator.next_event()
            producer.send(RAW_EVENTS_TOPIC, event.model_dump(mode="json"))
        producer.flush()
        time.sleep(max(0.01, 1.0 / EVENT_GENERATION_RATE))


if __name__ == "__main__":
    main()

