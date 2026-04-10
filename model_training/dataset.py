from __future__ import annotations

from typing import Any

import pandas as pd
from deltalake import DeltaTable

from feature_store.memory_store import InMemoryFeatureStore
from producer.simulator import EventSimulator
from shared.models import FeatureSnapshot, SecurityEvent


def build_training_dataframe(num_events: int = 5000) -> pd.DataFrame:
    simulator = EventSimulator()
    feature_store = InMemoryFeatureStore()
    rows: list[dict[str, Any]] = []

    for _ in range(num_events):
        event = simulator.next_event()
        features = feature_store.ingest_event(event)
        rows.append(build_feature_row(event, features))

    return pd.DataFrame(rows)


def build_training_dataframe_from_delta(
    delta_path: str,
    limit: int | None = None,
) -> pd.DataFrame:
    table = DeltaTable(delta_path)
    df = table.to_pandas()
    if limit is not None:
        df = df.tail(limit).reset_index(drop=True)
    return df


def build_feature_row(event: SecurityEvent, features: FeatureSnapshot) -> dict[str, Any]:
    event_date = event.timestamp.date().isoformat()
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "event_date": event_date,
        "cloud_provider": event.cloud_provider,
        "account_id": event.account_id,
        "user_id": event.user_id,
        "source_ip": event.source_ip,
        "geo_country": event.geo_country,
        "region": event.region,
        "service_name": event.service_name,
        "api_action": event.api_action,
        "principal_type": event.principal_type,
        "scenario": event.metadata.get("scenario", "unknown"),
        "is_privileged_action": int(event.is_privileged_action),
        "auth_failure": int(event.auth_result == "failure"),
        **features.model_dump(mode="json"),
    }


FEATURE_COLUMNS = [
    "failed_logins_5m",
    "failed_logins_1h",
    "request_count_5m",
    "distinct_ips_24h",
    "distinct_countries_24h",
    "distinct_regions_24h",
    "privileged_actions_1h",
    "ip_users_24h",
    "ip_failed_auth_rate_5m",
    "account_delete_actions_10m",
    "account_service_entropy_1h",
    "account_bytes_received_1h",
    "is_new_country_for_user",
    "is_new_ip_for_user",
    "is_privileged_action",
    "auth_failure",
]
