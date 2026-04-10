from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from datetime import timezone

from shared.models import FeatureSnapshot, SecurityEvent


class InMemoryFeatureStore:
    def __init__(self) -> None:
        self.user_requests: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.user_failed_logins: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.user_privileged_actions: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.user_dimensions: dict[tuple[str, str], deque[tuple[int, str]]] = defaultdict(deque)
        self.user_known_countries: dict[str, set[str]] = defaultdict(set)
        self.user_known_ips: dict[str, set[str]] = defaultdict(set)
        self.ip_users: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.ip_failed_auth: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.ip_requests: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.account_delete_actions: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.account_services: dict[str, deque[tuple[int, str]]] = defaultdict(deque)
        self.account_bytes: dict[str, deque[tuple[int, int]]] = defaultdict(deque)

    def ingest_event(self, event: SecurityEvent) -> FeatureSnapshot:
        event_ts = self._event_timestamp(event)

        prior_country_seen = event.geo_country in self.user_known_countries[event.user_id]
        prior_ip_seen = event.source_ip in self.user_known_ips[event.user_id]
        had_country_history = bool(self.user_known_countries[event.user_id])
        had_ip_history = bool(self.user_known_ips[event.user_id])

        self._append(self.user_requests[event.user_id], event_ts, event.event_id, 3600)
        self._append(self.ip_requests[event.source_ip], event_ts, event.event_id, 3600)

        if event.auth_result == "failure":
            self._append(self.user_failed_logins[event.user_id], event_ts, event.event_id, 3600)
            self._append(self.ip_failed_auth[event.source_ip], event_ts, event.event_id, 3600)

        if event.is_privileged_action:
            self._append(
                self.user_privileged_actions[event.user_id], event_ts, event.event_id, 3600
            )

        if self._is_delete_like_action(event.api_action):
            self._append(
                self.account_delete_actions[event.account_id], event_ts, event.event_id, 3600
            )

        self._append(
            self.user_dimensions[(event.user_id, "ips")],
            event_ts,
            f"{event.source_ip}|{event.event_id}",
            86400,
        )
        self._append(
            self.user_dimensions[(event.user_id, "countries")],
            event_ts,
            f"{event.geo_country}|{event.event_id}",
            86400,
        )
        self._append(
            self.user_dimensions[(event.user_id, "regions")],
            event_ts,
            f"{event.region}|{event.event_id}",
            86400,
        )

        self.user_known_countries[event.user_id].add(event.geo_country)
        self.user_known_ips[event.user_id].add(event.source_ip)

        self._append(
            self.ip_users[event.source_ip], event_ts, f"{event.user_id}|{event.event_id}", 86400
        )
        self._append(
            self.account_services[event.account_id],
            event_ts,
            f"{event.service_name}|{event.event_id}",
            3600,
        )
        self._append(self.account_bytes[event.account_id], event_ts, event.bytes_received, 3600)

        return FeatureSnapshot(
            failed_logins_5m=self._count_since(self.user_failed_logins[event.user_id], event_ts - 300),
            failed_logins_1h=self._count_since(self.user_failed_logins[event.user_id], event_ts - 3600),
            request_count_5m=self._count_since(self.user_requests[event.user_id], event_ts - 300),
            distinct_ips_24h=self._distinct_since(
                self.user_dimensions[(event.user_id, "ips")], event_ts - 86400
            ),
            distinct_countries_24h=self._distinct_since(
                self.user_dimensions[(event.user_id, "countries")], event_ts - 86400
            ),
            distinct_regions_24h=self._distinct_since(
                self.user_dimensions[(event.user_id, "regions")], event_ts - 86400
            ),
            privileged_actions_1h=self._count_since(
                self.user_privileged_actions[event.user_id], event_ts - 3600
            ),
            ip_users_24h=self._distinct_since(self.ip_users[event.source_ip], event_ts - 86400),
            ip_failed_auth_rate_5m=self._ip_failed_auth_rate(event.source_ip, event_ts),
            account_delete_actions_10m=self._count_since(
                self.account_delete_actions[event.account_id], event_ts - 600
            ),
            account_service_entropy_1h=self._service_entropy(event.account_id, event_ts),
            account_bytes_received_1h=self._sum_since(
                self.account_bytes[event.account_id], event_ts - 3600
            ),
            is_new_country_for_user=bool(had_country_history and not prior_country_seen),
            is_new_ip_for_user=bool(had_ip_history and not prior_ip_seen),
            is_privileged_action=event.is_privileged_action,
            auth_failure=bool(event.auth_result == "failure"),
        )

    @staticmethod
    def _append(queue: deque, event_ts: int, payload: str | int, retention_seconds: int) -> None:
        queue.append((event_ts, payload))
        cutoff = event_ts - retention_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    @staticmethod
    def _count_since(queue: deque[tuple[int, str]], start_ts: int) -> int:
        return sum(1 for ts, _ in queue if ts >= start_ts)

    @staticmethod
    def _distinct_since(queue: deque[tuple[int, str]], start_ts: int) -> int:
        values = {payload.split("|", 1)[0] for ts, payload in queue if ts >= start_ts}
        return len(values)

    def _ip_failed_auth_rate(self, source_ip: str, event_ts: int) -> float:
        failed = self._count_since(self.ip_failed_auth[source_ip], event_ts - 300)
        total = self._count_since(self.ip_requests[source_ip], event_ts - 300)
        if total == 0:
            return 0.0
        return round(failed / total, 3)

    def _service_entropy(self, account_id: str, event_ts: int) -> float:
        services = [
            payload.split("|", 1)[0]
            for ts, payload in self.account_services[account_id]
            if ts >= event_ts - 3600
        ]
        if not services:
            return 0.0
        counts = Counter(services)
        total = sum(counts.values())
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        return round(entropy, 3)

    @staticmethod
    def _sum_since(queue: deque[tuple[int, int]], start_ts: int) -> int:
        return sum(payload for ts, payload in queue if ts >= start_ts)

    @staticmethod
    def _event_timestamp(event: SecurityEvent) -> int:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return int(ts.astimezone(timezone.utc).timestamp())

    @staticmethod
    def _is_delete_like_action(action: str) -> bool:
        return "Delete" in action or "Terminate" in action
