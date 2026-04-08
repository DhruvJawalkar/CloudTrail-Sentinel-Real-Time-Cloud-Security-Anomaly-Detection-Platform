from __future__ import annotations

import math
from collections import Counter
from datetime import timezone

import redis

from shared.config import REDIS_DB, REDIS_HOST, REDIS_PORT
from shared.models import FeatureSnapshot, SecurityEvent


class RedisFeatureStore:
    def __init__(
        self,
        host: str = REDIS_HOST,
        port: int = REDIS_PORT,
        db: int = REDIS_DB,
    ) -> None:
        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=True)

    def ingest_event(self, event: SecurityEvent) -> FeatureSnapshot:
        event_ts = self._event_timestamp(event)

        prior_country_seen = self.client.sismember(
            self._user_known_countries_key(event.user_id), event.geo_country
        )
        prior_ip_seen = self.client.sismember(
            self._user_known_ips_key(event.user_id), event.source_ip
        )
        had_country_history = self.client.scard(self._user_known_countries_key(event.user_id)) > 0
        had_ip_history = self.client.scard(self._user_known_ips_key(event.user_id)) > 0

        self._track_request(event, event_ts)
        if event.auth_result == "failure":
            self._track_failed_auth(event, event_ts)
        if event.is_privileged_action:
            self._track_privileged_action(event, event_ts)
        if self._is_delete_like_action(event.api_action):
            self._track_delete_action(event, event_ts)

        self._track_user_dimension(event.user_id, "ips", event.source_ip, event.event_id, event_ts)
        self._track_user_dimension(
            event.user_id, "countries", event.geo_country, event.event_id, event_ts
        )
        self._track_user_dimension(
            event.user_id, "regions", event.region, event.event_id, event_ts
        )
        self.client.sadd(self._user_known_countries_key(event.user_id), event.geo_country)
        self.client.sadd(self._user_known_ips_key(event.user_id), event.source_ip)

        self._track_ip_user(event, event_ts)
        self._track_account_service(event, event_ts)
        self._track_account_bytes(event, event_ts)

        return FeatureSnapshot(
            failed_logins_5m=self._zcount(
                self._user_failed_logins_key(event.user_id), event_ts - 300, event_ts
            ),
            failed_logins_1h=self._zcount(
                self._user_failed_logins_key(event.user_id), event_ts - 3600, event_ts
            ),
            request_count_5m=self._zcount(
                self._user_requests_key(event.user_id), event_ts - 300, event_ts
            ),
            distinct_ips_24h=self._distinct_member_count(
                self._user_dimension_key(event.user_id, "ips"), event_ts - 86400
            ),
            distinct_countries_24h=self._distinct_member_count(
                self._user_dimension_key(event.user_id, "countries"), event_ts - 86400
            ),
            distinct_regions_24h=self._distinct_member_count(
                self._user_dimension_key(event.user_id, "regions"), event_ts - 86400
            ),
            privileged_actions_1h=self._zcount(
                self._user_privileged_actions_key(event.user_id), event_ts - 3600, event_ts
            ),
            ip_users_24h=self._distinct_member_count(
                self._ip_users_key(event.source_ip), event_ts - 86400
            ),
            ip_failed_auth_rate_5m=self._ip_failed_auth_rate(event.source_ip, event_ts),
            account_delete_actions_10m=self._zcount(
                self._account_delete_actions_key(event.account_id), event_ts - 600, event_ts
            ),
            account_service_entropy_1h=self._service_entropy(event.account_id, event_ts),
            account_bytes_received_1h=self._sum_scores(
                self._account_bytes_key(event.account_id), event_ts - 3600, event_ts
            ),
            is_new_country_for_user=bool(had_country_history and not prior_country_seen),
            is_new_ip_for_user=bool(had_ip_history and not prior_ip_seen),
        )

    def _track_request(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._user_requests_key(event.user_id)
        self._zadd_and_prune(key, event.event_id, event_ts, 3600)
        ip_key = self._ip_requests_key(event.source_ip)
        self._zadd_and_prune(ip_key, event.event_id, event_ts, 3600)

    def _track_failed_auth(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._user_failed_logins_key(event.user_id)
        self._zadd_and_prune(key, event.event_id, event_ts, 3600)
        ip_key = self._ip_failed_auth_key(event.source_ip)
        self._zadd_and_prune(ip_key, event.event_id, event_ts, 3600)

    def _track_privileged_action(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._user_privileged_actions_key(event.user_id)
        self._zadd_and_prune(key, event.event_id, event_ts, 3600)

    def _track_delete_action(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._account_delete_actions_key(event.account_id)
        self._zadd_and_prune(key, event.event_id, event_ts, 3600)

    def _track_user_dimension(
        self,
        user_id: str,
        dimension: str,
        value: str,
        event_id: str,
        event_ts: int,
    ) -> None:
        key = self._user_dimension_key(user_id, dimension)
        self._zadd_and_prune(key, f"{value}|{event_id}", event_ts, 86400)

    def _track_ip_user(self, event: SecurityEvent, event_ts: int) -> None:
        ip_key = self._ip_users_key(event.source_ip)
        self._zadd_and_prune(ip_key, f"{event.user_id}|{event.event_id}", event_ts, 86400)

    def _track_account_service(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._account_services_key(event.account_id)
        self._zadd_and_prune(key, f"{event.service_name}|{event.event_id}", event_ts, 3600)

    def _track_account_bytes(self, event: SecurityEvent, event_ts: int) -> None:
        key = self._account_bytes_key(event.account_id)
        self._zadd_and_prune(key, f"{event.bytes_received}|{event.event_id}", event_ts, 3600)

    def _zadd_and_prune(
        self,
        key: str,
        member: str,
        value: int,
        retention_seconds: int,
        *,
        score: int | None = None,
    ) -> None:
        actual_score = score if score is not None else value
        self.client.zadd(key, {member: actual_score})
        self.client.zremrangebyscore(key, 0, actual_score - retention_seconds - 1)
        self.client.expire(key, retention_seconds * 2)

    def _zcount(self, key: str, start_ts: int, end_ts: int) -> int:
        return int(self.client.zcount(key, start_ts, end_ts))

    def _distinct_member_count(self, key: str, start_ts: int) -> int:
        members = self.client.zrangebyscore(key, start_ts, "+inf")
        distinct_values = {member.split("|", 1)[0] for member in members}
        return len(distinct_values)

    def _ip_failed_auth_rate(self, source_ip: str, event_ts: int) -> float:
        failed = self._zcount(self._ip_failed_auth_key(source_ip), event_ts - 300, event_ts)
        total = self._distinct_event_count(self._ip_requests_key(source_ip), event_ts - 300)
        if total == 0:
            return 0.0
        return round(failed / total, 3)

    def _distinct_event_count(self, key: str, start_ts: int) -> int:
        return len(self.client.zrangebyscore(key, start_ts, "+inf"))

    def _service_entropy(self, account_id: str, event_ts: int) -> float:
        members = self.client.zrangebyscore(
            self._account_services_key(account_id), event_ts - 3600, "+inf"
        )
        if not members:
            return 0.0
        counts = Counter(member.split("|", 1)[0] for member in members)
        total = sum(counts.values())
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        return round(entropy, 3)

    def _sum_scores(self, key: str, start_ts: int, end_ts: int) -> int:
        members = self.client.zrangebyscore(key, start_ts, end_ts)
        return int(sum(int(member.split("|", 1)[0]) for member in members))

    @staticmethod
    def _event_timestamp(event: SecurityEvent) -> int:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return int(ts.astimezone(timezone.utc).timestamp())

    @staticmethod
    def _is_delete_like_action(action: str) -> bool:
        return "Delete" in action or "Terminate" in action

    @staticmethod
    def _user_requests_key(user_id: str) -> str:
        return f"features:user:{user_id}:requests"

    @staticmethod
    def _user_failed_logins_key(user_id: str) -> str:
        return f"features:user:{user_id}:failed_logins"

    @staticmethod
    def _user_privileged_actions_key(user_id: str) -> str:
        return f"features:user:{user_id}:privileged_actions"

    @staticmethod
    def _user_dimension_key(user_id: str, dimension: str) -> str:
        return f"features:user:{user_id}:{dimension}"

    @staticmethod
    def _user_known_countries_key(user_id: str) -> str:
        return f"features:user:{user_id}:known_countries"

    @staticmethod
    def _user_known_ips_key(user_id: str) -> str:
        return f"features:user:{user_id}:known_ips"

    @staticmethod
    def _ip_users_key(source_ip: str) -> str:
        return f"features:ip:{source_ip}:users"

    @staticmethod
    def _ip_failed_auth_key(source_ip: str) -> str:
        return f"features:ip:{source_ip}:failed_auth"

    @staticmethod
    def _ip_requests_key(source_ip: str) -> str:
        return f"features:ip:{source_ip}:requests"

    @staticmethod
    def _account_delete_actions_key(account_id: str) -> str:
        return f"features:account:{account_id}:delete_actions"

    @staticmethod
    def _account_services_key(account_id: str) -> str:
        return f"features:account:{account_id}:services"

    @staticmethod
    def _account_bytes_key(account_id: str) -> str:
        return f"features:account:{account_id}:bytes_received"
