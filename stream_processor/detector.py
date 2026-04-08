from __future__ import annotations

from shared.models import AlertCreate, FeatureSnapshot, SecurityEvent


class RulesEngine:
    def evaluate(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
    ) -> list[AlertCreate]:
        alerts: list[AlertCreate] = []
        alerts.extend(self._failed_auth_burst(event, features))
        alerts.extend(self._privileged_new_country(event, features))
        alerts.extend(self._deletion_spike(event, features))
        alerts.extend(self._high_volume_transfer(event, features))
        return alerts

    def _failed_auth_burst(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
    ) -> list[AlertCreate]:
        if event.api_action != "ConsoleLogin" or event.auth_result != "failure":
            return []
        if features.failed_logins_5m < 5:
            return []

        return [
            AlertCreate(
                severity="high",
                title="Failed login burst detected",
                description="Multiple failed console login attempts observed in a short window.",
                anomaly_score=min(0.99, 0.5 + features.failed_logins_5m * 0.08),
                confidence=0.86,
                reasons=[
                    f"{features.failed_logins_5m} failed console logins in the last 5 minutes",
                    f"Source country {event.geo_country}",
                    f"IP failed auth rate in 5 minutes: {features.ip_failed_auth_rate_5m}",
                ],
                recommended_actions=[
                    "Lock the account if the failures continue",
                    "Verify whether the source IP belongs to corporate infrastructure",
                    "Require MFA re-authentication",
                ],
                feature_context=features.model_dump(mode="json"),
                event=event,
            )
        ]

    def _privileged_new_country(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
    ) -> list[AlertCreate]:
        if event.is_privileged_action and features.is_new_country_for_user:
            return [
                AlertCreate(
                    severity="critical",
                    title="Privileged action from unseen country",
                    description="A privileged API action originated from a country not previously observed for this identity.",
                    anomaly_score=0.97,
                    confidence=0.91,
                    reasons=[
                        f"Privileged action {event.api_action}",
                        f"New country for user: {event.geo_country}",
                        f"Distinct countries seen in 24 hours: {features.distinct_countries_24h}",
                    ],
                    recommended_actions=[
                        "Review the initiating session and recent IAM activity",
                        "Temporarily revoke high-risk credentials if unverified",
                        "Correlate with device and VPN logs",
                    ],
                    feature_context=features.model_dump(mode="json"),
                    event=event,
                )
            ]
        return []

    def _deletion_spike(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
    ) -> list[AlertCreate]:
        if "Delete" not in event.api_action and "Terminate" not in event.api_action:
            return []
        if features.account_delete_actions_10m < 4:
            return []

        return [
            AlertCreate(
                severity="high",
                title="Deletion activity spike",
                description="Resource deletion velocity exceeded the expected local baseline for the account.",
                anomaly_score=min(0.98, 0.45 + features.account_delete_actions_10m * 0.1),
                confidence=0.79,
                reasons=[
                    f"{features.account_delete_actions_10m} delete or terminate actions in 10 minutes",
                    f"Account {event.account_id}",
                    f"Account service entropy in 1 hour: {features.account_service_entropy_1h}",
                ],
                recommended_actions=[
                    "Confirm whether an authorized cleanup job is running",
                    "Snapshot impacted resources if available",
                    "Pause destructive automation until triage completes",
                ],
                feature_context=features.model_dump(mode="json"),
                event=event,
            )
        ]

    def _high_volume_transfer(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
    ) -> list[AlertCreate]:
        if event.bytes_received < 2_000_000:
            return []
        return [
            AlertCreate(
                severity="medium",
                title="High-volume data access",
                description="An unusually large data transfer was observed for a single event.",
                anomaly_score=0.84,
                confidence=0.72,
                reasons=[
                    f"{event.bytes_received} bytes received",
                    f"API action {event.api_action}",
                    f"Account bytes received in 1 hour: {features.account_bytes_received_1h}",
                ],
                recommended_actions=[
                    "Check whether the transfer matches an approved backup or analytics job",
                    "Review the affected bucket or dataset",
                ],
                feature_context=features.model_dump(mode="json"),
                event=event,
            )
        ]
