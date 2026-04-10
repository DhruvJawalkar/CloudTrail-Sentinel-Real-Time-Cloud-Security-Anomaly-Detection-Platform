from __future__ import annotations

from shared.models import AlertCreate, FeatureSnapshot, ModelScore, SecurityEvent


class RulesEngine:
    def evaluate(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
    ) -> list[AlertCreate]:
        alerts: list[AlertCreate] = []
        alerts.extend(self._failed_auth_burst(event, features, model_score))
        alerts.extend(self._privileged_new_country(event, features, model_score))
        alerts.extend(self._deletion_spike(event, features, model_score))
        alerts.extend(self._high_volume_transfer(event, features, model_score))
        if not alerts:
            ml_alert = self._ml_behavioral_anomaly(event, features, model_score)
            if ml_alert is not None:
                alerts.append(ml_alert)
            return alerts

        return [self._enrich_with_model_context(alert, model_score) for alert in alerts]

    def _failed_auth_burst(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
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
                anomaly_score= model_score.anomaly_score if model_score.model_version != "unavailable" else min(0.99, 0.5 + features.failed_logins_5m * 0.08),
                confidence= model_score.confidence if model_score.model_version != "unavailable" else 0.86,
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
                detection_sources=["rule"],
                event=event,
            )
        ]

    def _privileged_new_country(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
    ) -> list[AlertCreate]:
        if event.is_privileged_action and features.is_new_country_for_user:
            return [
                AlertCreate(
                    severity="critical",
                    title="Privileged action from unseen country",
                    description="A privileged API action originated from a country not previously observed for this identity.",
                    anomaly_score= model_score.anomaly_score if model_score.model_version != "unavailable" else 0.97,
                    confidence= model_score.confidence if model_score.model_version != "unavailable" else 0.91,
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
                    detection_sources=["rule"],
                    event=event,
                )
            ]
        return []

    def _deletion_spike(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
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
                anomaly_score= model_score.anomaly_score if model_score.model_version != "unavailable" else min(0.98, 0.45 + features.account_delete_actions_10m * 0.1),
                confidence= model_score.confidence if model_score.model_version != "unavailable" else 0.79,            
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
                detection_sources=["rule"],
                event=event,
            )
        ]

    def _high_volume_transfer(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
    ) -> list[AlertCreate]:
        if event.bytes_received < 2_000_000:
            return []
        return [
            AlertCreate(
                severity="medium",
                title="High-volume data access",
                description="An unusually large data transfer was observed for a single event.",
                anomaly_score= model_score.anomaly_score if model_score.model_version != "unavailable" else 0.84,
                confidence= model_score.confidence if model_score.model_version != "unavailable" else 0.72,
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
                detection_sources=["rule"],
                event=event,
            )
        ]

    def _ml_behavioral_anomaly(
        self,
        event: SecurityEvent,
        features: FeatureSnapshot,
        model_score: ModelScore,
    ) -> AlertCreate | None:
        if not model_score.predicted_anomaly or model_score.anomaly_score < 0.82:
            return None

        severity = "high" if model_score.anomaly_score >= 0.92 else "medium"
        reasons = [
            f"Isolation Forest anomaly score: {model_score.anomaly_score}",
            f"Top contributors: {', '.join(model_score.top_contributors)}",
        ]
        if features.is_new_country_for_user:
            reasons.append(f"New country observed for user: {event.geo_country}")
        if features.is_new_ip_for_user:
            reasons.append(f"New IP observed for user: {event.source_ip}")

        return AlertCreate(
            severity=severity,
            title="Behavioral anomaly detected by ML model",
            description="The event deviated materially from the learned behavioral baseline.",
            anomaly_score=model_score.anomaly_score,
            confidence=model_score.confidence,
            reasons=reasons,
            recommended_actions=[
                "Review the feature snapshot and recent user activity",
                "Correlate the alert with recent authentication and resource access patterns",
            ],
            feature_context=features.model_dump(mode="json"),
            detection_sources=["ml"],
            ml_anomaly_score=model_score.anomaly_score,
            ml_confidence=model_score.confidence,
            model_version=model_score.model_version,
            ml_top_contributors=model_score.top_contributors,
            event=event,
        )

    def _enrich_with_model_context(
        self,
        alert: AlertCreate,
        model_score: ModelScore,
    ) -> AlertCreate:
        sources = list(alert.detection_sources)
        if model_score.predicted_anomaly and "ml" not in sources:
            sources.append("ml")
            if model_score.top_contributors:
                alert.reasons.append(
                    f"ML contributors: {', '.join(model_score.top_contributors)}"
                )
        alert.detection_sources = sources
        # if model_score.model_version != "unavailable":
        #     alert.anomaly_score = model_score.anomaly_score
        #     alert.confidence = model_score.confidence
        alert.ml_anomaly_score = model_score.anomaly_score
        alert.ml_confidence = model_score.confidence
        alert.model_version = model_score.model_version
        alert.ml_top_contributors = model_score.top_contributors
        return alert
