from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


Severity = Literal["low", "medium", "high", "critical"]


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime
    cloud_provider: Literal["aws", "azure", "gcp"]
    account_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    principal_type: Literal["human", "service_account", "root"]
    source_ip: str
    geo_country: str = Field(min_length=2, max_length=2)
    region: str = Field(min_length=1)
    service_name: str = Field(min_length=1)
    api_action: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    auth_result: Literal["success", "failure"]
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    device_fingerprint: str = Field(min_length=1)
    user_agent: str = Field(min_length=1)
    is_privileged_action: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "event_id",
        "account_id",
        "user_id",
        "region",
        "service_name",
        "api_action",
        "resource_type",
        "resource_id",
        "device_fingerprint",
        "user_agent",
    )
    @classmethod
    def validate_non_empty_string(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("geo_country")
    @classmethod
    def validate_geo_country(cls, value: str) -> str:
        value = value.strip().upper()
        if len(value) != 2 or not value.isalpha():
            raise ValueError("must be a 2-letter country code")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        value = value.strip()
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc
        return value

    @model_validator(mode="after")
    def validate_timestamp(self) -> "SecurityEvent":
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return self


class FeatureSnapshot(BaseModel):
    failed_logins_5m: int = 0
    failed_logins_1h: int = 0
    request_count_5m: int = 0
    distinct_ips_24h: int = 0
    distinct_countries_24h: int = 0
    distinct_regions_24h: int = 0
    privileged_actions_1h: int = 0
    ip_users_24h: int = 0
    ip_failed_auth_rate_5m: float = 0.0
    account_delete_actions_10m: int = 0
    account_service_entropy_1h: float = 0.0
    account_bytes_received_1h: int = 0
    is_new_country_for_user: bool = False
    is_new_ip_for_user: bool = False
    is_privileged_action: bool = False
    auth_failure: bool = False


class ModelScore(BaseModel):
    anomaly_score: float = 0.0
    confidence: float = 0.0
    predicted_anomaly: bool = False
    model_version: str = "unavailable"
    top_contributors: list[str] = Field(default_factory=list)
    explanation: str = ""


class ModelMetadata(BaseModel):
    model_type: str = "IsolationForest"
    model_version: str = "unavailable"
    feature_columns: list[str] = Field(default_factory=list)
    training_rows: int = 0
    contamination: float = 0.0
    artifact_present: bool = False
    trained_at: str | None = None
    observed_anomaly_fraction: float = 0.0
    scenario_breakdown: dict[str, dict[str, float]] = Field(default_factory=dict)
    anomaly_score_percentiles: dict[str, float] = Field(default_factory=dict)


class Alert(BaseModel):
    alert_id: str
    created_at: datetime
    last_seen_at: datetime | None = None
    severity: Severity
    title: str
    description: str
    anomaly_score: float = 0.0
    confidence: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    feature_context: dict[str, Any] = Field(default_factory=dict)
    detection_sources: list[str] = Field(default_factory=list)
    ml_anomaly_score: float | None = None
    ml_confidence: float | None = None
    model_version: str | None = None
    ml_top_contributors: list[str] = Field(default_factory=list)
    ml_explanation: str | None = None
    suppression_count: int = 0
    event: SecurityEvent


class AlertCreate(BaseModel):
    severity: Severity
    title: str
    description: str
    anomaly_score: float = 0.0
    confidence: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    feature_context: dict[str, Any] = Field(default_factory=dict)
    detection_sources: list[str] = Field(default_factory=list)
    ml_anomaly_score: float | None = None
    ml_confidence: float | None = None
    model_version: str | None = None
    ml_top_contributors: list[str] = Field(default_factory=list)
    ml_explanation: str | None = None
    event: SecurityEvent


class DeadLetterCreate(BaseModel):
    failed_at: datetime
    source_topic: str
    stage: str
    error_type: str
    error_message: str
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    event_id: str | None = None
    retryable: bool = False


class DeadLetter(BaseModel):
    dead_letter_id: str
    failed_at: datetime
    source_topic: str
    stage: str
    error_type: str
    error_message: str
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    event_id: str | None = None
    retryable: bool = False
