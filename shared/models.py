from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    cloud_provider: Literal["aws", "azure", "gcp"]
    account_id: str
    user_id: str
    principal_type: Literal["human", "service_account", "root"]
    source_ip: str
    geo_country: str
    region: str
    service_name: str
    api_action: str
    resource_type: str
    resource_id: str
    auth_result: Literal["success", "failure"]
    bytes_sent: int = 0
    bytes_received: int = 0
    device_fingerprint: str
    user_agent: str
    is_privileged_action: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


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


class ModelScore(BaseModel):
    anomaly_score: float = 0.0
    confidence: float = 0.0
    predicted_anomaly: bool = False
    model_version: str = "unavailable"
    top_contributors: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    alert_id: str
    created_at: datetime
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
    event: SecurityEvent
