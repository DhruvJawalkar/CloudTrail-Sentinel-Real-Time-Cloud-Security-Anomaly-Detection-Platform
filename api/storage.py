from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from shared.config import ALERT_SUPPRESSION_WINDOW_SECONDS, SQLITE_DB_PATH
from shared.models import Alert, AlertCreate, DeadLetter, DeadLetterCreate


class AlertRepository:
    def __init__(
        self,
        db_path: str = SQLITE_DB_PATH,
        suppression_window_seconds: int = ALERT_SUPPRESSION_WINDOW_SECONDS,
    ) -> None:
        self.db_path = Path(db_path)
        self.suppression_window_seconds = suppression_window_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    reasons_json TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    feature_context_json TEXT NOT NULL DEFAULT '{}',
                    detection_sources_json TEXT NOT NULL DEFAULT '[]',
                    ml_anomaly_score REAL,
                    ml_confidence REAL,
                    model_version TEXT,
                    ml_top_contributors_json TEXT NOT NULL DEFAULT '[]',
                    ml_explanation TEXT,
                    idempotency_key TEXT NOT NULL DEFAULT '',
                    alert_fingerprint TEXT NOT NULL DEFAULT '',
                    suppression_count INTEGER NOT NULL DEFAULT 0,
                    event_json TEXT NOT NULL
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
            }
            if "feature_context_json" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN feature_context_json TEXT NOT NULL DEFAULT '{}'
                    """
                )
            if "detection_sources_json" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN detection_sources_json TEXT NOT NULL DEFAULT '[]'
                    """
                )
            if "ml_anomaly_score" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN ml_anomaly_score REAL
                    """
                )
            if "ml_confidence" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN ml_confidence REAL
                    """
                )
            if "model_version" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN model_version TEXT
                    """
                )
            if "ml_top_contributors_json" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN ml_top_contributors_json TEXT NOT NULL DEFAULT '[]'
                    """
                )
            if "ml_explanation" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN ml_explanation TEXT
                    """
                )
            if "last_seen_at" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT ''
                    """
                )
                connection.execute(
                    """
                    UPDATE alerts
                    SET last_seen_at = created_at
                    WHERE last_seen_at = ''
                    """
                )
            if "alert_fingerprint" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN alert_fingerprint TEXT NOT NULL DEFAULT ''
                    """
                )
            if "idempotency_key" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT ''
                    """
                )
            if "suppression_count" not in columns:
                connection.execute(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN suppression_count INTEGER NOT NULL DEFAULT 0
                    """
                )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_idempotency_key
                ON alerts(idempotency_key)
                WHERE idempotency_key <> ''
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS dead_letters (
                    dead_letter_id TEXT PRIMARY KEY,
                    failed_at TEXT NOT NULL,
                    source_topic TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL DEFAULT '{}',
                    event_id TEXT,
                    retryable INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def create_alert(self, payload: AlertCreate) -> Alert:
        now = datetime.now(timezone.utc)
        idempotency_key = self._idempotency_key(payload)
        fingerprint = self._fingerprint(payload)
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            created_at=now,
            last_seen_at=now,
            severity=payload.severity,
            title=payload.title,
            description=payload.description,
            anomaly_score=payload.anomaly_score,
            confidence=payload.confidence,
            reasons=payload.reasons,
            recommended_actions=payload.recommended_actions,
            feature_context=payload.feature_context,
            detection_sources=payload.detection_sources,
            ml_anomaly_score=payload.ml_anomaly_score,
            ml_confidence=payload.ml_confidence,
            model_version=payload.model_version,
            ml_top_contributors=payload.ml_top_contributors,
            ml_explanation=payload.ml_explanation,
            suppression_count=0,
            event=payload.event,
        )
        with self._connect() as connection:
            existing_row = connection.execute(
                """
                SELECT *
                FROM alerts
                WHERE idempotency_key = ?
                LIMIT 1
                """,
                (idempotency_key,),
            ).fetchone()
            if existing_row is not None:
                return self._row_to_alert(existing_row)
            suppressed_row = self._find_suppressed_match(connection, fingerprint, now)
            if suppressed_row is not None:
                return self._update_suppressed_alert(
                    connection,
                    suppressed_row,
                    alert,
                    fingerprint,
                    idempotency_key,
                )
            try:
                connection.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, created_at, last_seen_at, severity, title, description,
                        anomaly_score, confidence, reasons_json,
                        recommended_actions_json, feature_context_json,
                        detection_sources_json, ml_anomaly_score, ml_confidence,
                        model_version, ml_top_contributors_json, ml_explanation, idempotency_key,
                        alert_fingerprint, suppression_count, event_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.created_at.isoformat(),
                        alert.last_seen_at.isoformat(),
                        alert.severity,
                        alert.title,
                        alert.description,
                        alert.anomaly_score,
                        alert.confidence,
                        json.dumps(alert.reasons),
                        json.dumps(alert.recommended_actions),
                        json.dumps(alert.feature_context),
                        json.dumps(alert.detection_sources),
                        alert.ml_anomaly_score,
                        alert.ml_confidence,
                        alert.model_version,
                        json.dumps(alert.ml_top_contributors),
                        alert.ml_explanation,
                        idempotency_key,
                        fingerprint,
                        alert.suppression_count,
                        alert.event.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError:
                existing_row = connection.execute(
                    """
                    SELECT *
                    FROM alerts
                    WHERE idempotency_key = ?
                    LIMIT 1
                    """,
                    (idempotency_key,),
                ).fetchone()
                if existing_row is not None:
                    return self._row_to_alert(existing_row)
                raise
        return alert

    def list_alerts(self, limit: int = 100) -> list[Alert]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY datetime(last_seen_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def create_dead_letter(self, payload: DeadLetterCreate) -> DeadLetter:
        dead_letter = DeadLetter(
            dead_letter_id=str(uuid.uuid4()),
            failed_at=payload.failed_at,
            source_topic=payload.source_topic,
            stage=payload.stage,
            error_type=payload.error_type,
            error_message=payload.error_message,
            raw_payload=payload.raw_payload,
            event_id=payload.event_id,
            retryable=payload.retryable,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO dead_letters (
                    dead_letter_id, failed_at, source_topic, stage, error_type,
                    error_message, raw_payload_json, event_id, retryable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dead_letter.dead_letter_id,
                    dead_letter.failed_at.isoformat(),
                    dead_letter.source_topic,
                    dead_letter.stage,
                    dead_letter.error_type,
                    dead_letter.error_message,
                    json.dumps(dead_letter.raw_payload),
                    dead_letter.event_id,
                    int(dead_letter.retryable),
                ),
            )
        return dead_letter

    def list_dead_letters(self, limit: int = 100) -> list[DeadLetter]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM dead_letters
                ORDER BY datetime(failed_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_dead_letter(row) for row in rows]

    def dead_letter_summary(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT stage, COUNT(*) AS count
                FROM dead_letters
                GROUP BY stage
                """
            ).fetchall()
        return {row["stage"]: row["count"] for row in rows}

    def total_alert_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()
        return int(row["count"])

    def total_dead_letter_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM dead_letters").fetchone()
        return int(row["count"])

    def alert_summary(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            ).fetchall()
        summary = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in rows:
            summary[row["severity"]] = row["count"]
        return summary

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            anomaly_score=row["anomaly_score"],
            confidence=row["confidence"],
            reasons=json.loads(row["reasons_json"]),
            recommended_actions=json.loads(row["recommended_actions_json"]),
            feature_context=json.loads(row["feature_context_json"] or "{}"),
            detection_sources=json.loads(row["detection_sources_json"] or "[]"),
            ml_anomaly_score=row["ml_anomaly_score"],
            ml_confidence=row["ml_confidence"],
            model_version=row["model_version"],
            ml_top_contributors=json.loads(row["ml_top_contributors_json"] or "[]"),
            ml_explanation=row["ml_explanation"],
            suppression_count=int(row["suppression_count"] or 0),
            event=json.loads(row["event_json"]),
        )

    @staticmethod
    def _row_to_dead_letter(row: sqlite3.Row) -> DeadLetter:
        return DeadLetter(
            dead_letter_id=row["dead_letter_id"],
            failed_at=datetime.fromisoformat(row["failed_at"]),
            source_topic=row["source_topic"],
            stage=row["stage"],
            error_type=row["error_type"],
            error_message=row["error_message"],
            raw_payload=json.loads(row["raw_payload_json"] or "{}"),
            event_id=row["event_id"],
            retryable=bool(row["retryable"]),
        )

    def _find_suppressed_match(
        self,
        connection: sqlite3.Connection,
        fingerprint: str,
        now: datetime,
    ) -> sqlite3.Row | None:
        threshold = (now - timedelta(seconds=self.suppression_window_seconds)).isoformat()
        return connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE alert_fingerprint = ?
              AND datetime(last_seen_at) >= datetime(?)
            ORDER BY datetime(last_seen_at) DESC
            LIMIT 1
            """,
            (fingerprint, threshold),
        ).fetchone()

    def _update_suppressed_alert(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        incoming: Alert,
        fingerprint: str,
        idempotency_key: str,
    ) -> Alert:
        existing = self._row_to_alert(row)
        severity = self._higher_severity(existing.severity, incoming.severity)
        anomaly_score = max(existing.anomaly_score, incoming.anomaly_score)
        confidence = max(existing.confidence, incoming.confidence)
        ml_anomaly_score = self._max_optional(existing.ml_anomaly_score, incoming.ml_anomaly_score)
        ml_confidence = self._max_optional(existing.ml_confidence, incoming.ml_confidence)
        detection_sources = sorted(
            set(existing.detection_sources).union(incoming.detection_sources)
        )
        reasons = self._merge_lists(existing.reasons, incoming.reasons)
        recommended_actions = self._merge_lists(
            existing.recommended_actions,
            incoming.recommended_actions,
        )
        ml_top_contributors = self._merge_lists(
            existing.ml_top_contributors,
            incoming.ml_top_contributors,
        )
        updated = Alert(
            alert_id=existing.alert_id,
            created_at=existing.created_at,
            last_seen_at=incoming.last_seen_at,
            severity=severity,
            title=incoming.title,
            description=incoming.description,
            anomaly_score=anomaly_score,
            confidence=confidence,
            reasons=reasons,
            recommended_actions=recommended_actions,
            feature_context=incoming.feature_context,
            detection_sources=detection_sources,
            ml_anomaly_score=ml_anomaly_score,
            ml_confidence=ml_confidence,
            model_version=incoming.model_version or existing.model_version,
            ml_top_contributors=ml_top_contributors,
            ml_explanation=incoming.ml_explanation or existing.ml_explanation,
            suppression_count=existing.suppression_count + 1,
            event=incoming.event,
        )
        connection.execute(
            """
            UPDATE alerts
            SET last_seen_at = ?,
                severity = ?,
                title = ?,
                description = ?,
                anomaly_score = ?,
                confidence = ?,
                reasons_json = ?,
                recommended_actions_json = ?,
                feature_context_json = ?,
                detection_sources_json = ?,
                ml_anomaly_score = ?,
                ml_confidence = ?,
                model_version = ?,
                ml_top_contributors_json = ?,
                ml_explanation = ?,
                idempotency_key = ?,
                alert_fingerprint = ?,
                suppression_count = ?,
                event_json = ?
            WHERE alert_id = ?
            """,
            (
                updated.last_seen_at.isoformat(),
                updated.severity,
                updated.title,
                updated.description,
                updated.anomaly_score,
                updated.confidence,
                json.dumps(updated.reasons),
                json.dumps(updated.recommended_actions),
                json.dumps(updated.feature_context),
                json.dumps(updated.detection_sources),
                updated.ml_anomaly_score,
                updated.ml_confidence,
                updated.model_version,
                json.dumps(updated.ml_top_contributors),
                updated.ml_explanation,
                idempotency_key,
                fingerprint,
                updated.suppression_count,
                updated.event.model_dump_json(),
                updated.alert_id,
            ),
        )
        return updated

    @staticmethod
    def _fingerprint(payload: AlertCreate) -> str:
        basis = {
            "title": payload.title,
            "severity": payload.severity,
            "sources": sorted(payload.detection_sources),
            "account_id": payload.event.account_id,
            "user_id": payload.event.user_id,
            "source_ip": payload.event.source_ip,
            "geo_country": payload.event.geo_country,
            "service_name": payload.event.service_name,
            "api_action": payload.event.api_action,
        }
        return json.dumps(basis, sort_keys=True)

    @staticmethod
    def _idempotency_key(payload: AlertCreate) -> str:
        basis = {
            "event_id": payload.event.event_id,
            "title": payload.title,
            "sources": sorted(payload.detection_sources),
            "model_version": payload.model_version,
        }
        return json.dumps(basis, sort_keys=True)

    @staticmethod
    def _higher_severity(left: str, right: str) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return left if order[left] >= order[right] else right

    @staticmethod
    def _merge_lists(left: list[str], right: list[str]) -> list[str]:
        return list(dict.fromkeys([*left, *right]))

    @staticmethod
    def _max_optional(left: float | None, right: float | None) -> float | None:
        if left is None:
            return right
        if right is None:
            return left
        return max(left, right)
