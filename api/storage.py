from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from shared.config import SQLITE_DB_PATH
from shared.models import Alert, AlertCreate


class AlertRepository:
    def __init__(self, db_path: str = SQLITE_DB_PATH) -> None:
        self.db_path = Path(db_path)
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
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    reasons_json TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    feature_context_json TEXT NOT NULL DEFAULT '{}',
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

    def create_alert(self, payload: AlertCreate) -> Alert:
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            severity=payload.severity,
            title=payload.title,
            description=payload.description,
            anomaly_score=payload.anomaly_score,
            confidence=payload.confidence,
            reasons=payload.reasons,
            recommended_actions=payload.recommended_actions,
            feature_context=payload.feature_context,
            event=payload.event,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, created_at, severity, title, description,
                    anomaly_score, confidence, reasons_json,
                    recommended_actions_json, feature_context_json, event_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.created_at.isoformat(),
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.anomaly_score,
                    alert.confidence,
                    json.dumps(alert.reasons),
                    json.dumps(alert.recommended_actions),
                    json.dumps(alert.feature_context),
                    alert.event.model_dump_json(),
                ),
            )
        return alert

    def list_alerts(self, limit: int = 100) -> list[Alert]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_alert(row) for row in rows]

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
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            anomaly_score=row["anomaly_score"],
            confidence=row["confidence"],
            reasons=json.loads(row["reasons_json"]),
            recommended_actions=json.loads(row["recommended_actions_json"]),
            feature_context=json.loads(row["feature_context_json"] or "{}"),
            event=json.loads(row["event_json"]),
        )
