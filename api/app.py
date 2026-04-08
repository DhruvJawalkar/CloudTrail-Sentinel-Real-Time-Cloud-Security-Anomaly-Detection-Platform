from __future__ import annotations

from fastapi import FastAPI

from api.storage import AlertRepository
from shared.models import Alert, AlertCreate

app = FastAPI(title="CloudTrail Sentinel API", version="0.1.0")
repository = AlertRepository()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/alerts", response_model=Alert, status_code=201)
def create_alert(payload: AlertCreate) -> Alert:
    return repository.create_alert(payload)


@app.get("/alerts", response_model=list[Alert])
def list_alerts(limit: int = 100) -> list[Alert]:
    return repository.list_alerts(limit=limit)


@app.get("/alerts/summary")
def alerts_summary() -> dict[str, int]:
    return repository.alert_summary()

