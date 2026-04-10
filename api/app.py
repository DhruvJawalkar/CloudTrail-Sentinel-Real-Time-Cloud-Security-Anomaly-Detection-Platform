from __future__ import annotations

from fastapi import FastAPI

from api.storage import AlertRepository
from shared.metrics import MetricsCollector
from shared.models import Alert, AlertCreate, DeadLetter, DeadLetterCreate

app = FastAPI(title="CloudTrail Sentinel API", version="0.1.0")
repository = AlertRepository()
metrics = MetricsCollector(service_name="api")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/alerts", response_model=Alert, status_code=201)
def create_alert(payload: AlertCreate) -> Alert:
    alert = repository.create_alert(payload)
    metrics.increment("alerts_written")
    metrics.increment(f"alerts_written_{alert.severity}")
    if alert.suppression_count > 0:
        metrics.increment("alerts_suppressed_updates")
    return alert


@app.get("/alerts", response_model=list[Alert])
def list_alerts(limit: int = 100) -> list[Alert]:
    metrics.increment("alert_list_requests")
    return repository.list_alerts(limit=limit)


@app.get("/alerts/summary")
def alerts_summary() -> dict[str, int]:
    metrics.increment("alert_summary_requests")
    return repository.alert_summary()


@app.post("/dead-letters", response_model=DeadLetter, status_code=201)
def create_dead_letter(payload: DeadLetterCreate) -> DeadLetter:
    dead_letter = repository.create_dead_letter(payload)
    metrics.increment("dead_letters_written")
    metrics.increment(f"dead_letters_written_{dead_letter.stage}")
    return dead_letter


@app.get("/dead-letters", response_model=list[DeadLetter])
def list_dead_letters(limit: int = 100) -> list[DeadLetter]:
    metrics.increment("dead_letter_list_requests")
    return repository.list_dead_letters(limit=limit)


@app.get("/dead-letters/summary")
def dead_letters_summary() -> dict[str, int]:
    metrics.increment("dead_letter_summary_requests")
    return repository.dead_letter_summary()


@app.get("/metrics")
def api_metrics() -> dict[str, object]:
    metrics.set_gauge("persisted_alerts", repository.total_alert_count())
    metrics.set_gauge("persisted_dead_letters", repository.total_dead_letter_count())
    return metrics.snapshot()
