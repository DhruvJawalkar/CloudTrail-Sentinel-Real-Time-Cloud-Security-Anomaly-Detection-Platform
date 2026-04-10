from __future__ import annotations

from fastapi import FastAPI

from model_serving.service import ModelScoringService
from shared.models import FeatureSnapshot, ModelMetadata, ModelScore

app = FastAPI(title="CloudTrail Sentinel Model Service", version="0.1.0")
service = ModelScoringService()


@app.get("/health")
def health() -> dict[str, str | bool]:
    metadata = service.get_metadata()
    status = "ok" if metadata.artifact_present else "degraded"
    return {
        "status": status,
        "artifact_present": metadata.artifact_present,
        "model_version": metadata.model_version,
    }


@app.get("/metadata", response_model=ModelMetadata)
def metadata() -> ModelMetadata:
    return service.get_metadata()


@app.post("/reload", response_model=ModelMetadata)
def reload_model() -> ModelMetadata:
    return service.reload()


@app.post("/score", response_model=ModelScore)
def score_features(features: FeatureSnapshot) -> ModelScore:
    return service.score(features)


@app.get("/metrics")
def metrics() -> dict[str, object]:
    return service.get_metrics()
