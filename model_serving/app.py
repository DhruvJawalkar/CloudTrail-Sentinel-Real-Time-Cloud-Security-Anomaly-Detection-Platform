from __future__ import annotations

from fastapi import FastAPI

from model_serving.service import ModelScoringService
from shared.models import FeatureSnapshot, ModelScore

app = FastAPI(title="CloudTrail Sentinel Model Service", version="0.1.0")
service = ModelScoringService()


@app.get("/health")
def health() -> dict[str, str]:
    status = "ok" if service.model is not None else "degraded"
    return {"status": status}


@app.post("/score", response_model=ModelScore)
def score_features(features: FeatureSnapshot) -> ModelScore:
    return service.score(features)

