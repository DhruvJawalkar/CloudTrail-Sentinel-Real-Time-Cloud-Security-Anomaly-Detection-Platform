from __future__ import annotations

from pathlib import Path

import pandas as pd
import pyarrow as pa
from deltalake import write_deltalake

from model_training.dataset import build_feature_row
from shared.models import FeatureSnapshot, SecurityEvent


class OfflineDeltaFeatureStore:
    def __init__(
        self,
        delta_path: str,
        flush_rows: int = 50,
    ) -> None:
        self.delta_path = Path(delta_path)
        self.flush_rows = max(flush_rows, 1)
        self._buffer: list[dict[str, object]] = []

    def ingest_event(self, event: SecurityEvent, features: FeatureSnapshot) -> None:
        self._buffer.append(build_feature_row(event, features))
        if len(self._buffer) >= self.flush_rows:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        self.delta_path.parent.mkdir(parents=True, exist_ok=True)
        frame = pd.DataFrame(self._buffer)
        table = pa.Table.from_pandas(frame, preserve_index=False)
        mode = "append" if self.delta_path.exists() else "overwrite"
        write_deltalake(
            str(self.delta_path),
            table,
            mode=mode,
            partition_by=["event_date", "cloud_provider"],
        )
        self._buffer.clear()
