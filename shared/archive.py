from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


_ARCHIVE_LOCK = Lock()


def append_jsonl(path: str, payload: dict[str, Any]) -> None:
    archive_path = Path(path)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, sort_keys=True)
    with _ARCHIVE_LOCK:
        with archive_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
