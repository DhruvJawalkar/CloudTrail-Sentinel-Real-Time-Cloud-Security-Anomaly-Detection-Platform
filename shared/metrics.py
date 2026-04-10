from __future__ import annotations

import threading
import time


class MetricsCollector:
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self.started_at = time.time()
        self._counters: dict[str, int] = {}
        self._latencies: dict[str, dict[str, float]] = {}
        self._gauges: dict[str, float | int] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def set_gauge(self, name: str, value: float | int) -> None:
        with self._lock:
            self._gauges[name] = value

    def record_latency(self, name: str, duration_seconds: float) -> None:
        with self._lock:
            stats = self._latencies.setdefault(
                name,
                {"count": 0.0, "total_seconds": 0.0, "max_seconds": 0.0},
            )
            stats["count"] += 1
            stats["total_seconds"] += duration_seconds
            stats["max_seconds"] = max(stats["max_seconds"], duration_seconds)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            latencies = {
                name: {
                    "count": int(stats["count"]),
                    "avg_ms": round(
                        (stats["total_seconds"] / stats["count"]) * 1000,
                        3,
                    )
                    if stats["count"]
                    else 0.0,
                    "max_ms": round(stats["max_seconds"] * 1000, 3),
                    "total_seconds": round(stats["total_seconds"], 3),
                }
                for name, stats in self._latencies.items()
            }
        uptime = max(time.time() - self.started_at, 0.001)
        rates = {
            f"{name}_per_sec": round(value / uptime, 3)
            for name, value in counters.items()
        }
        return {
            "service": self.service_name,
            "uptime_seconds": round(uptime, 3),
            "counters": counters,
            "gauges": gauges,
            "latencies": latencies,
            "rates": rates,
        }
