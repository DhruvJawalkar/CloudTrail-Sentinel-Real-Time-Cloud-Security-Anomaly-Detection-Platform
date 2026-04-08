# Phase 2 Feature Store

This package now contains the online feature store integration used by the stream processor.

Current implementation:

- Redis-backed rolling state
- per-user counters for failed logins, request volume, privileged actions, and recent identity spread
- per-IP features for shared user activity and failed auth rate
- per-account features for deletion bursts, service mix entropy, and bytes received

Primary entry point:

- `redis_store.py` exposes `RedisFeatureStore.ingest_event()`, which updates state and returns a `FeatureSnapshot`
