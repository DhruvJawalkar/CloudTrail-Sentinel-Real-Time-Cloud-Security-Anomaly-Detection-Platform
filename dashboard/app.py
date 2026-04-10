from __future__ import annotations

import os

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")
MODEL_API_BASE_URL = os.getenv("MODEL_API_BASE_URL", "http://model_serving:8010")
STREAM_PROCESSOR_METRICS_URL = os.getenv(
    "STREAM_PROCESSOR_METRICS_URL",
    "http://stream_processor:9101/metrics",
)


def _fetch_json(url: str) -> dict | list:
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json()


def _detection_category(alert: dict) -> str:
    sources = set(alert.get("detection_sources", []))
    if sources == {"ml"}:
        return "ml-only"
    if "rule" in sources and "ml" in sources:
        return "rule+ml"
    if "rule" in sources:
        return "rule-only"
    return "unknown"


st.set_page_config(page_title="CloudTrail Sentinel", layout="wide")
st.title("CloudTrail Sentinel")
st.caption("Real-time cloud security anomaly detection and triage")

summary = _fetch_json(f"{API_BASE_URL}/alerts/summary")
alerts = _fetch_json(f"{API_BASE_URL}/alerts")
dead_letter_summary = _fetch_json(f"{API_BASE_URL}/dead-letters/summary")
dead_letters = _fetch_json(f"{API_BASE_URL}/dead-letters?limit=20")
api_health = _fetch_json(f"{API_BASE_URL}/health")
model_health = _fetch_json(f"{MODEL_API_BASE_URL}/health")
model_metadata = _fetch_json(f"{MODEL_API_BASE_URL}/metadata")
api_metrics = _fetch_json(f"{API_BASE_URL}/metrics")
model_metrics = _fetch_json(f"{MODEL_API_BASE_URL}/metrics")
stream_metrics = _fetch_json(STREAM_PROCESSOR_METRICS_URL)
stream_health = {"status": "ok" if stream_metrics.get("service") == "stream_processor" else "degraded"}

col1, col2, col3, col4 = st.columns(4)
col1.metric("Critical", summary.get("critical", 0))
col2.metric("High", summary.get("high", 0))
col3.metric("Medium", summary.get("medium", 0))
col4.metric("Low", summary.get("low", 0))

health_left, health_center, health_right = st.columns(3)
with health_left:
    st.metric("API Health", api_health.get("status", "unknown"))
with health_center:
    st.metric("Model Health", model_health.get("status", "unknown"))
with health_right:
    st.metric("Stream Health", stream_health.get("status", "unknown"))

if not alerts:
    st.info("No alerts yet. Start the producer and stream processor to populate the dashboard.")
    st.stop()

for alert in alerts:
    alert["detection_category"] = _detection_category(alert)

detection_categories = ["rule+ml", "rule-only", "ml-only", "unknown"]
selected_categories = st.multiselect(
    "Detection sources",
    options=detection_categories,
    default=[category for category in detection_categories if category != "unknown"],
)
filtered_alerts = [
    alert for alert in alerts if alert["detection_category"] in selected_categories
]

if not filtered_alerts:
    st.warning("No alerts match the selected detection-source filters.")
    st.stop()

df = pd.DataFrame(
    [
        {
            "created_at": alert["created_at"],
            "last_seen_at": alert.get("last_seen_at", alert["created_at"]),
            "severity": alert["severity"],
            "detection": alert["detection_category"],
            "title": alert["title"],
            "user_id": alert["event"]["user_id"],
            "country": alert["event"]["geo_country"],
            "service": alert["event"]["service_name"],
            "action": alert["event"]["api_action"],
            "score": alert["anomaly_score"],
            "ml_score": alert.get("ml_anomaly_score"),
            "model_version": alert.get("model_version", "n/a"),
            "suppressed_repeats": alert.get("suppression_count", 0),
            "failed_logins_5m": alert.get("feature_context", {}).get("failed_logins_5m", 0),
            "distinct_countries_24h": alert.get("feature_context", {}).get(
                "distinct_countries_24h", 0
            ),
        }
        for alert in filtered_alerts
    ]
)

source_counts = (
    df["detection"].value_counts().rename_axis("detection").reset_index(name="count")
)

top_row_left, top_row_right = st.columns([1.5, 1])
with top_row_left:
    st.subheader("Recent Alerts")
    st.dataframe(df, use_container_width=True, hide_index=True)

with top_row_right:
    st.subheader("Model Metadata")
    st.markdown(f"**Model version:** {model_metadata.get('model_version', 'n/a')}")
    st.markdown(f"**Trained at:** {model_metadata.get('trained_at', 'n/a')}")
    st.markdown(f"**Training rows:** {model_metadata.get('training_rows', 0)}")
    st.markdown(
        f"**Observed anomaly fraction:** {model_metadata.get('observed_anomaly_fraction', 0.0)}"
    )
    st.markdown(
        f"**Training p95 anomaly score:** {model_metadata.get('anomaly_score_percentiles', {}).get('p95', 'n/a')}"
    )
    st.markdown(
        f"**Training p99 anomaly score:** {model_metadata.get('anomaly_score_percentiles', {}).get('p99', 'n/a')}"
    )

middle_left, middle_center, middle_right = st.columns(3)
with middle_left:
    st.subheader("Severity Distribution")
    st.bar_chart(pd.DataFrame([summary]))

with middle_center:
    st.subheader("Detection Mix")
    st.bar_chart(source_counts.set_index("detection"))

with middle_right:
    st.subheader("ML Score Distribution")
    ml_score_frame = df[df["ml_score"].notna()][["ml_score"]]
    if ml_score_frame.empty:
        st.info("No ML-scored alerts in the current filter.")
    else:
        st.bar_chart(ml_score_frame)

st.subheader("Operational Metrics")
ops_left, ops_center, ops_right = st.columns(3)
with ops_left:
    st.markdown("**Stream Processor**")
    st.json(
        {
            "uptime_seconds": stream_metrics.get("uptime_seconds"),
            "counters": stream_metrics.get("counters", {}),
            "latencies": stream_metrics.get("latencies", {}),
        }
    )
with ops_center:
    st.markdown("**API**")
    st.json(
        {
            "uptime_seconds": api_metrics.get("uptime_seconds"),
            "gauges": api_metrics.get("gauges", {}),
            "counters": api_metrics.get("counters", {}),
        }
    )
with ops_right:
    st.markdown("**Model Service**")
    st.json(
        {
            "uptime_seconds": model_metrics.get("uptime_seconds"),
            "gauges": model_metrics.get("gauges", {}),
            "latencies": model_metrics.get("latencies", {}),
        }
    )

st.subheader("Dead-Letter Activity")
dlq_left, dlq_right = st.columns([1, 1.6])
with dlq_left:
    if dead_letter_summary:
        st.bar_chart(pd.DataFrame([dead_letter_summary]))
    else:
        st.info("No dead-letter records yet.")
with dlq_right:
    if dead_letters:
        dlq_df = pd.DataFrame(
            [
                {
                    "failed_at": item["failed_at"],
                    "stage": item["stage"],
                    "error_type": item["error_type"],
                    "event_id": item.get("event_id"),
                    "retryable": item.get("retryable", False),
                }
                for item in dead_letters
            ]
        )
        st.dataframe(dlq_df, use_container_width=True, hide_index=True)
    else:
        st.info("No recent dead-letter events.")

st.subheader("Training Scenario Breakdown")
scenario_breakdown = model_metadata.get("scenario_breakdown", {})
if scenario_breakdown:
    scenario_df = pd.DataFrame(
        [
            {
                "scenario": scenario,
                "count": values.get("count", 0),
                "predicted_anomalies": values.get("predicted_anomalies", 0),
                "predicted_anomaly_rate": values.get("predicted_anomaly_rate", 0.0),
            }
            for scenario, values in scenario_breakdown.items()
        ]
    ).sort_values("predicted_anomaly_rate", ascending=False)
    st.dataframe(scenario_df, use_container_width=True, hide_index=True)
else:
    st.info("No scenario breakdown is available for the current model artifact.")

st.subheader("Alert Details")
selected_alert = st.selectbox(
    "Select an alert",
    filtered_alerts,
    format_func=lambda alert: (
        f'{alert["severity"].upper()} | {alert["detection_category"]} | '
        f'{alert["title"]} | {alert["event"]["user_id"]}'
    ),
)

st.markdown(f"**Description:** {selected_alert['description']}")
st.markdown(f"**Reasons:** {', '.join(selected_alert['reasons'])}")
st.markdown(
    f"**Recommended actions:** {', '.join(selected_alert['recommended_actions'])}"
)
st.markdown(f"**Detection sources:** {selected_alert['detection_category']}")
st.markdown(f"**Suppressed repeats:** {selected_alert.get('suppression_count', 0)}")
st.markdown(f"**First seen:** {selected_alert.get('created_at', 'n/a')}")
st.markdown(f"**Last seen:** {selected_alert.get('last_seen_at', 'n/a')}")
st.markdown(f"**ML anomaly score:** {selected_alert.get('ml_anomaly_score', 'n/a')}")
st.markdown(f"**ML confidence:** {selected_alert.get('ml_confidence', 'n/a')}")
st.markdown(f"**Model version:** {selected_alert.get('model_version', 'n/a')}")
st.markdown(
    f"**Top ML contributors:** {', '.join(selected_alert.get('ml_top_contributors', [])) or 'n/a'}"
)
st.markdown(f"**ML explanation:** {selected_alert.get('ml_explanation', 'n/a')}")
st.markdown("**Feature context:**")
st.json(selected_alert.get("feature_context", {}))
st.markdown("**Triggering event:**")
st.json(selected_alert["event"])

if dead_letters:
    st.subheader("Dead-Letter Details")
    selected_dead_letter = st.selectbox(
        "Select a dead-letter event",
        dead_letters,
        format_func=lambda item: (
            f'{item["stage"]} | {item["error_type"]} | {item.get("event_id") or "no-event-id"}'
        ),
    )
    st.markdown(f"**Failed at:** {selected_dead_letter['failed_at']}")
    st.markdown(f"**Stage:** {selected_dead_letter['stage']}")
    st.markdown(f"**Error type:** {selected_dead_letter['error_type']}")
    st.markdown(f"**Retryable:** {selected_dead_letter.get('retryable', False)}")
    st.markdown(f"**Error message:** {selected_dead_letter['error_message']}")
    st.markdown("**Raw payload:**")
    st.json(selected_dead_letter.get("raw_payload", {}))
