from __future__ import annotations

import os

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")

st.set_page_config(page_title="CloudTrail Sentinel", layout="wide")
st.title("CloudTrail Sentinel")
st.caption("Real-time cloud security anomaly detection and triage")

summary = requests.get(f"{API_BASE_URL}/alerts/summary", timeout=5).json()
alerts = requests.get(f"{API_BASE_URL}/alerts", timeout=5).json()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Critical", summary.get("critical", 0))
col2.metric("High", summary.get("high", 0))
col3.metric("Medium", summary.get("medium", 0))
col4.metric("Low", summary.get("low", 0))

if not alerts:
    st.info("No alerts yet. Start the producer and stream processor to populate the dashboard.")
    st.stop()

df = pd.DataFrame(
    [
        {
            "created_at": alert["created_at"],
            "severity": alert["severity"],
            "title": alert["title"],
            "user_id": alert["event"]["user_id"],
            "country": alert["event"]["geo_country"],
            "service": alert["event"]["service_name"],
            "action": alert["event"]["api_action"],
            "score": alert["anomaly_score"],
            "ml_score": alert.get("ml_anomaly_score"),
            "sources": ",".join(alert.get("detection_sources", [])),
            "failed_logins_5m": alert.get("feature_context", {}).get("failed_logins_5m", 0),
            "distinct_countries_24h": alert.get("feature_context", {}).get(
                "distinct_countries_24h", 0
            ),
        }
        for alert in alerts
    ]
)

left, right = st.columns([1.4, 1])
with left:
    st.subheader("Recent Alerts")
    st.dataframe(df, use_container_width=True, hide_index=True)

with right:
    st.subheader("Severity Distribution")
    st.bar_chart(pd.DataFrame([summary]))

st.subheader("Alert Details")
selected_alert = st.selectbox(
    "Select an alert",
    alerts,
    format_func=lambda alert: f'{alert["severity"].upper()} | {alert["title"]} | {alert["event"]["user_id"]}',
)

st.markdown(f"**Description:** {selected_alert['description']}")
st.markdown(f"**Reasons:** {', '.join(selected_alert['reasons'])}")
st.markdown(
    f"**Recommended actions:** {', '.join(selected_alert['recommended_actions'])}"
)
st.markdown(
    f"**Detection sources:** {', '.join(selected_alert.get('detection_sources', [])) or 'n/a'}"
)
st.markdown(f"**ML anomaly score:** {selected_alert.get('ml_anomaly_score', 'n/a')}")
st.markdown(f"**ML confidence:** {selected_alert.get('ml_confidence', 'n/a')}")
st.markdown(f"**Model version:** {selected_alert.get('model_version', 'n/a')}")
st.markdown(
    f"**Top ML contributors:** {', '.join(selected_alert.get('ml_top_contributors', [])) or 'n/a'}"
)
st.markdown("**Feature context:**")
st.json(selected_alert.get("feature_context", {}))
st.markdown("**Triggering event:**")
st.json(selected_alert["event"])
