import streamlit as st
import os
import json
import glob
import pandas as pd

HONEYPOT_LOG_DIR = "/tmp/honeypot_logs/"
MITIGATION_LOG = "/home/sandeep/Capstone_Phase3/controller/risk_mitigation_actions.json"

# Add autorefresh (every 5 seconds)
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=5000, limit=None, key="honeypot_autorefresh")
except Exception:
    from streamlit.components.v1 import html as _st_html
    _st_html("<script>setInterval(()=>{window.location.reload();}, 5000);</script>", height=0)

st.title("Honeypot Analytics Dashboard")

# --- Load honeypot events ---
files = sorted(glob.glob(os.path.join(HONEYPOT_LOG_DIR, "event_*.json")), reverse=True)
events = []
for fname in files:
    try:
        with open(fname) as f:
            events.append(json.load(f))
    except Exception:
        pass

# --- Load redirected sources from mitigation log ---
redirected_sources = set()
if os.path.exists(MITIGATION_LOG):
    with open(MITIGATION_LOG) as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get("action_type") == "REDIRECT_TO_HONEYPOT" and entry.get("source_ip"):
                    redirected_sources.add(entry["source_ip"])
            except Exception:
                pass

if not events and not redirected_sources:
    st.info("No honeypot events or redirected sources yet. Waiting for attacker interactions...")
else:
    df = pd.DataFrame(events)
    # --- Merge redirected sources with honeypot events ---
    event_ips = set(df["src_ip"]) if not df.empty and "src_ip" in df.columns else set()
    all_sources = event_ips.union(redirected_sources)
    # Build a summary DataFrame
    summary = pd.DataFrame({"src_ip": list(all_sources)})
    if not df.empty and "src_ip" in df.columns:
        event_counts = df["src_ip"].value_counts().to_dict()
        summary["event_count"] = summary["src_ip"].map(event_counts).fillna(0).astype(int)
    else:
        summary["event_count"] = 0
    summary["redirected_only"] = ~summary["src_ip"].isin(event_ips)

    # --- Executive Summary KPIs ---
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric("Total Attacks", int(summary["event_count"].sum()))
    with kpi2:
        st.metric("Unique Attacker IPs", len(summary))
    with kpi3:
        if not df.empty and 'dst_port' in df.columns:
            top_port = df['dst_port'].mode()[0] if not df['dst_port'].isnull().all() else 'N/A'
            st.metric("Most Targeted Port", top_port)
        else:
            st.metric("Most Targeted Port", "N/A")
    with kpi4:
        if not df.empty and 'payload_preview' in df.columns:
            top_payload = df['payload_preview'].mode()[0] if not df['payload_preview'].isnull().all() else 'N/A'
            st.metric("Top Payload", str(top_payload)[:20])
        else:
            st.metric("Top Payload", "N/A")
    st.markdown("---")

    # --- Top Attackers Table ---
    st.subheader("Top Attackers (including redirected)")
    attacker_stats = summary.copy()
    attacker_stats["status"] = attacker_stats["redirected_only"].map(lambda x: "Redirected, no event" if x else "Event logged")
    attacker_stats = attacker_stats.sort_values(["event_count", "src_ip"], ascending=[False, True]).reset_index(drop=True)
    st.dataframe(attacker_stats[["src_ip", "event_count", "status"]].rename(columns={"src_ip": "Source IP", "event_count": "Event Count", "status": "Status"}))
    st.markdown("---")

    # --- Recommendations/Alerts Section ---
    st.subheader("Recommendations & Alerts")
    flagged = attacker_stats[(attacker_stats["event_count"] >= 4) | (attacker_stats["redirected_only"])]
    if not flagged.empty:
        for _, row in flagged.iterrows():
            if row["redirected_only"]:
                st.warning(f"⚠️ Source IP {row['src_ip']} was redirected to the honeypot but has not interacted yet. Recommend monitoring or blacklisting.")
            elif row["event_count"] >= 4:
                st.warning(f"⚠️ Source IP {row['src_ip']} was redirected/interacted {row['event_count']} times. Recommend adding to blacklist.")
    else:
        st.success("No sources currently meet the blacklist recommendation criteria.")
    st.markdown("---")

    # Bar chart: Number of events per source IP (including redirected)
    st.subheader("Honeypot Event Frequency (Bar Chart, including redirected)")
    import plotly.graph_objects as go
    bar_fig = go.Figure()
    bar_fig.add_trace(go.Bar(
        x=attacker_stats["src_ip"],
        y=attacker_stats["event_count"],
        marker_color=["#434fa0" if not redirected else "#8e44ad" for redirected in attacker_stats["redirected_only"]],
        width=0.15,  # Narrow bars
        text=attacker_stats["event_count"],
        textposition='auto',
    ))
    bar_fig.update_layout(
        title_text="",
        xaxis_title="Source IP",
        yaxis_title="Event Count",
        height=350,
        width=500,
        margin=dict(l=60, r=60, t=30, b=50)
    )
    with st.container():
        st.markdown("""
        <div style='width:520px; margin: 0 auto; display: flex; justify-content: center;'>
        """, unsafe_allow_html=True)
        st.plotly_chart(bar_fig)
        st.markdown("""
        </div>
        """, unsafe_allow_html=True)

    # Show only the 10 most recent events, without the 'bytes' column
    st.subheader("Recent Honeypot Events")
    if not df.empty:
        recent_events = df[["timestamp", "src_ip", "dst_port", "payload_preview"]].head(10)
        st.dataframe(recent_events)
    else:
        st.info("No honeypot event data available.")
