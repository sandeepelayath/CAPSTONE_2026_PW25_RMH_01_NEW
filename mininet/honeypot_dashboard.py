import streamlit as st
import os
import json
import glob
import pandas as pd

# Add autorefresh (every 5 seconds)
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=5000, limit=None, key="honeypot_autorefresh")
except Exception:
    from streamlit.components.v1 import html as _st_html
    _st_html("<script>setInterval(()=>{window.location.reload();}, 5000);</script>", height=0)

LOG_DIR = "/tmp/honeypot_logs/"
st.title("Honeypot Analytics Dashboard")

files = sorted(glob.glob(os.path.join(LOG_DIR, "event_*.json")), reverse=True)
events = []
for fname in files:
    try:
        with open(fname) as f:
            events.append(json.load(f))
    except Exception:
        pass

if not events:
    st.info("No honeypot events yet. Waiting for attacker interactions...")
else:
    df = pd.DataFrame(events)
    # --- Executive Summary KPIs ---
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric("Total Attacks", len(df))
    with kpi2:
        st.metric("Unique Attacker IPs", df['src_ip'].nunique())
    with kpi3:
        if 'dst_port' in df.columns:
            top_port = df['dst_port'].mode()[0] if not df['dst_port'].isnull().all() else 'N/A'
            st.metric("Most Targeted Port", top_port)
        else:
            st.metric("Most Targeted Port", "N/A")
    with kpi4:
        if 'payload_preview' in df.columns:
            top_payload = df['payload_preview'].mode()[0] if not df['payload_preview'].isnull().all() else 'N/A'
            st.metric("Top Payload", str(top_payload)[:20])
        else:
            st.metric("Top Payload", "N/A")
    st.markdown("---")

    # --- Top Attackers Table ---
    st.subheader("Top Attackers")
    if 'src_ip' in df.columns:
        attacker_stats = df.groupby('src_ip').agg(
            count=('src_ip', 'size'),
            first_seen=('timestamp', 'min'),
            last_seen=('timestamp', 'max')
        ).sort_values('count', ascending=False).head(10).reset_index()
        st.dataframe(attacker_stats, use_container_width=True)
    else:
        st.info("No attacker IP data available.")
    st.markdown("---")

    # --- Recommendations/Alerts Section ---
    st.subheader("Recommendations & Alerts")
    if 'src_ip' in df.columns:
        frequent_attackers = df['src_ip'].value_counts()
        flagged = frequent_attackers[frequent_attackers >= 4]
        if not flagged.empty:
            for ip, count in flagged.items():
                st.warning(f"⚠️ Source IP {ip} was redirected to the honeypot {count} times. Recommend adding to blacklist.")
        else:
            st.success("No sources currently meet the blacklist recommendation criteria.")
    st.markdown("---")

    # Bar chart: Number of events per source IP
    st.subheader("Honeypot Event Frequency (Bar Chart)")
    event_counts = df["src_ip"].value_counts()
    st.bar_chart(event_counts)

    # Line chart: Traffic to honeypot from different IPs over time (show all data)
    st.subheader("Honeypot Event Timeline (Line Chart)")
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
    df = df.dropna(subset=['datetime'])
    if not df.empty:
        traffic_by_time = df.groupby([pd.Grouper(key='datetime', freq='5min'), 'src_ip']).size().unstack(fill_value=0)
        st.line_chart(traffic_by_time)
    else:
        st.info("No honeypot traffic available.")

    # Show only the 10 most recent events, without the 'bytes' column
    st.subheader("Recent Honeypot Events")
    recent_events = df[["timestamp", "src_ip", "dst_port", "payload_preview"]].head(10)
    st.dataframe(recent_events)
