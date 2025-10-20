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
    st.write(f"Total events: {len(df)}")

    # Bar chart: Number of events per source IP
    st.bar_chart(df["src_ip"].value_counts())

    # Line chart: Traffic to honeypot from different IPs over time (show all data)
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
    df = df.dropna(subset=['datetime'])
    if not df.empty:
        traffic_by_time = df.groupby([pd.Grouper(key='datetime', freq='5min'), 'src_ip']).size().unstack(fill_value=0)
        st.line_chart(traffic_by_time)
    else:
        st.info("No honeypot traffic available.")

    # Show only the 10 most recent events, without the 'bytes' column
    st.markdown('### Recent Honeypot Events')
    st.dataframe(df[["timestamp", "src_ip", "dst_port", "payload_preview"]].head(10))
