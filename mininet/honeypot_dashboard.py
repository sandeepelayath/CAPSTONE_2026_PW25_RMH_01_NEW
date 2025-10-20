import streamlit as st
import os
import json
import glob
import pandas as pd

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
    st.dataframe(df[["timestamp", "src_ip", "dst_port", "bytes", "payload_preview"]])
    st.bar_chart(df["src_ip"].value_counts())
