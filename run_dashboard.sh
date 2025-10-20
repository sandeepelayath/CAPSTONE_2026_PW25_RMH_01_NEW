#!/bin/bash

# SDN Security Operations Center Dashboard Launcher
# This script launches the enhanced analytics dashboard and honeypot dashboard

echo "🛡️ Starting SDN Security Operations Center Dashboard..."
echo "📊 Loading enhanced analytics with professional visualizations..."
echo "Dashboard will be available at: http://localhost:8501"
echo ""
echo "🪤 Starting Honeypot Intelligence Dashboard..."
echo "Honeypot dashboard will be available at: http://localhost:8502"
echo ""
echo "Press Ctrl+C to stop both dashboards"
echo ""

# Change to the directory containing the dashboard
cd "$(dirname "$0")"

# Launch the Streamlit dashboards
streamlit run analytics_dashboard.py --server.port 8501 --server.address 0.0.0.0 --server.headless true &
streamlit run mininet/honeypot_dashboard.py --server.port 8502 --server.address 0.0.0.0 --server.headless true &
wait
