# CAPSTONE 2026: Secure Traffic Anomaly Detection in Software Defined Networks using Neural Networks

## Overview

This project implements a real-time, encryption-agnostic anomaly detection and adaptive mitigation framework for Software-Defined Networking (SDN) environments. It combines a hybrid **LSTM + Randomized Neural Network (RaNN)** model for traffic classification with a risk-based mitigation engine that triggers automated defenses — rate-limiting, honeypot redirection, and dynamic flow blocking — directly from the SDN controller.

The system is simulated using **Mininet** for network topology, **Ryu** as the SDN controller, and includes live analytics dashboards for monitoring detection and mitigation activity in real time.

## Key Features

- **Encryption-agnostic detection** — classifies traffic using flow-level statistical features only, without payload inspection or decryption.
- **Hybrid LSTM + RaNN model** — combines temporal pattern learning (LSTM) with fast randomized-network inference for low-latency classification.
- **Risk-based mitigation engine** — graduated response system (passive monitoring → adaptive rate limiting → honeypot redirection → immediate blocking) based on a multi-factor risk score.
- **Honeypot-based threat intelligence** — tripwire mechanism for high-confidence detection of malicious sources.
- **Live analytics dashboards** — real-time admin and honeypot monitoring dashboards built with Streamlit.

## Repository Structure

```
.
├── ML_Model_Latest/          # Model training scripts and fine-tuned model artifacts
├── controller/                # Ryu SDN controller and flow classifier
├── mininet/                   # Network topology simulation scripts
├── accuracy_calculator.py     # Post-run accuracy/metrics evaluation
├── admin_interface.py         # Admin dashboard (whitelist/blacklist controls, manual overrides)
├── analytics_dashboard.py     # Real-time analytics and monitoring dashboard
├── run_dashboard.sh           # Script to launch both dashboards
└── requirements.txt           # Python dependencies
```

## Prerequisites

### System Requirements
- Ubuntu 20.04 or later
- Python 3.9
- Mininet
- Open vSwitch

### Installation Steps

1. Update system packages:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. Install dependencies:
   ```bash
   sudo apt install mininet python3-pip openvswitch-switch tcpdump
   sudo add-apt-repository ppa:deadsnakes/ppa -y
   sudo apt update
   sudo apt install python3.9 python3.9-venv python3.9-dev -y
   ```

3. Create and activate a virtual environment:
   ```bash
   python3.9 -m venv myenv39
   source myenv39/bin/activate
   ```

4. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Dataset Preparation and Model Training

1. Download the [CIC-IDS2017 dataset](https://drive.google.com/drive/folders/1kSNKSGeiKaRAoVMY8cIcMQ_FM1rMUdEY).
2. Collect live Mininet traffic to combine with the base dataset:
   ```bash
   sudo env "PATH=$PATH" python3 mininet-data-collector.py
   ```
3. Place the resulting CSV files inside `ML_Model_Latest/data/`.
4. Train the model:
   ```bash
   cd ML_Model_Latest
   python LSTM_RANN_Hybrid_Phase3.py                          # Hyperparameter tuning
   python LSTM_RANN_Hybrid_Phase3_store_final_tuned_model.py  # Train and save final model
   ```

The fine-tuned LSTM+RaNN hybrid model is stored in `Capstone_Phase3/lstm_rann_hybrid_finetuned_ml_model/` and loaded by the `FlowClassifier` in `Capstone_Phase3/controller/flow_classifier.py`.

## Execution Workflow

Run each of the following in a separate terminal:

**Terminal 1 — Mininet Topology Simulation**
```bash
cd Capstone_Phase3/mininet/
sudo python3 test1.py   # or test2.py / test3.py / test_topology.py
```

**Terminal 2 — SDN Controller**
```bash
cd Capstone_Phase3/controller/
ryu-manager ryu_controller.py
```

**Terminal 3 — Analytics Dashboards**
```bash
cd Capstone_Phase3/
./run_dashboard.sh
```
- Admin dashboard: http://127.0.0.1:8501/
- Honeypot dashboard: http://127.0.0.1:8502/

**Terminal 4 — Accuracy Check (after `test_topology.py` completes)**
```bash
cd Capstone_Phase3/
python3 accuracy_calculator.py
```

## Cleanup

Cleanup runs automatically at the start of each test script. For an explicit manual cleanup:
```bash
sudo mn -c
```

## Results

As reported in the Phase 3 project report (internal testing on the CIC-IDS2017 dataset and Mininet-generated traffic):

| Metric | Value |
|---|---|
| Precision | 95.2% |
| Recall | 93.8% |
| F1-Score | 94.5% |
| Detection latency (median) | 12 ms |
| Mitigation latency (median) | 18 ms |
| Max supported flow rate | 10,000 flows/sec |

> Note: these figures come from local/internal validation during development and testing was noted as constrained by local machine performance. They should be treated as indicative rather than final benchmark numbers.

## Contributors

- **Sandeep Elayath**
- **Safdar Ahmad**
- **Vidhan Viswas**
- **Basavaraj Naikal**

Guided by **Dr. Radhika M Hirannaiah**, Associate Professor, PES University.

## License

This project is open-source and was completed as part of the final-year Capstone Project at PES University, Bengaluru.
