# CAPSTONE 2026: Secure Traffic Anomaly Detection in Software Defined Networks using Neural Networks

## Overview
This project implements a machine learning approach for detecting anomalies in encrypted network traffic within a Software-Defined Networking (SDN) environment. The system utilizes Mininet for network simulation, Ryu as an SDN controller, and a trained ML model for anomaly detection.

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

## Dataset Preparation and ML MOdel Training
1. Download the CIC-IDS2017 dataset. (It is also available https://drive.google.com/drive/folders/1kSNKSGeiKaRAoVMY8cIcMQ_FM1rMUdEY)
2. Collect data from real-time mininet network traffic and store as csv - to be combined with dataset
   ```bash
   sudo env "PATH=$PATH" python3 mininet-data-collector.py
   ```
4. Store the CSV files inside `ML_Model_Latest/data/`
5. Training the Model
   ```bash
   cd ML_Model_Latest
   python LSTM_RANN_Hybrid_Phase3.py #to fine tune hyperparameters
   python LSTM_RANN_Hybrid_Phase3_store_final_tuned_model.py #to train and store the model using finetuned hyperparameters
   ```

## Trained models after Finetuning
LSTM+RaNN Hybrid model stored in: Capstone_Phase3/lstm_rann_hybrid_finetuned_ml_model/
This pre trained model is loaded and used in FlowClassifier (Capstone_Phase3/controller/flow_classier.py)


## Execution Workflow
### Terminal 1 (Controller):
```bash
cd Capstone_Phase3/controller/
ryu-manager ryu_controller.py
```
### Terminal 2 (Mininet Topology Simulation):
```bash
cd Capstone_Phase3/mininet/
sudo python3 test_topology.py
```
### Terminal 3 (Start Analytics Dashboard):
```bash
cd Capstone_Phase3/
./run_dashboard.sh #Open Admin dashboard in http://127.0.0.1:8501/ and HOneypot dashboard in http://127.0.0.1:8502/
```
### Terminal 4 (Check The Accuracy after test_topology.py execution completes):
```bash
cd Capstone_Phase3/
python3 accuracy_calculator.py 
```
## Cleanup
After execution, clean up Mininet:
```bash
sudo mn -c
```

## Contributors
- **Sandeep Elayath**
- **Safdar Ahmad**
- **Vidhan Viswas**
- **Basavraj Naikal**

## License
This project is open-source and available under the MIT License.

