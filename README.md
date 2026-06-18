# AI Threat Hunter

An ML-powered network threat hunting platform built with Streamlit and Isolation Forest for identifying suspicious network behavior, potential Command & Control (C2) communications, and anomalous traffic patterns.

---

## Overview

AI Threat Hunter is an unsupervised machine learning application designed to analyze network flow telemetry and identify high-risk connections without requiring labeled attack data.

The platform dynamically profiles uploaded network traffic, calculates anomaly scores, and ranks connections based on their likelihood of representing malicious activity.

### Key Capabilities

* Unsupervised anomaly detection using Isolation Forest
* Dynamic network baseline profiling
* Threat confidence scoring
* Interactive threat hunting dashboard
* Timeline visualization of suspicious activity
* Identification of high-risk network flows
* Streamlit-based analyst interface

---

## Architecture

```text
Network Flow CSV
        │
        ▼
Feature Engineering
        │
        ▼
Data Standardization
        │
        ▼
Isolation Forest
        │
        ▼
Anomaly Scoring
        │
        ▼
Threat Confidence Calculation
        │
        ▼
Threat Hunting Dashboard
```

---

## Feature Engineering

The application derives additional security-focused features from raw network telemetry:

### Threat Byte Ratio

```text
Forward Bytes / Backward Bytes
```

### Threat Packet Ratio

```text
Forward Packets / Backward Packets
```

### Additional Features

* Flow Duration
* Flow Bytes per Second
* Flow Packets per Second
* Forward Packet Length Mean
* Forward Packet Length Standard Deviation
* Backward Packet Length Standard Deviation
* Average Packet Size

---

## Machine Learning Model

The application uses the Isolation Forest algorithm from Scikit-Learn.

### Why Isolation Forest?

* Works without labeled attack data
* Effective for anomaly detection
* Scales well to large datasets
* Suitable for identifying unusual network behaviors

### Detection Process

1. Network features are extracted.
2. Data is standardized.
3. Isolation Forest learns the network baseline.
4. Anomaly scores are generated.
5. Threat confidence scores are calculated.
6. Connections are ranked by risk.

---

## Dashboard Components

### Threat Intelligence Overview

Displays:

* Total Connections Analyzed
* Benign Traffic Count
* Anomalies Detected

### Anomaly Distribution

Interactive Plotly visualization showing:

* Network activity timeline
* Isolation Forest anomaly scores
* Threat classifications

### Top Model-Detected Threats

Displays connections classified as anomalous by the model.

### Top Suspicious Connections

Displays the highest-ranked connections by threat confidence score.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/AI-threat-hunter.git
cd AI-threat-hunter
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
streamlit run app.py
```

---

## Dataset Format

The application expects a CSV containing network flow features such as:

```text
timestamp
src_ip
dst_ip
flow_duration
flow_bytes/s
flow_packets/s
total_fwd_packets
total_backward_packets
average_packet_size
...
```

Datasets generated from CICFlowMeter can be used directly.

---

## Future Enhancements

Planned improvements include:

* PCAP ingestion
* Zeek integration
* Beaconing detection engine
* DNS tunneling detection
* JA3 fingerprint analysis
* Threat intelligence enrichment
* MITRE ATT&CK mapping
* LLM-generated SOC analyst summaries

---

## Technology Stack

* Python
* Streamlit
* Pandas
* NumPy
* Scikit-Learn
* Plotly

---

## Disclaimer

This project is intended for educational, research, and threat hunting purposes. Isolation Forest identifies anomalous behavior and should not be treated as a standalone malware detection system.
