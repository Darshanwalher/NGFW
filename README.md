# 🛡️ NetGuard IDS v2.0
### Hybrid Machine Learning Network Intrusion Detection System

An advanced real-time Intrusion Detection System built using **XGBoost + Isolation Forest**. It features live packet capture, deep traffic visualization, and **SHAP-based explainable AI**—all wrapped in a high-end Streamlit cyber dashboard.

---

## 🚀 Overview

NetGuard IDS is a hybrid detection system designed to monitor and secure network environments through:

* 📡 **Live Capture:** Real-time traffic sniffing using Scapy.
* 🧠 **Feature Engineering:** Extraction of 33 advanced flow-based features.
* 🔍 **Dual-Engine Detection:**
    * **Supervised:** XGBoost for known attack patterns.
    * **Unsupervised:** Isolation Forest for zero-day anomaly detection.
* 🔬 **Explainable AI:** SHAP integration to provide transparency for every detection.
* 📊 **Visual Analytics:** Interactive Plotly charts and time-series data.

---

## 🧠 Hybrid Detection Logic

NetGuard uses a multi-layered decision strategy to minimize false negatives:

1.  **XGBoost Classifier:** Identifies signatures of known threats.
2.  **Isolation Forest:** Flags outliers that deviate from normal baseline behavior.

> **Decision Strategy:**
> * If `XGBoost probability >= threshold` → **Malicious**
> * Else if `Isolation score < 0` → **Malicious** (Anomaly)
> * Else → **Benign**

[Image of a flowchart showing a hybrid machine learning decision tree combining XGBoost and Isolation Forest for network security]

---

## 📊 Feature Extraction (33 Metrics)

The system transforms raw packets into actionable data, including:
* **Flow Statistics:** Duration, total bytes, and packet counts.
* **Directional Data:** Forward/Backward packet statistics.
* **Timing:** Inter-arrival time (IAT) statistics.
* **TCP Flags:** SYN, ACK, RST, FIN, PSH, URG counts.
* **Rates:** Packets per second and size variance.

---

## 📈 Interactive Visualizations

The dashboard provides deep-dive analytics into captured traffic:
* **Packet Dynamics:** Forward vs. Backward size distribution.
* **Threat Hints:** TCP flag distribution categorized by risk levels.
* **Temporal Analysis:** Time-series scatter plots for packet bursts.
* **Explainability:** SHAP force plots showing feature impact on predictions.

---

## 🛠️ Tech Stack

| Component | Technologies |
| :--- | :--- |
| **Backend** | Python, Scapy, NumPy, Pandas, Joblib |
| **Machine Learning** | XGBoost, Isolation Forest, SHAP |
| **UI/UX** | Streamlit, Plotly, Matplotlib |

---

## 📂 Project Structure

```text
NetGuard-IDS/
├── app.py                  # Main Streamlit application
├── production/             # Pre-trained models & metadata
│   ├── xgb_production_v1.pkl
│   ├── iso_production_v1.pkl
│   └── background_data.pkl
├── requirements.txt        # Dependency list
└── README.md               # Documentation

⚠️ Important Deployment Notes
Elevated Privileges
Live packet capture requires raw socket access:

Linux / Mac: Run with sudo streamlit run app.py

Windows: Install Npcap in "WinPcap-compatible mode."

Cloud Limitations
Warning: Live capture will NOT work on cloud platforms (Render, Railway, Streamlit Cloud) due to kernel-level security sandboxing. For cloud demos, use:

Pre-recorded PCAP file uploads.

Static dataset-based testing.

🔬 Explainable AI (SHAP)
The system doesn't just say "Malicious"—it tells you why.

Red: Features pushing the score toward a "Malicious" classification.

Blue: Features suggesting "Benign" behavior.

🎯 Target Use Cases
Academic Cybersecurity Research.

Network Behavior Analysis.

IDS/IPS Prototyping.

Machine Learning in Security (MLSec) experimentation.

🔮 Future Enhancements
[ ] Deep Learning integration (LSTM/CNN).

[ ] Real-time Auto-blocking Firewall integration.

[ ] SIEM (Splunk/ELK) export support.

[ ] Threat Intelligence API lookups (VirusTotal/AbuseIPDB).


---

