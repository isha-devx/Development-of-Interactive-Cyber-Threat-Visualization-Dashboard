# Task 1: Model Research - Cyber Threat Detection

### 1. Objective
To research and identify suitable models for categorizing and detecting malicious activities in network traffic.

### 2. Proposed Frameworks
- **MITRE ATT&CK Mapping:** We will use this framework to map incidents to specific tactics like Initial Access, Persistence, and Exfiltration.
- **Anomaly Detection:** Using statistical methods to identify spikes in traffic that deviate from the baseline.

### 3. Machine Learning Approaches
For this project, we explored:
- **Random Forest Classifier:** Effective for classifying attack types based on features like Port, Protocol, and Severity.
- **Isolation Forest:** An unsupervised learning algorithm perfect for detecting "Outliers" or anomalies in security logs.

### 4. Visualization Strategy
- **Geospatial Maps:** To track the source and destination of attacks.
- **Time-Series Analysis:** To monitor attack frequency over hours/days.
