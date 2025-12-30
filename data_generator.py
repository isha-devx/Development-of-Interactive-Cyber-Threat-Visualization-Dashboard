import pandas as pd
import random
from datetime import datetime, timedelta

# Configuration
num_records = 350
attack_types = ['DDoS', 'SQL Injection', 'Phishing', 'Malware', 'Brute Force', 'Man-in-the-Middle']
severities = ['Low', 'Medium', 'High', 'Critical']
protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH']
countries = ['USA', 'India', 'China', 'Germany', 'Russia', 'UK', 'Canada', 'Brazil']

data = []

for i in range(num_records):
    # Generating random time within the last 30 days
    dt = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
    
    data.append({
        'Incident_ID': f'INC-{2024}-{1000+i}',
        'Timestamp': dt.strftime('%Y-%m-%d %H:%M:%S'),
        'Source_IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'Destination_IP': f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
        'Attack_Type': random.choice(attack_types),
        'Severity': random.choice(severities),
        'Protocol': random.choice(protocols),
        'Port': random.choice([80, 443, 22, 21, 3306, 53]),
        'Country': random.choice(countries),
        'Traffic_Volume_MB': round(random.uniform(0.1, 500.0), 2),
        'Is_Malicious': 1 if random.random() > 0.15 else 0  # 85% chance of being malicious in this simulated dataset
    })

# Create DataFrame and Save
df = pd.DataFrame(data)
df.to_csv('cyber_threat_data.csv', index=False)

print("SUCCESS: 'cyber_threat_data.csv' has been generated with 350 records.")
