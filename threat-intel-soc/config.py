# config.py — SOC Project Configuration
# AlienVault removed. Using free feeds (no API key needed).

# Data file (do not change — your existing CSV)
DATA_FILE = "threat_data_10K.csv"

# Pipeline settings
POLLING_INTERVAL         = 21600   # 6 hours (free feeds update slowly)
CONFIDENCE_THRESHOLD     = 2
MAX_INDICATORS_PER_PULSE = 500     # per feed

# Legacy keys kept for compatibility (not used)
API_KEY    = ""
API_URL    = ""
PULSES_LIMIT = 50
