# config.py — SOC Project Configuration
# Supports both AlienVault OTX API and free feeds

import os
from dotenv import load_dotenv

# Load environment variables from .env file (if exists)
load_dotenv()

# Data file (fallback static data)
DATA_FILE = "threat_data_10K.csv"

# Pipeline settings
POLLING_INTERVAL         = 21600   # 6 hours (recommended for free feeds)
CONFIDENCE_THRESHOLD     = 2       # Minimum confidence score
MAX_INDICATORS_PER_PULSE = 500     # Maximum indicators per feed

# AlienVault OTX API Configuration
# Priority: Environment variable > Hardcoded value
API_KEY = os.getenv('OTX_API_KEY', '5298f109b39665384a9147df1f17651b97384ba33c3510eaf98ba5c723570158')
API_URL = os.getenv('OTX_API_URL', 'https://otx.alienvault.com/api/v1/pulses/subscribed')
PULSES_LIMIT = int(os.getenv('PULSES_LIMIT', '50'))

# Feature flags
USE_OTX_API = bool(API_KEY and API_KEY != "")  # Auto-enable if API key exists
USE_FREE_FEEDS = True  # Always use free feeds as backup

# Free Threat Intelligence Feeds (no API key needed)
FREE_FEEDS = {
    "feodo_tracker":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "emerging_threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "cins_score":       "https://cinsscore.com/list/ci-badguys.txt",
    "spamhaus_drop":    "https://www.spamhaus.org/drop/drop.txt",
}

# Geolocation API (free, no key needed)
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=countryCode,country,city"
GEO_RATE_LIMIT = 45  # requests per minute

# Debug mode
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

def get_config_summary():
    """Returns configuration summary for debugging"""
    return {
        "OTX API Enabled": USE_OTX_API,
        "Free Feeds Enabled": USE_FREE_FEEDS,
        "API Key Present": bool(API_KEY and len(API_KEY) > 10),
        "Polling Interval": f"{POLLING_INTERVAL}s ({POLLING_INTERVAL/3600}h)",
        "Max Indicators": MAX_INDICATORS_PER_PULSE,
        "Debug Mode": DEBUG
    }

if __name__ == "__main__":
    import json
    print("🔧 Configuration Summary:")
    print(json.dumps(get_config_summary(), indent=2))