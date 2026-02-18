# collector.py — Hybrid Threat Intelligence Collector
# Supports AlienVault OTX API + 4 free feeds (no API key needed)
# Automatically uses both sources for comprehensive threat intelligence

import requests
import ipaddress
import time
from typing import List, Dict, Any, Set
from datetime import datetime
from config import (
    MAX_INDICATORS_PER_PULSE, 
    API_KEY, 
    API_URL, 
    PULSES_LIMIT,
    FREE_FEEDS,
    USE_OTX_API,
    USE_FREE_FEEDS,
    CONFIDENCE_THRESHOLD,
    DEBUG
)

_geo_cache: Dict[str, str] = {}


def log(message: str, level: str = "INFO"):
    """Simple logging with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")


def is_valid_public_ip(ip_str: str) -> bool:
    """Check if string is a valid public IPv4 address"""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return (addr.version == 4 and not addr.is_private
                and not addr.is_loopback and not addr.is_link_local
                and not addr.is_multicast and not addr.is_reserved)
    except ValueError:
        return False


def fetch_from_free_feeds() -> List[Dict[str, Any]]:
    """Download bad IPs from 4 free feeds. No API key required."""
    log("Starting free feeds collection...")
    all_ips: Set[str] = set()

    for name, url in FREE_FEEDS.items():
        try:
            log(f"Downloading {name}...", "INFO")
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            
            initial_count = len(all_ips)
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                ip_part = line.split()[0].split("/")[0]
                if is_valid_public_ip(ip_part):
                    all_ips.add(ip_part)
            
            new_ips = len(all_ips) - initial_count
            log(f"✓ {name}: Added {new_ips} new IPs (Total: {len(all_ips)})", "INFO")
            
        except Exception as e:
            log(f"⚠ {name} failed: {e}", "WARN")

    ip_list = list(all_ips)[:MAX_INDICATORS_PER_PULSE * len(FREE_FEEDS)]
    log(f"Total unique bad IPs from free feeds: {len(ip_list)}", "INFO")

    return [
        {
            "ipAddress": ip,
            "countryCode": "Unknown",
            "abuseConfidenceScore": 80,
            "description": "Malicious IP from threat feeds",
            "source": "free_feeds",
            "type": "IPv4"
        } 
        for ip in ip_list
    ]


def fetch_from_otx_api() -> List[Dict[str, Any]]:
    """Fetch threat intelligence from AlienVault OTX API"""
    if not USE_OTX_API:
        log("OTX API disabled or no API key provided", "WARN")
        return []
    
    log("Starting AlienVault OTX API collection...", "INFO")
    threats = []
    
    try:
        headers = {
            'X-OTX-API-KEY': API_KEY,
            'Content-Type': 'application/json'
        }
        
        params = {
            'limit': PULSES_LIMIT,
            'modified_since': None  # Get all recent pulses
        }
        
        log(f"Requesting {PULSES_LIMIT} pulses from OTX...", "INFO")
        response = requests.get(API_URL, headers=headers, params=params, timeout=30)
        
        if response.status_code == 403:
            log("❌ API Key invalid or expired!", "ERROR")
            return []
        
        response.raise_for_status()
        data = response.json()
        
        pulses = data.get('results', [])
        log(f"✓ Received {len(pulses)} pulses from OTX", "INFO")
        
        # Process each pulse
        for pulse in pulses:
            pulse_name = pulse.get('name', 'Unknown')
            indicators = pulse.get('indicators', [])
            
            if DEBUG:
                log(f"Processing pulse: {pulse_name} ({len(indicators)} indicators)", "DEBUG")
            
            for indicator in indicators[:MAX_INDICATORS_PER_PULSE]:
                indicator_type = indicator.get('type', '')
                indicator_value = indicator.get('indicator', '')
                
                threat_data = {
                    "indicator": indicator_value,
                    "type": indicator_type,
                    "description": indicator.get('description', pulse_name),
                    "pulse_name": pulse_name,
                    "created": indicator.get('created', ''),
                    "source": "otx_api",
                    "tags": pulse.get('tags', []),
                    "industries": pulse.get('industries', []),
                    "malware_families": pulse.get('malware_families', [])
                }
                
                # Add IP-specific fields
                if indicator_type in ['IPv4', 'IPv6']:
                    threat_data['ipAddress'] = indicator_value
                    threat_data['countryCode'] = 'Unknown'
                    threat_data['abuseConfidenceScore'] = 90  # OTX data is high quality
                
                threats.append(threat_data)
        
        log(f"✓ Collected {len(threats)} indicators from OTX API", "INFO")
        
    except requests.exceptions.RequestException as e:
        log(f"❌ OTX API request failed: {e}", "ERROR")
    except Exception as e:
        log(f"❌ Unexpected error in OTX collection: {e}", "ERROR")
    
    return threats


def fetch_threats() -> List[Dict[str, Any]]:
    """
    Main threat collection function.
    Fetches from both OTX API and free feeds for comprehensive coverage.
    """
    log("=" * 60, "INFO")
    log("THREAT COLLECTION STARTED", "INFO")
    log("=" * 60, "INFO")
    
    all_threats = []
    
    # Collect from AlienVault OTX API
    if USE_OTX_API:
        try:
            otx_threats = fetch_from_otx_api()
            all_threats.extend(otx_threats)
            log(f"✓ OTX API: {len(otx_threats)} threats collected", "INFO")
        except Exception as e:
            log(f"⚠ OTX API collection failed: {e}", "WARN")
    else:
        log("⊘ OTX API disabled", "INFO")
    
    # Collect from free feeds
    if USE_FREE_FEEDS:
        try:
            free_threats = fetch_from_free_feeds()
            all_threats.extend(free_threats)
            log(f"✓ Free Feeds: {len(free_threats)} threats collected", "INFO")
        except Exception as e:
            log(f"⚠ Free feeds collection failed: {e}", "WARN")
    else:
        log("⊘ Free feeds disabled", "INFO")
    
    # Summary
    log("=" * 60, "INFO")
    log(f"TOTAL THREATS COLLECTED: {len(all_threats)}", "INFO")
    log("=" * 60, "INFO")
    
    return all_threats


def enrich_with_geolocation(ip: str) -> Dict[str, str]:
    """
    Enrich IP with geolocation data using ip-api.com
    Free service, 45 requests/minute
    """
    if ip in _geo_cache:
        return _geo_cache[ip]
    
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,country,city",
            timeout=5
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_data = {
                    "countryCode": data.get("countryCode", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown")
                }
                _geo_cache[ip] = geo_data
                return geo_data
        
        if resp.status_code == 429:
            log("⚠ Geolocation rate limit hit, waiting...", "WARN")
            time.sleep(2)
            
    except Exception as e:
        if DEBUG:
            log(f"Geolocation lookup failed for {ip}: {e}", "DEBUG")
    
    # Default fallback
    default = {"countryCode": "Unknown", "country": "Unknown", "city": "Unknown"}
    _geo_cache[ip] = default
    return default


def get_collection_stats() -> Dict[str, Any]:
    """Get statistics about the last collection"""
    return {
        "timestamp": datetime.now().isoformat(),
        "otx_enabled": USE_OTX_API,
        "free_feeds_enabled": USE_FREE_FEEDS,
        "cache_size": len(_geo_cache),
        "api_key_configured": bool(API_KEY and len(API_KEY) > 10)
    }


# Test mode
if __name__ == "__main__":
    log("Running collector in TEST mode...", "INFO")
    log(f"Configuration: OTX={USE_OTX_API}, Free Feeds={USE_FREE_FEEDS}", "INFO")
    
    threats = fetch_threats()
    
    print("\n" + "=" * 60)
    print("COLLECTION SUMMARY:")
    print("=" * 60)
    print(f"Total threats collected: {len(threats)}")
    
    if threats:
        print("\nFirst 3 threats:")
        for i, threat in enumerate(threats[:3], 1):
            print(f"\n{i}. {threat.get('source', 'unknown').upper()}")
            print(f"   Type: {threat.get('type', 'N/A')}")
            print(f"   Indicator: {threat.get('indicator', threat.get('ipAddress', 'N/A'))}")
            print(f"   Description: {threat.get('description', 'N/A')[:80]}")