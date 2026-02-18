# collector.py — Free Threat Intelligence Collector
# Replaces AlienVault OTX with 4 permanently free feeds (no API key needed).
# Sources: Feodo Tracker, Emerging Threats, CINS Score, Spamhaus DROP

import requests
import ipaddress
import time
from typing import List, Dict, Any
from config import MAX_INDICATORS_PER_PULSE

FREE_FEEDS = {
    "feodo_tracker":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "emerging_threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "cins_score":       "https://cinsscore.com/list/ci-badguys.txt",
    "spamhaus_drop":    "https://www.spamhaus.org/drop/drop.txt",
}

_geo_cache: Dict[str, str] = {}


def is_valid_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return (addr.version == 4 and not addr.is_private
                and not addr.is_loopback and not addr.is_link_local
                and not addr.is_multicast and not addr.is_reserved)
    except ValueError:
        return False


def fetch_threats() -> List[Dict[str, Any]]:
    """Download bad IPs from 4 free feeds. No API key required."""
    all_ips: set = set()

    for name, url in FREE_FEEDS.items():
        try:
            print(f"[COLLECTOR] Downloading {name}...")
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                ip_part = line.split()[0].split("/")[0]
                if is_valid_public_ip(ip_part):
                    all_ips.add(ip_part)
            print(f"[COLLECTOR] OK {name}: {len(all_ips)} IPs so far")
        except Exception as e:
            print(f"[COLLECTOR] WARN {name} failed: {e}")

    ip_list = list(all_ips)[:MAX_INDICATORS_PER_PULSE * len(FREE_FEEDS)]
    print(f"[COLLECTOR] Total unique bad IPs: {len(ip_list)}")

    return [{"ipAddress": ip, "countryCode": "Unknown",
             "abuseConfidenceScore": 80, "description": ""} for ip in ip_list]


def enrich_with_geolocation(ip: str) -> str:
    """ip-api.com geolocation — free, no key, 45 req/min."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                cc = data.get("countryCode", "Unknown")
                _geo_cache[ip] = cc
                return cc
        if resp.status_code == 429:
            time.sleep(1)
    except Exception:
        pass
    _geo_cache[ip] = "Unknown"
    return "Unknown"