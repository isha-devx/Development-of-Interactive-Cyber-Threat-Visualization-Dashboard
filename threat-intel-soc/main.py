# main.py — SOC Pipeline Runner (improved with graceful shutdown)
import time, signal, sys
from datetime import datetime
from config import POLLING_INTERVAL
from collector import fetch_threats, enrich_with_geolocation
from processor import get_severity, classify_attack_type, get_mitre_technique, get_target_system
from storage import save_csv, get_stats

_running = True

def _stop(sig, frame):
    global _running
    print("\n[PIPELINE] Stopping...")
    _running = False

signal.signal(signal.SIGINT,  _stop)
signal.signal(signal.SIGTERM, _stop)

def run_soc_pipeline():
    print("=" * 58)
    print("  SOC THREAT INTELLIGENCE PIPELINE")
    print("  Source: 4 Free Feeds (no API key)")
    print(f"  Interval: {POLLING_INTERVAL}s ({POLLING_INTERVAL/3600:.1f} hours)")
    print("=" * 58)
    cycle = 0

    while _running:
        cycle += 1
        start = datetime.now()
        print(f"\n--- Cycle #{cycle} — {start.strftime('%Y-%m-%d %H:%M:%S')} ---")

        raw = fetch_threats()
        saved = skipped = 0

        for threat in raw:
            if not _running: break
            ip          = threat.get("ipAddress","").strip()
            country     = threat.get("countryCode","Unknown")
            score       = int(threat.get("abuseConfidenceScore", 80))
            description = threat.get("description","")
            if not ip: continue

            if country == "Unknown":
                country = enrich_with_geolocation(ip)

            severity    = get_severity(score)
            attack_type = classify_attack_type(score, description)
            mitre       = get_mitre_technique(attack_type)
            target      = get_target_system(attack_type)

            if save_csv(ip, country, score, severity, attack_type, mitre, target):
                saved += 1
            else:
                skipped += 1

        stats = get_stats()
        print(f"[PIPELINE] Saved: {saved}  Skipped (dup): {skipped}")
        print(f"[PIPELINE] DB Total: {stats['total']} | Critical: {stats['critical']} | High: {stats['high']}")
        print(f"[PIPELINE] Sleeping {POLLING_INTERVAL}s...")

        for _ in range(POLLING_INTERVAL):
            if not _running: break
            time.sleep(1)

    print("[PIPELINE] Done.")

if __name__ == "__main__":
    run_soc_pipeline()
