# storage.py — Thread-safe CSV storage with smart deduplication
import csv, os, threading
from datetime import datetime
from config import DATA_FILE

HEADERS = ["timestamp","severity","score","country","attack_type","mitre","source_ip","target_system"]
_lock = threading.Lock()
_seen_today: set = set()

def _load_today_ips():
    if not os.path.exists(DATA_FILE):
        return
    today = datetime.now().date()
    try:
        with open(DATA_FILE, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    if datetime.fromisoformat(row["timestamp"]).date() == today:
                        _seen_today.add(row["source_ip"])
                except Exception:
                    pass
    except Exception as e:
        print(f"[STORAGE] Warning: {e}")

_load_today_ips()

def is_duplicate(ip: str) -> bool:
    return ip in _seen_today

def save_csv(ip, country, score, severity, attack_type, mitre, target_system) -> bool:
    if is_duplicate(ip):
        return False
    file_exists = os.path.isfile(DATA_FILE)
    row = [datetime.now(), severity, score, country, attack_type, mitre, ip, target_system]
    try:
        with _lock:
            with open(DATA_FILE, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if not file_exists:
                    w.writerow(HEADERS)
                w.writerow(row)
            _seen_today.add(ip)
        print(f"[STORAGE] Saved: {ip} | {country} | {severity} | {attack_type}")
        return True
    except Exception as e:
        print(f"[STORAGE] Error: {e}")
        return False

def get_stats() -> dict:
    if not os.path.exists(DATA_FILE):
        return {"total":0,"critical":0,"high":0,"medium":0,"low":0}
    try:
        with open(DATA_FILE, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return {
            "total":    len(rows),
            "critical": sum(1 for r in rows if r.get("severity")=="Critical"),
            "high":     sum(1 for r in rows if r.get("severity")=="High"),
            "medium":   sum(1 for r in rows if r.get("severity")=="Medium"),
            "low":      sum(1 for r in rows if r.get("severity")=="Low"),
        }
    except Exception as e:
        print(f"[STORAGE] Warning: {e}")
        return {"total":0,"critical":0,"high":0,"medium":0,"low":0}
