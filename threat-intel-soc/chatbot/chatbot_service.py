# chatbot/chatbot_service.py — Data-aware SOC Chatbot
# Replace the existing chatbot/chatbot_service.py with this file.

import random, os, sys, csv
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from config import DATA_FILE
except ImportError:
    DATA_FILE = "threat_data_10K.csv"


def _load_df():
    rows = []
    if not os.path.exists(DATA_FILE):
        return rows
    try:
        with open(DATA_FILE, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except Exception:
        pass
    return rows


def get_bot_response(user_message: str) -> str:
    rows = _load_df()
    l    = user_message.lower()

    total    = len(rows)
    critical = sum(1 for r in rows if r.get("severity") == "Critical")
    high     = sum(1 for r in rows if r.get("severity") == "High")

    from collections import Counter
    countries = Counter(r.get("country","") for r in rows)
    attacks   = Counter(r.get("attack_type","") for r in rows)
    targets   = Counter(r.get("target_system","") for r in rows)
    mitres    = Counter(r.get("mitre","") for r in rows)

    top_cc  = ", ".join(f"{k}({v})" for k,v in countries.most_common(5))
    top_atk = ", ".join(f"{k}({v})" for k,v in attacks.most_common(5))
    top_tgt = ", ".join(f"{k}({v})" for k,v in targets.most_common(4))
    top_mit = ", ".join(f"{k}({v})" for k,v in mitres.most_common(5))

    QA = [
        (["total","how many","count","threat"],
         f"Database has {total:,} threats — {critical:,} Critical, {high:,} High."),
        (["countr","origin","geo","region"],
         f"Top threat origins: {top_cc}."),
        (["attack","type","method"],
         f"Top attack types: {top_atk}."),
        (["mitre","att&ck","tactic"],
         f"Top MITRE techniques: {top_mit}."),
        (["target","system","victim"],
         f"Most targeted systems: {top_tgt}."),
        (["score","risk","sever","rating"],
         "Scores 0-100: Critical ≥90, High ≥70, Medium ≥40, Low ≥10."),
        (["report","summary","brief"],
         f"Summary: {total:,} events | {critical:,} Critical | Top country: {countries.most_common(1)[0][0] if countries else 'N/A'} | Top attack: {attacks.most_common(1)[0][0] if attacks else 'N/A'}."),
        (["response","contain","block"],
         "Response: 1) Validate IP via VirusTotal. 2) Block at firewall. 3) Isolate system. 4) Log incident."),
        (["feed","source","collector","api"],
         "Using 4 free feeds: Feodo Tracker, Emerging Threats, CINS Score, Spamhaus DROP — no API key needed!"),
        (["export","download","csv"],
         f"Your data is in threat_data_10K.csv ({total:,} rows). Open it in Excel or use pandas to analyse."),
        (["dashboard","what","about"],
         f"This SOC dashboard monitors {total:,} threats. It has 9 tabs: Overview, Trends, Geo Map, Attacks, Heatmap, MITRE, Targets, Anomaly, Critical Threats."),
    ]

    for keys, ans in QA:
        if any(k in l for k in keys):
            return ans

    fallback = [
        "Try: 'how many threats', 'top countries', 'attack types', 'MITRE techniques', or 'generate report'.",
        f"I'm tracking {total:,} threats right now. Ask me about countries, attack types, or MITRE tactics!",
        "Use the sidebar to explore: Trends, Geo Map, MITRE ATT&CK, Anomaly Detection, and more.",
    ]
    return random.choice(fallback)