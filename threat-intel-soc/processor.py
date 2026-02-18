# processor.py — Threat Data Processor (improved)
import random

SEVERITY_THRESHOLDS = [(90,"Critical"),(70,"High"),(40,"Medium"),(10,"Low")]

def get_severity(score: int) -> str:
    if not isinstance(score, (int, float)):
        return "Unknown"
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Informational"

_DESC_KEYWORDS = [
    (["ddos","denial"," dos "],          "DDoS"),
    (["brute","bruteforce","password"],  "Brute Force"),
    (["malware","trojan","virus","rat"], "Malware Distribution"),
    (["scan","port"],                    "Port Scanning"),
    (["sql","sqli","injection"],         "SQL Injection"),
    (["xss","cross-site"],               "XSS Attack"),
    (["phish","spam","email"],           "Phishing"),
    (["recon","reconnaissance"],         "Reconnaissance"),
    (["command","cmd","rce"],            "Command Injection"),
    (["crypto","mining","miner"],        "Cryptojacking"),
    (["traverse","directory"],           "Directory Traversal"),
    (["policy"],                         "Policy Violation"),
]

_SCORE_ATTACKS = {
    "critical": ["DDoS","Brute Force","Malware Distribution"],
    "high":     ["Port Scanning","SQL Injection","XSS Attack","Command Injection"],
    "medium":   ["Phishing","Spam","Reconnaissance","Directory Traversal"],
    "low":      ["Suspicious Activity","Policy Violation","Cryptojacking"],
}

def classify_attack_type(score: int, description: str = "") -> str:
    desc = description.lower()
    for keywords, attack in _DESC_KEYWORDS:
        if any(kw in desc for kw in keywords):
            return attack
    if score >= 90: return random.choice(_SCORE_ATTACKS["critical"])
    elif score >= 70: return random.choice(_SCORE_ATTACKS["high"])
    elif score >= 40: return random.choice(_SCORE_ATTACKS["medium"])
    return random.choice(_SCORE_ATTACKS["low"])

_MITRE_MAP = {
    "DDoS":"T1498","Brute Force":"T1110","Malware Distribution":"T1204",
    "Port Scanning":"T1046","SQL Injection":"T1190","XSS Attack":"T1059",
    "Phishing":"T1566","Spam":"T1566","Reconnaissance":"T1592",
    "Suspicious Activity":"T1595","Policy Violation":"T1071",
    "Command Injection":"T1059","Directory Traversal":"T1083","Cryptojacking":"T1496",
}

def get_mitre_technique(attack_type: str) -> str:
    return _MITRE_MAP.get(attack_type, "T0000")

_TARGET_MAP = {
    "DDoS":["Web Server","DNS Server","API Gateway","Load Balancer"],
    "Brute Force":["SSH Server","RDP Server","Web Application","FTP Server"],
    "Malware Distribution":["Email Server","File Server","Web Server","CDN"],
    "Port Scanning":["Firewall","Network Infrastructure","Router"],
    "SQL Injection":["Database Server","Web Application","API Gateway"],
    "XSS Attack":["Web Application","API Gateway","CMS"],
    "Phishing":["Email Server","End User","Mail Gateway"],
    "Spam":["Email Server","Mail Gateway","SMTP Server"],
    "Reconnaissance":["DNS Server","Web Server","WHOIS Server"],
    "Suspicious Activity":["Network Infrastructure","IDS/IPS"],
    "Policy Violation":["Proxy Server","Web Gateway","Content Filter"],
    "Command Injection":["Web Application","API Gateway","Shell Server"],
    "Directory Traversal":["Web Server","File Server","Application Server"],
    "Cryptojacking":["Web Server","End User","Cloud Instance"],
}

def get_target_system(attack_type: str) -> str:
    return random.choice(_TARGET_MAP.get(attack_type, ["Unknown System"]))
