import { useState, useEffect, useRef, useCallback } from "react";

// ── Config ────────────────────────────────────────────────────
const REFRESH_MS = 2800;

const SEV = {
  Critical: { color: "#ff3b5c", glow: "rgba(255,59,92,0.4)",  bg: "rgba(255,59,92,0.08)",  border: "rgba(255,59,92,0.28)" },
  High:     { color: "#ff8c00", glow: "rgba(255,140,0,0.35)", bg: "rgba(255,140,0,0.08)",  border: "rgba(255,140,0,0.25)" },
  Medium:   { color: "#f5c518", glow: "rgba(245,197,24,0.30)",bg: "rgba(245,197,24,0.07)", border: "rgba(245,197,24,0.22)" },
  Low:      { color: "#00e5a0", glow: "rgba(0,229,160,0.25)", bg: "rgba(0,229,160,0.07)",  border: "rgba(0,229,160,0.20)" },
};

const APIS = [
  { name: "AbuseIPDB",        key: "abuseipdb",        color: "#ff3b5c" },
  { name: "Feodo Tracker",    key: "feodo_tracker",    color: "#ff8c00" },
  { name: "Emerging Threats", key: "emerging_threats", color: "#a855f7" },
  { name: "CINS Score",       key: "cins_score",       color: "#38bdf8" },
  { name: "Spamhaus DROP",    key: "spamhaus_drop",    color: "#00e5a0" },
];

const ATTACK_TYPES = [
  "Brute Force","DDoS","Malware C2","Port Scanning","SQL Injection",
  "Web App Attack","Phishing","Exploited Host","Reconnaissance","Command Injection",
  "IoT Attack","Cryptojacking","Network Hijack","Directory Traversal","XSS Attack",
];

const COUNTRIES = ["RU","CN","US","DE","NL","KR","UA","BR","VN","IN","FR","TR","PK","ID","GB"];
const MITRE     = ["T1110","T1046","T1071","T1498","T1190","T1566","T1592","T1059","T1083","T1204"];
const IPS = Array.from({length: 40}, (_, i) =>
  `${[1,5,45,91,185,194,104,198,23,89,203,103,178,92,139][i%15]}.${(i*17+33)%256}.${(i*31+7)%256}.${(i*13+91)%256}`
);
const THREAT_LOCATIONS = [
  { name: "USA", lat: 37.09, lon: -95.71 },
  { name: "China", lat: 35.86, lon: 104.20 },
  { name: "Russia", lat: 61.52, lon: 105.32 },
  { name: "Germany", lat: 51.17, lon: 10.45 },
  { name: "UK", lat: 55.38, lon: -3.44 },
  { name: "India", lat: 20.59, lon: 78.96 },
  { name: "Brazil", lat: -14.24, lon: -51.93 },
  { name: "Japan", lat: 36.20, lon: 138.25 },
  { name: "France", lat: 46.23, lon: 2.21 },
  { name: "Vietnam", lat: 14.06, lon: 108.28 },
  { name: "South Korea", lat: 35.91, lon: 127.77 },
  { name: "Ukraine", lat: 48.38, lon: 31.17 },
];

const AI_RESPONSES = {
  "sql injection": "SQL Injection exploits vulnerabilities in database queries. Attackers inject malicious SQL statements to bypass authentication or extract data. Use parameterized queries and ORM frameworks to prevent this.",
  "phishing": "Phishing uses deceptive emails or fake websites to steal credentials. Check for HTTPS, verify sender domains, and use MFA. Our URL Scanner can analyze suspicious links in real-time.",
  "ddos": "DDoS attacks overwhelm targets with traffic from multiple sources. Mitigation includes rate limiting, traffic scrubbing, and CDN-based protection. Our threat feed shows active DDoS campaigns.",
  "malware": "Malware encompasses viruses, trojans, ransomware, and spyware. Deploy endpoint protection, keep systems patched, and segment networks to limit lateral movement.",
  "ransomware": "Ransomware encrypts victim data and demands payment. Key defenses: offline backups, network segmentation, user awareness training, and endpoint detection & response (EDR).",
  "firewall": "Firewalls filter traffic based on rules. Next-gen firewalls (NGFW) add deep packet inspection, application awareness, and integrated IPS. Check your open ports in the Network Scanner tab.",
  "vulnerability": "Vulnerabilities are weaknesses that attackers exploit. Regular patching, vulnerability scanning, and penetration testing are critical. Our network scanner identifies open ports and potential exposures.",
  "brute force": "Brute force attacks try all password combinations. Mitigate with account lockouts, CAPTCHA, MFA, and strong password policies. Monitor for repeated authentication failures.",
  "network": "Network security includes firewalls, IDS/IPS, VLANs, and monitoring. Our Network Scanner tab provides real-time device discovery and port analysis for your local network.",
  "zero day": "Zero-day vulnerabilities are unknown to vendors, leaving no patch available. Behavioral detection, threat intelligence feeds, and network segmentation reduce exposure.",
  "threat intelligence": "Threat intelligence aggregates IOCs (Indicators of Compromise), TTPs, and adversary data to proactively defend. Our dashboard integrates AbuseIPDB, Feodo Tracker, and other feeds.",
  "vpn": "VPNs encrypt traffic and mask IP addresses. For enterprise use, consider zero-trust network access (ZTNA) as a more modern, granular alternative.",
  "siem": "SIEM platforms collect and correlate security events from multiple sources, enabling real-time threat detection and forensic investigation.",
};

function rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function seedData() {
  return {
    critical: rnd(120, 180), high: rnd(280, 380), medium: rnd(400, 550), low: rnd(600, 800),
    countries: rnd(18, 32), totalIPs: rnd(1800, 2600),
    activeThreats: rnd(12, 25), blocked: rnd(40, 70), totalScanned: rnd(60, 100),
    networkDevices: rnd(8, 20), vulnerabilities: rnd(2, 8), openPorts: rnd(25, 45),
    bandwidth: rnd(40, 95), latency: rnd(18, 35), packetLoss: (Math.random() * 0.5).toFixed(2),
    apiCounts: {
      abuseipdb: rnd(600, 900), feodo_tracker: rnd(300, 500),
      emerging_threats: rnd(400, 650), cins_score: rnd(200, 400), spamhaus_drop: rnd(150, 320),
    },
    feed: [],
    attackDist: Object.fromEntries(ATTACK_TYPES.map(a => [a, rnd(20, 200)])),
    history: Array.from({length: 30}, (_, i) => ({ t: i, v: rnd(40, 160) })),
    liveThreats: Array.from({length: 8}, () => {
      const loc = pick(THREAT_LOCATIONS);
      return {
        id: Math.random().toString(36).substr(2,8),
        source: loc.name, lat: loc.lat, lon: loc.lon,
        type: pick(ATTACK_TYPES), severity: pick(["Critical","High","Medium","Low"]),
        ip: pick(IPS), ts: new Date(), status: Math.random() > 0.3 ? "Mitigated" : "Active",
      };
    }),
    networkDevicesList: Array.from({length: 6}, (_, i) => ({
      ip: `192.168.1.${[1,101,105,25,200,150][i]}`,
      mac: Array.from({length: 6}, () => Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(':'),
      hostname: ["Router","PC-Office","Unknown","Server-01","NAS","IoT-Hub"][i],
      type: ["Gateway","Desktop","Unknown","Server","Storage","IoT"][i],
      status: ["Online","Online","Suspicious","Online","Online","Online"][i],
    })),
  };
}

function genEvent(prev) {
  const sev = pick(["Critical","Critical","High","High","Medium","Low"]);
  const api = pick(APIS);
  const ip = pick(IPS);
  const country = pick(COUNTRIES);
  const score = sev === "Critical" ? rnd(75,100) : sev === "High" ? rnd(50,74) : sev === "Medium" ? rnd(25,49) : rnd(1,24);
  return {
    id: Date.now() + Math.random(), sev, api: api.name, apiKey: api.key,
    apiColor: api.color, atk: pick(ATTACK_TYPES), ip, country, score,
    mitre: pick(MITRE), ts: new Date(),
  };
}

function useAnimCounter(target, duration = 600) {
  const [value, setValue] = useState(target);
  const prevRef = useRef(target);
  useEffect(() => {
    const from = prevRef.current, to = target;
    if (from === to) return;
    const startTime = performance.now();
    const step = (now) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(from + (to - from) * ease));
      if (progress < 1) requestAnimationFrame(step);
      else prevRef.current = to;
    };
    requestAnimationFrame(step);
  }, [target]);
  return value;
}

// ── Sparkline ─────────────────────────────────────────────────
function Sparkline({ data, color }) {
  const w = 100, h = 32;
  const max = Math.max(...data.map(d => d.v), 1);
  const pts = data.map((d, i) => [(i / (data.length - 1)) * w, h - (d.v / max) * (h - 4) - 2]);
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const fill = [...pts, [w, h], [0, h]].map((p, i) =>
    `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} style={{ overflow: "visible", opacity: 0.8 }}>
      <defs>
        <linearGradient id={`sg${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={fill + " Z"} fill={`url(#sg${color.replace("#","")})`} />
      <path d={path} stroke={color} strokeWidth="1.5" fill="none" strokeLinejoin="round" />
    </svg>
  );
}

// ── Pulse Dot ─────────────────────────────────────────────────
function PulseDot({ color = "#00e5a0" }) {
  return (
    <div style={{ position: "relative", width: 10, height: 10, display: "inline-block" }}>
      <div style={{
        position: "absolute", inset: 0, borderRadius: "50%",
        background: color, animation: "socPulse 1.6s ease-in-out infinite",
      }} />
      <div style={{ position: "absolute", inset: 2, borderRadius: "50%", background: color }} />
      <style>{`@keyframes socPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.3;transform:scale(2)}}`}</style>
    </div>
  );
}

// ── Panel Shell ───────────────────────────────────────────────
function Panel({ title, badge, children, style = {} }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.025)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 14, overflow: "hidden", ...style
    }}>
      {title && (
        <div style={{
          display: "flex", alignItems: "center", gap: 10, justifyContent: "space-between",
          padding: "12px 16px", borderBottom: "1px solid rgba(255,255,255,0.06)",
          background: "rgba(0,0,0,0.25)",
        }}>
          <span style={{ fontSize: 10, color: "#4b6077", letterSpacing: "0.14em", textTransform: "uppercase", fontFamily: "monospace" }}>
            {title}
          </span>
          {badge && <span style={{ fontSize: 9, background: "rgba(255,59,92,0.12)", border: "1px solid rgba(255,59,92,0.3)", color: "#ff3b5c", borderRadius: 5, padding: "2px 8px", fontFamily: "monospace" }}>{badge}</span>}
        </div>
      )}
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}

// ── KPI Card ──────────────────────────────────────────────────
function KpiCard({ label, value, delta, color, glow, bg, border, sparkData, icon }) {
  const animated = useAnimCounter(value);
  const isUp = delta > 0;
  return (
    <div style={{
      flex: 1, minWidth: 160,
      background: bg, border: `1px solid ${border}`,
      borderTop: `2px solid ${color}`, borderRadius: 12,
      padding: "16px 18px", position: "relative", overflow: "hidden",
      boxShadow: `0 4px 24px ${glow}`,
    }}>
      <div style={{ fontSize: 9, color: "#3d5166", letterSpacing: "0.14em", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 8 }}>{label}</div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 12, justifyContent: "space-between" }}>
        <div>
          <div style={{ fontSize: 30, fontWeight: 800, color, fontFamily: "'Courier New', monospace", lineHeight: 1 }}>
            {animated.toLocaleString()}
          </div>
          <div style={{ fontSize: 9, color: isUp ? "#ff3b5c" : "#00e5a0", fontFamily: "monospace", marginTop: 4 }}>
            {isUp ? "▲" : "▼"} {Math.abs(delta)} since last cycle
          </div>
        </div>
        {sparkData && <Sparkline data={sparkData} color={color} />}
      </div>
    </div>
  );
}

// ── Severity Ring ─────────────────────────────────────────────
function SevRing({ counts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const sevKeys = ["Critical","High","Medium","Low"];
  let offset = 0;
  const r = 54, cx = 64, cy = 64, circumference = 2 * Math.PI * r;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <div style={{ position: "relative", width: 128, height: 128 }}>
        <svg width="128" height="128">
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="14" />
          {sevKeys.map(sev => {
            const pct = counts[sev] / total;
            const dashLen = pct * circumference;
            const el = (
              <circle key={sev} cx={cx} cy={cy} r={r} fill="none"
                stroke={SEV[sev].color} strokeWidth="14"
                strokeDasharray={`${dashLen} ${circumference - dashLen}`}
                strokeDashoffset={-offset * circumference}
                strokeLinecap="butt"
                style={{ transition: "all 0.8s cubic-bezier(0.22,1,0.36,1)", filter: `drop-shadow(0 0 5px ${SEV[sev].color}88)` }}
                transform={`rotate(-90 ${cx} ${cy})`}
              />
            );
            offset += pct; return el;
          })}
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: "#e2e8f0", fontFamily: "monospace", lineHeight: 1 }}>{total.toLocaleString()}</div>
          <div style={{ fontSize: 8, color: "#3d5166", fontFamily: "monospace", letterSpacing: "0.1em", textTransform: "uppercase" }}>total</div>
        </div>
      </div>
      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 20px", width: "100%" }}>
        {sevKeys.map(sev => (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: SEV[sev].color, fontSize: 8 }}>●</span>
            <span style={{ color: "#475569", fontSize: 9, fontFamily: "monospace" }}>{sev}</span>
            <span style={{ color: SEV[sev].color, fontSize: 9, fontFamily: "monospace", fontWeight: 700, marginLeft: "auto" }}>
              {Math.round((counts[sev] / total) * 100)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Live Feed Row ─────────────────────────────────────────────
function FeedRow({ evt, fresh }) {
  const sev = SEV[evt.sev];
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "88px 70px 1fr 110px 60px 80px",
      gap: 8, padding: "7px 16px", borderBottom: "1px solid rgba(255,255,255,0.035)",
      alignItems: "center", fontSize: 10, fontFamily: "monospace",
      background: fresh ? sev.bg : "transparent", transition: "background 1.2s ease",
    }}>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 5, background: sev.bg, border: `1px solid ${sev.border}`, borderRadius: 5, padding: "2px 7px", width: "fit-content" }}>
        <span style={{ color: sev.color, fontSize: 7 }}>●</span>
        <span style={{ color: sev.color, fontWeight: 700, fontSize: 9 }}>{evt.sev}</span>
      </div>
      <div style={{ color: "#7c3aed", fontSize: 9 }}>{evt.score}/100</div>
      <div style={{ color: "#cbd5e1" }}>{evt.ip}</div>
      <div style={{ color: "#4b6077" }}>{evt.atk}</div>
      <div style={{ color: "#374151" }}>{evt.country}</div>
      <div style={{ color: evt.apiColor, fontSize: 9 }}>{evt.api.split(" ")[0]}</div>
    </div>
  );
}

// ── API Source Panel ──────────────────────────────────────────
function ApiSourcePanel({ apiCounts, sevBySrc }) {
  const total = Object.values(apiCounts).reduce((a, b) => a + b, 0) || 1;
  return (
    <>
      {APIS.map(api => {
        const count = apiCounts[api.key] || 0;
        const pct = Math.round((count / total) * 100);
        const sevs = sevBySrc?.[api.key] || {};
        return (
          <div key={api.key} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: api.color, display: "inline-block" }} />
                <span style={{ color: "#94a3b8", fontSize: 10, fontFamily: "monospace" }}>{api.name}</span>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {Object.entries(sevs).map(([sev, c]) => (
                  <span key={sev} style={{ fontSize: 8, color: SEV[sev]?.color, fontFamily: "monospace" }}>{sev.slice(0,4)}:{c}</span>
                ))}
                <span style={{ color: api.color, fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{count.toLocaleString()}</span>
              </div>
            </div>
            <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${pct}%`, borderRadius: 2, background: `linear-gradient(90deg,${api.color},${api.color}66)`, transition: "width 0.8s cubic-bezier(0.22,1,0.36,1)", boxShadow: `0 0 8px ${api.color}55` }} />
            </div>
          </div>
        );
      })}
    </>
  );
}

// ── Attack Distribution ───────────────────────────────────────
function AttackDist({ data }) {
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = sorted[0]?.[1] || 1;
  const colors = ["#ff3b5c","#ff8c00","#f5c518","#00e5a0","#38bdf8","#a855f7","#ec4899","#f43f5e"];
  return (
    <>
      {sorted.map(([atk, cnt], i) => (
        <div key={atk} style={{ marginBottom: 9 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
            <span style={{ color: "#4b6077", fontSize: 10, fontFamily: "monospace" }}>{atk}</span>
            <span style={{ color: colors[i], fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{cnt}</span>
          </div>
          <div style={{ height: 3, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${(cnt / max) * 100}%`, borderRadius: 2, background: colors[i], transition: "width 0.7s cubic-bezier(0.22,1,0.36,1)" }} />
          </div>
        </div>
      ))}
    </>
  );
}

// ── Threat Map (SVG World) ─────────────────────────────────────
function ThreatMap({ liveThreats }) {
  // Simplified world map dots representing attack origins
  const mapW = 600, mapH = 280;
  const toXY = (lat, lon) => [
    ((lon + 180) / 360) * mapW,
    ((90 - lat) / 180) * mapH,
  ];
  return (
    <div style={{ position: "relative", overflow: "hidden", borderRadius: 8, background: "rgba(0,0,0,0.3)" }}>
      <svg width="100%" viewBox={`0 0 ${mapW} ${mapH}`} style={{ display: "block" }}>
        {/* Background grid */}
        {Array.from({length: 12}, (_, i) => (
          <line key={`v${i}`} x1={(i/11)*mapW} y1="0" x2={(i/11)*mapW} y2={mapH} stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
        ))}
        {Array.from({length: 6}, (_, i) => (
          <line key={`h${i}`} x1="0" y1={(i/5)*mapH} x2={mapW} y2={(i/5)*mapH} stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
        ))}
        {/* Target (London) */}
        {(() => {
          const [tx, ty] = toXY(51.5, -0.13);
          return (
            <g key="target">
              <circle cx={tx} cy={ty} r="10" fill="none" stroke="#00e5a0" strokeWidth="1" opacity="0.4">
                <animate attributeName="r" from="6" to="18" dur="2s" repeatCount="indefinite"/>
                <animate attributeName="opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite"/>
              </circle>
              <circle cx={tx} cy={ty} r="5" fill="rgba(0,229,160,0.3)" stroke="#00e5a0" strokeWidth="1.5"/>
              <text x={tx+8} y={ty-4} fill="#00e5a0" fontSize="8" fontFamily="monospace">TARGET</text>
            </g>
          );
        })()}
        {/* Attack lines + source dots */}
        {liveThreats.slice(0, 12).map(t => {
          const [x, y] = toXY(t.lat, t.lon);
          const [tx, ty] = toXY(51.5, -0.13);
          const col = SEV[t.severity]?.color || "#ff3b5c";
          return (
            <g key={t.id}>
              <line x1={x} y1={y} x2={tx} y2={ty} stroke={col} strokeWidth="0.8" opacity="0.25" strokeDasharray="3 3"/>
              <circle cx={x} cy={y} r="4" fill={col} opacity="0.7">
                <animate attributeName="opacity" from="0.7" to="0.2" dur={`${1 + Math.random()}s`} repeatCount="indefinite" direction="alternate"/>
              </circle>
              <text x={x+6} y={y+4} fill={col} fontSize="7" fontFamily="monospace" opacity="0.7">{t.source.split(" ")[0]}</text>
            </g>
          );
        })}
      </svg>
      <div style={{ position: "absolute", top: 8, right: 8, fontSize: 9, fontFamily: "monospace", color: "#4b6077" }}>
        {liveThreats.length} active sources
      </div>
    </div>
  );
}

// ── Analytics Charts ──────────────────────────────────────────
function AnalyticsTab({ data }) {
  // Bandwidth sparkline large
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <Panel title="Bandwidth History (Mbps)" style={{ gridColumn: "1/-1" }}>
        <svg width="100%" height={80} viewBox="0 0 600 80" preserveAspectRatio="none">
          {data.history.map((d, i) => {
            const x = (i / (data.history.length - 1)) * 600;
            const prev = data.history[i - 1];
            if (!prev) return null;
            const px = ((i-1)/(data.history.length-1))*600;
            return <line key={i} x1={px} y1={80-(prev.v/160)*76} x2={x} y2={80-(d.v/160)*76} stroke="#38bdf8" strokeWidth="2"/>;
          })}
        </svg>
      </Panel>
      <Panel title="Threat Timeline">
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {["Critical","High","Medium","Low"].map(sev => (
            <div key={sev}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ color: SEV[sev].color, fontSize: 10, fontFamily: "monospace" }}>{sev}</span>
                <span style={{ color: SEV[sev].color, fontFamily: "monospace", fontSize: 10 }}>{data[sev.toLowerCase()].toLocaleString()}</span>
              </div>
              <div style={{ height: 6, background: "rgba(255,255,255,0.05)", borderRadius: 3 }}>
                <div style={{ height: "100%", borderRadius: 3, background: SEV[sev].color, width: `${(data[sev.toLowerCase()] / data.low) * 100}%`, transition: "width 0.8s" }} />
              </div>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Top Attack Sources">
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {APIS.map((api, i) => (
            <div key={api.key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ color: api.color, fontSize: 10, fontFamily: "monospace", minWidth: 130 }}>{api.name}</span>
              <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
                <div style={{ height: "100%", borderRadius: 2, background: api.color, width: `${(data.apiCounts[api.key] / 900) * 100}%` }} />
              </div>
              <span style={{ color: api.color, fontFamily: "monospace", fontSize: 10, minWidth: 50, textAlign: "right" }}>{data.apiCounts[api.key].toLocaleString()}</span>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Security Score">
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
          {(() => {
            const score = Math.max(10, 100 - Math.round((data.critical / (data.critical + data.high + data.medium + data.low)) * 100 * 2));
            const col = score > 70 ? "#00e5a0" : score > 45 ? "#f5c518" : "#ff3b5c";
            return (
              <>
                <div style={{ fontSize: 64, fontWeight: 900, color: col, fontFamily: "monospace", lineHeight: 1, textShadow: `0 0 30px ${col}66` }}>{score}</div>
                <div style={{ fontSize: 10, color: col, fontFamily: "monospace", letterSpacing: "0.1em" }}>SECURITY SCORE</div>
                <div style={{ display: "flex", gap: 20 }}>
                  {[["Latency", `${data.latency}ms`], ["Pkt Loss", `${data.packetLoss}%`], ["Bandwidth", `${data.bandwidth}Mb`]].map(([k, v]) => (
                    <div key={k} style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 14, color: "#cbd5e1", fontFamily: "monospace" }}>{v}</div>
                      <div style={{ fontSize: 8, color: "#3d5166", letterSpacing: "0.1em" }}>{k}</div>
                    </div>
                  ))}
                </div>
              </>
            );
          })()}
        </div>
      </Panel>
    </div>
  );
}

// ── AI Assistant ──────────────────────────────────────────────
function AIAssistant() {
  const [messages, setMessages] = useState([
    { from: "ai", text: "CyberShield AI online. Ask me about threats, attack types, security concepts, or dashboard features." }
  ]);
  const [input, setInput] = useState("");
  const bottomRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const send = () => {
    if (!input.trim()) return;
    const userMsg = input.trim();
    setMessages(m => [...m, { from: "user", text: userMsg }]);
    setInput("");
    setTimeout(() => {
      let response = "I understand your question about cybersecurity. This dashboard monitors real-time threat intelligence from 5 global feeds. For specific topics, try asking about: phishing, DDoS, malware, ransomware, SQL injection, or network security.";
      const q = userMsg.toLowerCase();
      for (const [key, resp] of Object.entries(AI_RESPONSES)) {
        if (q.includes(key)) { response = resp; break; }
      }
      setMessages(m => [...m, { from: "ai", text: response }]);
    }, 600);
  };

  return (
    <Panel title="AI Security Assistant" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ flex: 1, overflowY: "auto", maxHeight: 360, display: "flex", flexDirection: "column", gap: 10 }}>
        {messages.map((msg, i) => (
          <div key={i} style={{
            display: "flex", justifyContent: msg.from === "user" ? "flex-end" : "flex-start",
          }}>
            <div style={{
              maxWidth: "80%", padding: "10px 14px", borderRadius: msg.from === "user" ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
              background: msg.from === "user" ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.05)",
              border: `1px solid ${msg.from === "user" ? "rgba(56,189,248,0.25)" : "rgba(255,255,255,0.08)"}`,
              color: msg.from === "user" ? "#38bdf8" : "#94a3b8",
              fontSize: 11, fontFamily: "monospace", lineHeight: 1.6,
            }}>
              {msg.from === "ai" && <div style={{ color: "#00e5a0", fontSize: 9, marginBottom: 4, letterSpacing: "0.1em" }}>◈ CYBERSHIELD AI</div>}
              {msg.text}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && send()}
          placeholder="Ask about threats, security, or network…"
          style={{
            flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, padding: "9px 14px", color: "#94a3b8", fontSize: 11,
            fontFamily: "monospace", outline: "none",
          }}
        />
        <button onClick={send} style={{
          background: "rgba(0,229,160,0.15)", border: "1px solid rgba(0,229,160,0.3)",
          borderRadius: 8, color: "#00e5a0", padding: "9px 18px", cursor: "pointer",
          fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em",
        }}>SEND</button>
      </div>
    </Panel>
  );
}

// ── URL Scanner ───────────────────────────────────────────────
function URLScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const maliciousKw = ["malware","phish","hack","exploit","botnet","c2","trojan","ransomware","xss","inject"];
  const safeDomains = ["google.com","github.com","amazon.com","microsoft.com","cloudflare.com","wikipedia.org"];

  const scan = () => {
    if (!url.trim()) return;
    setScanning(true);
    setResult(null);
    setTimeout(() => {
      const u = url.toLowerCase();
      let isSafe = true, score = rnd(5, 30);
      for (const kw of maliciousKw) { if (u.includes(kw)) { isSafe = false; score = rnd(70, 98); break; } }
      if (isSafe) {
        for (const d of safeDomains) { if (u.includes(d)) { isSafe = true; score = rnd(2, 18); break; } }
        if (score > 30 && Math.random() > 0.55) { isSafe = false; score = rnd(60, 85); }
      }
      setResult({
        url, isSafe, score,
        ssl: isSafe || Math.random() > 0.4,
        phishing: !isSafe && Math.random() > 0.5,
        malware: !isSafe && Math.random() > 0.6,
        reputation: isSafe ? "Clean" : score > 80 ? "Malicious" : "Suspicious",
        category: isSafe ? pick(["News","Technology","Business","Education"]) : pick(["Phishing","Malware","C2","Exploit"]),
      });
      setScanning(false);
    }, 1400);
  };

  const col = result ? (result.score < 30 ? "#00e5a0" : result.score < 60 ? "#f5c518" : "#ff3b5c") : "#38bdf8";

  return (
    <Panel title="URL & Link Safety Scanner">
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <input
          value={url} onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === "Enter" && scan()}
          placeholder="https://example.com"
          style={{
            flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, padding: "10px 14px", color: "#94a3b8",
            fontSize: 11, fontFamily: "monospace", outline: "none",
          }}
        />
        <button onClick={scan} disabled={scanning} style={{
          background: scanning ? "rgba(56,189,248,0.08)" : "rgba(56,189,248,0.15)",
          border: "1px solid rgba(56,189,248,0.3)", borderRadius: 8,
          color: "#38bdf8", padding: "10px 22px", cursor: "pointer",
          fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em",
        }}>{scanning ? "SCANNING…" : "SCAN URL"}</button>
      </div>
      {result && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={{ gridColumn: "1/-1", background: result.isSafe ? "rgba(0,229,160,0.07)" : "rgba(255,59,92,0.07)", border: `1px solid ${col}33`, borderRadius: 10, padding: "16px 20px", display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ fontSize: 32, color: col }}>{result.isSafe ? "✓" : "✗"}</div>
            <div>
              <div style={{ fontSize: 14, color: col, fontFamily: "monospace", fontWeight: 700 }}>{result.isSafe ? "URL APPEARS SAFE" : "THREAT DETECTED"}</div>
              <div style={{ fontSize: 10, color: "#4b6077", fontFamily: "monospace" }}>Risk Score: {result.score}/100 · Category: {result.category}</div>
            </div>
          </div>
          {[
            ["SSL Certificate", result.ssl ? "Valid" : "Invalid/Missing", result.ssl ? "#00e5a0" : "#ff3b5c"],
            ["Reputation", result.reputation, col],
            ["Phishing", result.phishing ? "Detected" : "Not Detected", result.phishing ? "#ff3b5c" : "#00e5a0"],
            ["Malware", result.malware ? "Detected" : "Not Detected", result.malware ? "#ff3b5c" : "#00e5a0"],
          ].map(([label, value, c]) => (
            <div key={label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 8, padding: "12px 14px" }}>
              <div style={{ fontSize: 9, color: "#3d5166", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "monospace" }}>{label}</div>
              <div style={{ fontSize: 13, color: c, fontFamily: "monospace", fontWeight: 700, marginTop: 4 }}>{value}</div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// ── Threat History ─────────────────────────────────────────────
function ThreatHistory({ threats }) {
  const [filter, setFilter] = useState("All");
  const filtered = filter === "All" ? threats : threats.filter(t => t.sev === filter);
  return (
    <Panel title="Threat History" badge={`${filtered.length} records`}>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["All","Critical","High","Medium","Low"].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            background: filter === f ? (f === "All" ? "rgba(56,189,248,0.15)" : SEV[f]?.bg || "rgba(56,189,248,0.15)") : "rgba(255,255,255,0.03)",
            border: `1px solid ${filter === f ? (f === "All" ? "rgba(56,189,248,0.3)" : SEV[f]?.border || "rgba(56,189,248,0.3)") : "rgba(255,255,255,0.07)"}`,
            color: filter === f ? (f === "All" ? "#38bdf8" : SEV[f]?.color || "#38bdf8") : "#4b6077",
            borderRadius: 6, padding: "4px 12px", cursor: "pointer",
            fontSize: 9, fontFamily: "monospace", letterSpacing: "0.1em",
          }}>{f}</button>
        ))}
      </div>
      <div style={{ maxHeight: 360, overflowY: "auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "80px 60px 1fr 110px 60px 90px", gap: 8, padding: "6px 10px", borderBottom: "1px solid rgba(255,255,255,0.06)", fontSize: 8, color: "#1e3a4a", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "monospace" }}>
          <div>Severity</div><div>Score</div><div>IP Address</div><div>Attack Type</div><div>Country</div><div>MITRE ATT&CK</div>
        </div>
        {filtered.slice(0, 50).map(evt => {
          const sev = SEV[evt.sev];
          return (
            <div key={evt.id} style={{ display: "grid", gridTemplateColumns: "80px 60px 1fr 110px 60px 90px", gap: 8, padding: "6px 10px", borderBottom: "1px solid rgba(255,255,255,0.03)", alignItems: "center", fontSize: 10, fontFamily: "monospace" }}>
              <span style={{ color: sev.color, fontSize: 9 }}>{evt.sev}</span>
              <span style={{ color: "#7c3aed" }}>{evt.score}</span>
              <span style={{ color: "#94a3b8" }}>{evt.ip}</span>
              <span style={{ color: "#4b6077" }}>{evt.atk}</span>
              <span style={{ color: "#374151" }}>{evt.country}</span>
              <span style={{ color: "#3d5166" }}>{evt.mitre}</span>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ── Database Manager ──────────────────────────────────────────
function DatabaseManager({ data }) {
  const [connected, setConnected] = useState(false);
  const [query, setQuery] = useState("SELECT * FROM threats LIMIT 10;");
  const [queryResult, setQueryResult] = useState(null);

  const toggleConnect = () => setConnected(c => !c);
  const runQuery = () => {
    setQueryResult({
      columns: ["id","ip","severity","attack_type","country","score","timestamp"],
      rows: Array.from({length: 5}, (_, i) => [
        `threat_${1000+i}`, pick(IPS), pick(["Critical","High","Medium","Low"]),
        pick(ATTACK_TYPES), pick(COUNTRIES), rnd(1,100),
        new Date(Date.now() - i * 60000).toLocaleTimeString()
      ]),
    });
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 16 }}>
      <Panel title="Database Connection">
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {[["Database", "threats.db"], ["Engine", "SQLite WAL"], ["Total IPs", data.totalIPs.toLocaleString()], ["Records", ((data.critical + data.high + data.medium + data.low)).toLocaleString()], ["Countries", data.countries]].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: 8 }}>
              <span style={{ fontSize: 10, color: "#3d5166", fontFamily: "monospace" }}>{k}</span>
              <span style={{ fontSize: 10, color: "#00e5a0", fontFamily: "monospace" }}>{v}</span>
            </div>
          ))}
          <button onClick={toggleConnect} style={{
            background: connected ? "rgba(255,59,92,0.1)" : "rgba(0,229,160,0.1)",
            border: `1px solid ${connected ? "rgba(255,59,92,0.3)" : "rgba(0,229,160,0.3)"}`,
            color: connected ? "#ff3b5c" : "#00e5a0",
            borderRadius: 8, padding: "10px", cursor: "pointer",
            fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em", width: "100%",
          }}>{connected ? "● DISCONNECT" : "○ CONNECT DB"}</button>
        </div>
      </Panel>
      <Panel title="SQL Query Runner">
        <textarea
          value={query} onChange={e => setQuery(e.target.value)}
          style={{
            width: "100%", height: 80, background: "rgba(0,0,0,0.3)",
            border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8,
            color: "#38bdf8", fontSize: 11, fontFamily: "monospace",
            padding: "10px 12px", resize: "vertical", outline: "none", boxSizing: "border-box",
          }}
        />
        <button onClick={runQuery} style={{
          background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.25)",
          borderRadius: 7, color: "#38bdf8", padding: "8px 20px", cursor: "pointer",
          fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em", marginTop: 8,
        }}>▶ RUN QUERY</button>
        {queryResult && (
          <div style={{ marginTop: 12, overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 9, fontFamily: "monospace" }}>
              <thead>
                <tr>{queryResult.columns.map(c => <th key={c} style={{ color: "#00e5a0", padding: "4px 8px", textAlign: "left", borderBottom: "1px solid rgba(0,229,160,0.2)" }}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {queryResult.rows.map((row, i) => (
                  <tr key={i} style={{ background: i % 2 ? "rgba(255,255,255,0.02)" : "transparent" }}>
                    {row.map((cell, j) => <td key={j} style={{ color: "#4b6077", padding: "4px 8px", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>{cell}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

// ── Export Data ───────────────────────────────────────────────
function ExportData({ feed, data }) {
  const exportCSV = (name, rows) => {
    const csv = rows.map(r => Object.values(r).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${name}_${Date.now()}.csv`;
    a.click();
  };

  return (
    <Panel title="Data Export">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        {[
          { label: "Threat Feed", desc: `${feed.length} events`, onClick: () => exportCSV("threats", feed.map(e => ({ id: e.id, sev: e.sev, ip: e.ip, atk: e.atk, country: e.country, score: e.score, mitre: e.mitre }))) },
          { label: "API Summary", desc: "Per-source counts", onClick: () => exportCSV("api_summary", APIS.map(a => ({ api: a.name, count: data.apiCounts[a.key] }))) },
          { label: "Attack Distribution", desc: "Type breakdown", onClick: () => exportCSV("attacks", Object.entries(data.attackDist).map(([atk, cnt]) => ({ attack: atk, count: cnt }))) },
        ].map(({ label, desc, onClick }) => (
          <div key={label} onClick={onClick} style={{
            background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 10, padding: "16px 18px", cursor: "pointer",
            transition: "all 0.2s",
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = "rgba(0,229,160,0.3)"}
            onMouseLeave={e => e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)"}
          >
            <div style={{ fontSize: 20, marginBottom: 8 }}>⬇</div>
            <div style={{ fontSize: 11, color: "#cbd5e1", fontFamily: "monospace", fontWeight: 700 }}>{label}</div>
            <div style={{ fontSize: 9, color: "#3d5166", fontFamily: "monospace", marginTop: 4 }}>{desc} · CSV format</div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 16, padding: "12px 16px", background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 8 }}>
        <div style={{ fontSize: 9, color: "#00e5a0", fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 6 }}>EXPORT SUMMARY</div>
        <div style={{ display: "flex", gap: 24 }}>
          {[["Total IPs", data.totalIPs.toLocaleString()], ["Countries", data.countries], ["Feed Events", feed.length], ["Total Threats", (data.critical+data.high+data.medium+data.low).toLocaleString()]].map(([k, v]) => (
            <div key={k}>
              <div style={{ fontSize: 16, color: "#00e5a0", fontFamily: "monospace", fontWeight: 700 }}>{v}</div>
              <div style={{ fontSize: 8, color: "#3d5166", letterSpacing: "0.1em" }}>{k}</div>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

// ── Barcode Scanner ───────────────────────────────────────────
function BarcodeScanner() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const scan = () => {
    if (!input.trim()) return;
    setScanning(true);
    setTimeout(() => {
      const isMalicious = Math.random() > 0.6;
      setResult({
        barcode: input,
        type: pick(["QR Code","Code 128","EAN-13","UPC-A","DataMatrix"]),
        content: input.includes("http") ? input : `Product ID: ${input.toUpperCase()}`,
        safe: !isMalicious,
        threat: isMalicious ? pick(["Phishing URL","Malicious Redirect","Counterfeit Product","Suspicious Domain"]) : "None detected",
        vendor: pick(["Amazon","Unknown","eBay","Alibaba","Internal"]),
        riskScore: isMalicious ? rnd(60,95) : rnd(2,25),
      });
      setScanning(false);
    }, 1000);
  };

  return (
    <Panel title="Barcode & QR Code Scanner">
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <input
          value={input} onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && scan()}
          placeholder="Enter barcode value or URL from QR code…"
          style={{
            flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, padding: "10px 14px", color: "#94a3b8",
            fontSize: 11, fontFamily: "monospace", outline: "none",
          }}
        />
        <button onClick={scan} disabled={scanning} style={{
          background: "rgba(168,85,247,0.15)", border: "1px solid rgba(168,85,247,0.3)",
          borderRadius: 8, color: "#a855f7", padding: "10px 22px", cursor: "pointer",
          fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em",
        }}>{scanning ? "SCANNING…" : "⌗ SCAN"}</button>
      </div>
      <div style={{ padding: "20px", border: "2px dashed rgba(168,85,247,0.2)", borderRadius: 10, textAlign: "center", marginBottom: 16, color: "#3d5166", fontSize: 10, fontFamily: "monospace" }}>
        ⌗ Paste barcode value or scan QR content above
      </div>
      {result && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={{ gridColumn: "1/-1", background: result.safe ? "rgba(0,229,160,0.07)" : "rgba(255,59,92,0.07)", border: `1px solid ${result.safe ? "rgba(0,229,160,0.3)" : "rgba(255,59,92,0.3)"}`, borderRadius: 10, padding: "14px 18px" }}>
            <div style={{ fontSize: 12, color: result.safe ? "#00e5a0" : "#ff3b5c", fontFamily: "monospace", fontWeight: 700 }}>{result.safe ? "✓ NO THREAT DETECTED" : "⚠ THREAT DETECTED"}</div>
            <div style={{ fontSize: 10, color: "#4b6077", fontFamily: "monospace", marginTop: 4 }}>Risk Score: {result.riskScore}/100 · Type: {result.type} · Threat: {result.threat}</div>
          </div>
          {[["Content", result.content], ["Barcode Type", result.type], ["Vendor", result.vendor], ["Safe", result.safe ? "Yes" : "No"]].map(([k, v]) => (
            <div key={k} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 8, padding: "10px 14px" }}>
              <div style={{ fontSize: 9, color: "#3d5166", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "monospace" }}>{k}</div>
              <div style={{ fontSize: 12, color: "#94a3b8", fontFamily: "monospace", marginTop: 4 }}>{v}</div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// ── Network Scanner ───────────────────────────────────────────
function NetworkScanner({ data }) {
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState(data.networkDevicesList);

  const runScan = () => {
    setScanning(true);
    setTimeout(() => {
      setDevices(d => d.map(dev => ({
        ...dev,
        status: Math.random() > 0.85 ? "Suspicious" : "Online",
      })));
      setScanning(false);
    }, 2000);
  };

  const statusCol = s => s === "Online" ? "#00e5a0" : s === "Suspicious" ? "#f5c518" : "#ff3b5c";

  return (
    <Panel title="IP & Network Scanner">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 20 }}>
        {[["Total Devices", data.networkDevices, "#38bdf8"], ["Vulnerabilities", data.vulnerabilities, "#ff3b5c"], ["Open Ports", data.openPorts, "#f5c518"], ["Bandwidth", `${data.bandwidth}Mb`, "#00e5a0"]].map(([k, v, c]) => (
          <div key={k} style={{ background: "rgba(255,255,255,0.03)", border: `1px solid ${c}22`, borderRadius: 8, padding: "12px 14px", textAlign: "center" }}>
            <div style={{ fontSize: 22, color: c, fontFamily: "monospace", fontWeight: 800 }}>{v}</div>
            <div style={{ fontSize: 8, color: "#3d5166", letterSpacing: "0.1em", marginTop: 4 }}>{k}</div>
          </div>
        ))}
      </div>
      <button onClick={runScan} disabled={scanning} style={{
        background: scanning ? "rgba(56,189,248,0.05)" : "rgba(56,189,248,0.12)",
        border: "1px solid rgba(56,189,248,0.25)", borderRadius: 8,
        color: scanning ? "#3d5166" : "#38bdf8", padding: "10px 24px",
        cursor: scanning ? "not-allowed" : "pointer",
        fontSize: 10, fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 16,
        animation: scanning ? "scanPulse 1s infinite" : "none",
      }}>
        {scanning ? "◌ SCANNING NETWORK…" : "▶ START NETWORK SCAN"}
      </button>
      <style>{`@keyframes scanPulse{0%,100%{opacity:1}50%{opacity:0.4}}`}</style>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10, fontFamily: "monospace" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(56,189,248,0.2)" }}>
              {["IP Address","MAC","Hostname","Type","Status"].map(h => (
                <th key={h} style={{ color: "#38bdf8", padding: "6px 12px", textAlign: "left", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {devices.map((dev, i) => (
              <tr key={i} style={{ background: i % 2 ? "rgba(255,255,255,0.015)" : "transparent", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                <td style={{ padding: "8px 12px", color: "#38bdf8" }}>{dev.ip}</td>
                <td style={{ padding: "8px 12px", color: "#4b6077" }}>{dev.mac}</td>
                <td style={{ padding: "8px 12px", color: "#94a3b8" }}>{dev.hostname}</td>
                <td style={{ padding: "8px 12px", color: "#4b6077" }}>{dev.type}</td>
                <td style={{ padding: "8px 12px" }}>
                  <span style={{ color: statusCol(dev.status), fontSize: 9, background: `${statusCol(dev.status)}15`, border: `1px solid ${statusCol(dev.status)}33`, borderRadius: 4, padding: "2px 8px" }}>{dev.status.toUpperCase()}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

// ── Navigation ────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: "dashboard",  label: "Dashboard",       icon: "◈" },
  { id: "threatmap",  label: "Threat Map",       icon: "◎" },
  { id: "analytics",  label: "Analytics",        icon: "▦" },
  { id: "ai",         label: "AI Assistant",     icon: "◆" },
  { id: "urlscan",    label: "URL Scanner",      icon: "◉" },
  { id: "history",    label: "Threat History",   icon: "▤" },
  { id: "database",   label: "Database",         icon: "▣" },
  { id: "export",     label: "Export Data",      icon: "⬇" },
  { id: "barcode",    label: "Barcode Scanner",  icon: "⌗" },
  { id: "network",    label: "Network Scanner",  icon: "◐" },
];

// ── MAIN DASHBOARD ────────────────────────────────────────────
export default function SOCDashboard() {
  const [data, setData] = useState(() => seedData());
  const [feed, setFeed] = useState([]);
  const [prev, setPrev] = useState(null);
  const [tick, setTick] = useState(0);
  const [freshIds, setFreshIds] = useState(new Set());
  const [activeTab, setActiveTab] = useState("dashboard");
  const feedRef = useRef([]);

  const update = useCallback(() => {
    setData(old => {
      setPrev({ critical: old.critical, high: old.high, medium: old.medium, low: old.low });
      const newEvts = Array.from({ length: rnd(1, 4) }, () => genEvent(old));
      const newFreshIds = new Set(newEvts.map(e => e.id));
      setFreshIds(newFreshIds);
      setTimeout(() => setFreshIds(new Set()), 1400);
      feedRef.current = [...newEvts, ...feedRef.current].slice(0, 80);
      setFeed([...feedRef.current]);

      const delta = { critical: 0, high: 0, medium: 0, low: 0 };
      newEvts.forEach(e => { delta[e.sev.toLowerCase()] = (delta[e.sev.toLowerCase()] || 0) + 1; });
      const newApiCounts = { ...old.apiCounts };
      newEvts.forEach(e => { if (newApiCounts[e.apiKey] !== undefined) newApiCounts[e.apiKey]++; });
      const newAttackDist = { ...old.attackDist };
      newEvts.forEach(e => { newAttackDist[e.atk] = (newAttackDist[e.atk] || 0) + 1; });
      const newHistory = [...old.history.slice(1), { t: old.history.length, v: old.critical + delta.critical }];

      // Occasionally add new live threat
      const newLiveThreats = [...old.liveThreats];
      if (Math.random() < 0.6) {
        const loc = pick(THREAT_LOCATIONS);
        newLiveThreats.unshift({ id: Math.random().toString(36).substr(2,8), source: loc.name, lat: loc.lat + (Math.random()-.5)*2, lon: loc.lon + (Math.random()-.5)*2, type: pick(ATTACK_TYPES), severity: pick(["Critical","High","Medium","Low"]), ip: pick(IPS), ts: new Date(), status: Math.random() > 0.3 ? "Mitigated" : "Active" });
        if (newLiveThreats.length > 20) newLiveThreats.pop();
      }

      return {
        ...old, critical: old.critical + delta.critical, high: old.high + delta.high,
        medium: old.medium + delta.medium, low: old.low + delta.low,
        totalIPs: old.totalIPs + newEvts.length,
        apiCounts: newApiCounts, attackDist: newAttackDist, history: newHistory,
        liveThreats: newLiveThreats,
        activeThreats: rnd(5, 25), blocked: old.blocked + rnd(0, 2),
        bandwidth: rnd(40, 95),
      };
    });
    setTick(t => t + 1);
  }, []);

  useEffect(() => {
    const id = setInterval(update, REFRESH_MS);
    return () => clearInterval(id);
  }, [update]);

  const sevBySrc = {};
  feedRef.current.slice(0, 200).forEach(e => {
    if (!sevBySrc[e.apiKey]) sevBySrc[e.apiKey] = {};
    sevBySrc[e.apiKey][e.sev] = (sevBySrc[e.apiKey][e.sev] || 0) + 1;
  });
  const counts = { Critical: data.critical, High: data.high, Medium: data.medium, Low: data.low };
  const p = prev || counts;

  const renderContent = () => {
    switch (activeTab) {
      case "dashboard": return (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* KPI Row */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {[["Active Threats", data.activeThreats, "#ff3b5c", "rgba(255,59,92,0.4)", "rgba(255,59,92,0.08)", "rgba(255,59,92,0.25)"],
              ["Blocked", data.blocked, "#00e5a0", "rgba(0,229,160,0.3)", "rgba(0,229,160,0.07)", "rgba(0,229,160,0.22)"],
              ["Total Scanned", data.totalScanned, "#38bdf8", "rgba(56,189,248,0.3)", "rgba(56,189,248,0.07)", "rgba(56,189,248,0.22)"],
              ["Network Devices", data.networkDevices, "#f5c518", "rgba(245,197,24,0.3)", "rgba(245,197,24,0.07)", "rgba(245,197,24,0.22)"]
            ].map(([label, value, color, glow, bg, border]) => (
              <div key={label} style={{ flex: 1, minWidth: 140, background: bg, border: `1px solid ${border}`, borderTop: `2px solid ${color}`, borderRadius: 12, padding: "14px 16px", boxShadow: `0 4px 20px ${glow}` }}>
                <div style={{ fontSize: 9, color: "#3d5166", letterSpacing: "0.12em", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: "monospace" }}>{value}</div>
              </div>
            ))}
          </div>
          {/* Severity KPIs */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <KpiCard label="Critical Threats" value={data.critical} delta={data.critical - p.critical} {...SEV.Critical} sparkData={data.history} />
            <KpiCard label="High Priority" value={data.high} delta={data.high - p.high} {...SEV.High} sparkData={data.history.map(h => ({...h, v: Math.round(h.v * 2.1)}))} />
            <KpiCard label="Medium Alerts" value={data.medium} delta={data.medium - p.medium} {...SEV.Medium} sparkData={data.history.map(h => ({...h, v: Math.round(h.v * 3.4)}))} />
            <KpiCard label="Low / Info" value={data.low} delta={data.low - p.low} {...SEV.Low} sparkData={data.history.map(h => ({...h, v: Math.round(h.v * 4.7)}))} />
          </div>
          {/* Main Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
            <Panel title="Severity Breakdown">
              <SevRing counts={counts} />
              <div style={{ marginTop: 14, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {Object.entries(counts).map(([sev, cnt]) => (
                  <div key={sev} style={{ background: SEV[sev].bg, border: `1px solid ${SEV[sev].border}`, borderRadius: 8, padding: "8px 12px", textAlign: "center" }}>
                    <div style={{ color: SEV[sev].color, fontSize: 16, fontWeight: 800, fontFamily: "monospace" }}>{cnt.toLocaleString()}</div>
                    <div style={{ color: "#3d5166", fontSize: 8, letterSpacing: "0.08em", textTransform: "uppercase" }}>{sev}</div>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="API Source Detection">
              <ApiSourcePanel apiCounts={data.apiCounts} sevBySrc={sevBySrc} />
            </Panel>
            <Panel title="Attack Type Distribution">
              <AttackDist data={data.attackDist} />
            </Panel>
          </div>
          {/* Live Feed */}
          <Panel title="Live Threat Feed" badge={`${feed.length} events`}>
            <div style={{ display: "grid", gridTemplateColumns: "88px 70px 1fr 110px 60px 80px", gap: 8, padding: "5px 16px 8px", borderBottom: "1px solid rgba(255,255,255,0.06)", fontSize: 8, color: "#1e3a4a", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "monospace" }}>
              <div>Severity</div><div>Score</div><div>Source IP</div><div>Attack Type</div><div>Country</div><div>API</div>
            </div>
            <div style={{ maxHeight: 280, overflowY: "auto" }}>
              {feed.length === 0 ? (
                <div style={{ padding: 24, textAlign: "center", color: "#1e293b", fontSize: 10, fontFamily: "monospace" }}>Initializing threat feed…</div>
              ) : feed.map(evt => <FeedRow key={evt.id} evt={evt} fresh={freshIds.has(evt.id)} />)}
            </div>
          </Panel>
        </div>
      );
      case "threatmap": return (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <Panel title="Global Threat Map" badge={`${data.liveThreats.length} active sources`}>
            <ThreatMap liveThreats={data.liveThreats} />
          </Panel>
          <Panel title="Live Threat Feed" badge={`${data.liveThreats.length} threats`}>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10, fontFamily: "monospace" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                    {["ID","Source","IP","Type","Severity","Status"].map(h => <th key={h} style={{ color: "#3d5166", padding: "6px 12px", textAlign: "left", fontSize: 8, letterSpacing: "0.1em" }}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {data.liveThreats.map((t, i) => (
                    <tr key={t.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)", background: i % 2 ? "rgba(255,255,255,0.01)" : "transparent" }}>
                      <td style={{ padding: "7px 12px", color: "#3d5166" }}>{t.id}</td>
                      <td style={{ padding: "7px 12px", color: "#94a3b8" }}>{t.source}</td>
                      <td style={{ padding: "7px 12px", color: "#38bdf8" }}>{t.ip}</td>
                      <td style={{ padding: "7px 12px", color: "#4b6077" }}>{t.type}</td>
                      <td style={{ padding: "7px 12px" }}><span style={{ color: SEV[t.severity]?.color, fontSize: 9 }}>{t.severity}</span></td>
                      <td style={{ padding: "7px 12px" }}><span style={{ color: t.status === "Mitigated" ? "#00e5a0" : "#ff3b5c", fontSize: 9 }}>{t.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      );
      case "analytics": return <AnalyticsTab data={data} />;
      case "ai": return <AIAssistant />;
      case "urlscan": return <URLScanner />;
      case "history": return <ThreatHistory threats={feed} />;
      case "database": return <DatabaseManager data={data} />;
      case "export": return <ExportData feed={feed} data={data} />;
      case "barcode": return <BarcodeScanner />;
      case "network": return <NetworkScanner data={data} />;
      default: return null;
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#020b14", color: "#94a3b8", fontFamily: "'Courier New', monospace" }}>
      {/* Sidebar */}
      <div style={{
        width: 220, flexShrink: 0, background: "#030d18",
        borderRight: "1px solid rgba(0,229,160,0.12)",
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, height: "100vh", overflowY: "auto",
      }}>
        {/* Logo */}
        <div style={{ padding: "20px 20px 16px", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg,rgba(0,229,160,0.2),rgba(56,189,248,0.2))", border: "1px solid rgba(0,229,160,0.3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🛡</div>
            <div>
              <div style={{ color: "#fff", fontSize: 11, fontWeight: 700, letterSpacing: "0.1em" }}>CYBERSHIELD</div>
              <div style={{ color: "#1e3a4a", fontSize: 7, letterSpacing: "0.1em" }}>SOC PLATFORM</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "14px 12px" }}>
          {NAV_ITEMS.map(item => (
            <button key={item.id} onClick={() => setActiveTab(item.id)} style={{
              display: "flex", alignItems: "center", gap: 10, width: "100%",
              padding: "9px 12px", marginBottom: 2, borderRadius: 8,
              background: activeTab === item.id ? "rgba(0,229,160,0.1)" : "transparent",
              border: `1px solid ${activeTab === item.id ? "rgba(0,229,160,0.2)" : "transparent"}`,
              color: activeTab === item.id ? "#00e5a0" : "#3d5166",
              cursor: "pointer", textAlign: "left", fontSize: 10, letterSpacing: "0.08em",
              transition: "all 0.15s",
            }}>
              <span style={{ fontSize: 12, opacity: 0.9 }}>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        {/* Sidebar status */}
        <div style={{ padding: "14px 16px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <PulseDot />
            <span style={{ fontSize: 9, color: "#00e5a0", letterSpacing: "0.1em" }}>LIVE FEED ACTIVE</span>
          </div>
          <div style={{ fontSize: 8, color: "#1e3a4a", fontFamily: "monospace" }}>
            CYCLE #{tick.toString().padStart(4,"0")} · {new Date().toLocaleTimeString()}
          </div>
          <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 4 }}>
            {[["WiFi Signal","95%","#00e5a0"],["WPA3-Enterprise","Active","#38bdf8"]].map(([k,v,c]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontSize: 8, color: "#1e3a4a" }}>{k}</span>
                <span style={{ fontSize: 8, color: c }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, overflow: "auto" }}>
        {/* Header */}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "14px 24px",
          borderBottom: "1px solid rgba(255,255,255,0.05)",
          background: "rgba(3,13,24,0.8)", backdropFilter: "blur(10px)",
          position: "sticky", top: 0, zIndex: 100,
        }}>
          <div>
            <div style={{ color: "#fff", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em" }}>
              {NAV_ITEMS.find(n => n.id === activeTab)?.label.toUpperCase()}
            </div>
            <div style={{ color: "#1e3a4a", fontSize: 8, letterSpacing: "0.1em" }}>
              THREAT INTELLIGENCE DASHBOARD · {new Date().toLocaleDateString()}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ display: "flex", gap: 16, fontSize: 9, color: "#3d5166", fontFamily: "monospace" }}>
              <span>DB: threats.db</span>
              <span>{data.totalIPs.toLocaleString()} IPs</span>
              <span>{data.countries} countries</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, background: "rgba(0,229,160,0.07)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 8, padding: "5px 12px" }}>
              <PulseDot />
              <span style={{ color: "#00e5a0", fontSize: 9, letterSpacing: "0.1em" }}>LIVE</span>
            </div>
          </div>
        </div>

        {/* Page Content */}
        <div style={{ padding: 20 }}>
          {renderContent()}
        </div>

        {/* Footer */}
        <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", padding: "10px 24px", display: "flex", justifyContent: "space-between", fontSize: 8, color: "#1e3a4a", fontFamily: "monospace" }}>
          <div>CYBERSHIELD SOC · {data.totalIPs.toLocaleString()} IPs · {data.countries} countries · SQLite WAL</div>
          <div>AbuseIPDB · Feodo Tracker · Emerging Threats · CINS Score · Spamhaus DROP</div>
          <div>REFRESH: {REFRESH_MS/1000}s · CYCLE #{tick}</div>
        </div>
      </div>
    </div>
  );
}
