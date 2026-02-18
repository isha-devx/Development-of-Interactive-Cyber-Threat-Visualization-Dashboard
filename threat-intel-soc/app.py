# ============================================================
# app.py — Premium SOC Threat Intelligence Dashboard
# Enhanced from original: glassmorphic dark UI, better charts,
# sidebar navigation, live KPIs, anomaly detection, MITRE tab.
# Run: python app.py  → http://127.0.0.1:8050
# ============================================================

from dash import Dash, dcc, html, Input, Output, State, dash_table
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# ── Load & prepare data ──────────────────────────────────────
df = pd.read_csv("threat_data_10K.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df = df.dropna(subset=["timestamp"])

for col, default in [("severity","Unknown"),("score",0),("country","Unknown"),
                     ("attack_type","Unknown"),("mitre","T0000"),
                     ("source_ip","0.0.0.0"),("target_system","Unknown")]:
    if col not in df.columns:
        df[col] = default

ISO2_TO_ISO3 = {
    "IN":"IND","US":"USA","RU":"RUS","NL":"NLD","KR":"KOR","DE":"DEU",
    "FR":"FRA","GB":"GBR","CN":"CHN","JP":"JPN","BR":"BRA","CA":"CAN",
    "AU":"AUS","IT":"ITA","ES":"ESP","MX":"MEX","UA":"UKR","ID":"IDN",
    "PK":"PAK","ZA":"ZAF","SG":"SGP","VN":"VNM","TH":"THA","PL":"POL"
}
df["country_iso3"] = df["country"].map(lambda x: ISO2_TO_ISO3.get(x, x))
df["date"]        = df["timestamp"].dt.date
df["hour"]        = df["timestamp"].dt.hour
df["day_of_week"] = df["timestamp"].dt.day_name()
df["severity_rank"] = df["severity"].map({"Critical":4,"High":3,"Medium":2,"Low":1,"Unknown":0})

# ── Colour palette ───────────────────────────────────────────
SEV_COLORS = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#10b981","Unknown":"#64748b"}
BG_DARK    = "#03080e"
BG_CARD    = "rgba(255,255,255,0.018)"
BORDER     = "rgba(255,255,255,0.06)"
ACCENT     = "#00d9ff"
FONT_MONO  = "'JetBrains Mono', 'Fira Code', 'Courier New', monospace"

PLOTLY_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#94a3b8", family=FONT_MONO, size=11),
    margin=dict(l=12, r=12, t=36, b=12),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
    coloraxis_colorbar=dict(tickfont=dict(color="#64748b")),
)

# ── Helper: card wrapper ─────────────────────────────────────
def card(children, style=None):
    base = {
        "background": BG_CARD,
        "border": f"1px solid {BORDER}",
        "borderRadius": "14px",
        "padding": "16px",
        "marginBottom": "16px",
    }
    if style:
        base.update(style)
    return html.Div(children, style=base)

def section_title(text):
    return html.Div(text, style={
        "fontSize": "10px", "color": "#475569", "letterSpacing": "0.12em",
        "textTransform": "uppercase", "marginBottom": "12px", "fontFamily": FONT_MONO
    })

# ── KPI style helper ─────────────────────────────────────────
def kpi_card(icon, label, value_id, color):
    return html.Div([
        html.Div(icon, style={"fontSize": "22px", "marginBottom": "4px"}),
        html.Div(label, style={"fontSize": "10px", "color": "#475569", "letterSpacing": "0.1em",
                               "textTransform": "uppercase", "fontFamily": FONT_MONO}),
        html.Div(id=value_id, style={"fontSize": "28px", "fontWeight": "700",
                                      "color": color, "fontFamily": FONT_MONO, "lineHeight": "1.2"}),
    ], style={
        "background": BG_CARD,
        "border": f"1px solid {BORDER}",
        "borderLeft": f"3px solid {color}",
        "borderRadius": "14px",
        "padding": "16px 20px",
        "flex": "1",
        "minWidth": "160px",
    })

# ── Sidebar nav item ─────────────────────────────────────────
NAV_TABS = [
    ("overview",  "⬡", "Overview"),
    ("trends",    "◈", "Trend Analysis"),
    ("geomap",    "◉", "Geo Map"),
    ("attacks",   "⚠", "Attack Types"),
    ("heatmap",   "▦", "Heatmap"),
    ("mitre",     "▣", "MITRE ATT&CK"),
    ("targets",   "⊛", "Top Targets"),
    ("anomaly",   "⏱", "Anomaly Detect"),
    ("threats",   "◎", "Critical Threats"),
]

def nav_item(tab_id, icon, label):
    return html.Div([
        html.Span(icon, style={"fontSize": "14px", "lineHeight": "1"}),
        html.Span(label, style={"fontSize": "11px", "letterSpacing": "0.05em"}),
    ], id=f"nav-{tab_id}", n_clicks=0,
    className="nav-item",
    style={
        "display": "flex", "alignItems": "center", "gap": "10px",
        "padding": "8px 12px", "borderRadius": "10px", "cursor": "pointer",
        "color": "#475569", "fontFamily": FONT_MONO, "border": "1px solid transparent",
        "transition": "all 0.2s", "marginBottom": "2px",
    })

# ── App init ─────────────────────────────────────────────────
app = Dash(__name__, suppress_callback_exceptions=True)
app.title = "SOC Threat Intelligence"

# ── Layout ───────────────────────────────────────────────────
app.layout = html.Div([

    # ── Hidden state: active tab ────────────────────────────
    dcc.Store(id="active-tab", data="overview"),

    # ── Outer flex ─────────────────────────────────────────
    html.Div([

        # ── SIDEBAR ────────────────────────────────────────
        html.Div([
            # Logo
            html.Div([
                html.Div([
                    html.Div("🛡", style={"fontSize": "18px"}),
                ], style={
                    "width": "32px", "height": "32px", "borderRadius": "10px",
                    "background": "linear-gradient(135deg,rgba(0,217,255,0.12),rgba(124,58,237,0.22))",
                    "border": f"1px solid rgba(0,217,255,0.26)", "display": "flex",
                    "alignItems": "center", "justifyContent": "center", "flexShrink": "0",
                }),
                html.Div([
                    html.Div("CYBER SOC", style={"color": "#fff", "fontSize": "11px",
                             "fontWeight": "700", "letterSpacing": "0.15em", "fontFamily": FONT_MONO}),
                    html.Div("Threat Intelligence", style={"color": "#334155", "fontSize": "9px",
                             "fontFamily": FONT_MONO}),
                ])
            ], style={"display": "flex", "alignItems": "center", "gap": "10px",
                      "padding": "0 8px", "marginBottom": "20px"}),

            # Nav items
            html.Div([nav_item(t, i, l) for t, i, l in NAV_TABS]),

            # Severity mini bar
            html.Div([
                html.Div("Severity", style={"fontSize": "9px", "color": "#334155",
                         "textTransform": "uppercase", "letterSpacing": "0.1em",
                         "fontFamily": FONT_MONO, "marginBottom": "8px"}),
                *[html.Div([
                    html.Span(s[:4], style={"fontSize": "9px", "color": "#475569",
                              "width": "28px", "display": "inline-block", "fontFamily": FONT_MONO}),
                    html.Div(style={
                        "display": "inline-block", "height": "4px", "borderRadius": "2px",
                        "background": SEV_COLORS[s], "marginLeft": "4px",
                        "width": f"{(df['severity'].value_counts().get(s,0)/len(df)*100):.0f}%",
                        "maxWidth": "80px", "verticalAlign": "middle",
                    }),
                    html.Span(f" {df['severity'].value_counts().get(s,0):,}",
                              style={"fontSize": "9px", "color": SEV_COLORS[s],
                                     "fontFamily": FONT_MONO, "marginLeft": "4px"}),
                ], style={"marginBottom": "5px"}) for s in ["Critical","High","Medium","Low"]],
            ], style={
                "marginTop": "auto", "padding": "12px",
                "background": BG_CARD, "border": f"1px solid {BORDER}",
                "borderRadius": "12px",
            }),

        ], style={
            "width": "192px", "flexShrink": "0",
            "background": "rgba(4,10,18,0.98)",
            "borderRight": f"1px solid {BORDER}",
            "display": "flex", "flexDirection": "column",
            "padding": "18px 10px",
            "height": "100vh", "overflowY": "auto",
            "position": "sticky", "top": "0",
        }),

        # ── MAIN AREA ───────────────────────────────────────
        html.Div([

            # Top bar
            html.Div([
                html.Div(id="topbar-title", style={
                    "color": "#fff", "fontSize": "14px", "fontWeight": "700",
                    "fontFamily": FONT_MONO, "letterSpacing": "0.05em",
                }),
                html.Div([
                    html.Div(id="total_threats", style={"fontSize": "11px", "color": "#475569",
                             "fontFamily": FONT_MONO}),
                    html.Div([
                        html.Span("●", style={"color": "#10b981", "fontSize": "8px"}),
                        html.Span(" LIVE", style={"fontSize": "10px", "color": "#10b981",
                                                   "fontFamily": FONT_MONO, "marginLeft": "4px"}),
                    ], style={"display": "flex", "alignItems": "center"}),
                ], style={"textAlign": "right"}),
            ], style={
                "display": "flex", "justifyContent": "space-between", "alignItems": "center",
                "padding": "12px 20px",
                "background": "rgba(3,8,14,0.96)",
                "borderBottom": f"1px solid {BORDER}",
                "position": "sticky", "top": "0", "zIndex": "100",
            }),

            # Filters bar
            html.Div([
                html.Div([
                    html.Label("Severity", style={"fontSize": "9px", "color": "#475569",
                               "textTransform": "uppercase", "letterSpacing": "0.1em",
                               "fontFamily": FONT_MONO, "display": "block", "marginBottom": "4px"}),
                    dcc.Dropdown(
                        id="severity_filter",
                        options=[{"label": s, "value": s} for s in sorted(df["severity"].unique())],
                        value=list(df["severity"].unique()),
                        multi=True,
                        style={"minWidth": "180px"},
                        className="dark-dropdown",
                    ),
                ]),
                html.Div([
                    html.Label("Time Range", style={"fontSize": "9px", "color": "#475569",
                               "textTransform": "uppercase", "letterSpacing": "0.1em",
                               "fontFamily": FONT_MONO, "display": "block", "marginBottom": "4px"}),
                    dcc.Dropdown(
                        id="time_range",
                        options=[
                            {"label": "Last 7 Days",  "value": "7d"},
                            {"label": "Last 14 Days", "value": "14d"},
                            {"label": "Last 30 Days", "value": "30d"},
                            {"label": "All Time",     "value": "all"},
                        ],
                        value="all",
                        style={"minWidth": "140px"},
                        className="dark-dropdown",
                    ),
                ]),
                html.Div([
                    html.Label("Attack Type", style={"fontSize": "9px", "color": "#475569",
                               "textTransform": "uppercase", "letterSpacing": "0.1em",
                               "fontFamily": FONT_MONO, "display": "block", "marginBottom": "4px"}),
                    dcc.Dropdown(
                        id="attack_filter",
                        options=[{"label": "All Types", "value": "all"}] +
                                [{"label": a, "value": a} for a in sorted(df["attack_type"].unique())],
                        value="all",
                        style={"minWidth": "160px"},
                        className="dark-dropdown",
                    ),
                ]),
                html.Div(id="last_updated", style={"fontSize": "9px", "color": "#334155",
                         "fontFamily": FONT_MONO, "alignSelf": "flex-end"}),
            ], style={
                "display": "flex", "flexWrap": "wrap", "gap": "16px",
                "padding": "12px 20px",
                "background": "rgba(4,10,18,0.80)",
                "borderBottom": f"1px solid {BORDER}",
            }),

            # KPI row
            html.Div([
                kpi_card("🔴", "Critical Threats", "kpi_critical", "#ef4444"),
                kpi_card("🟠", "High Priority",    "kpi_high",     "#f97316"),
                kpi_card("🌍", "Countries",         "kpi_countries","#7c3aed"),
                kpi_card("📊", "Trend vs Prev",    "kpi_trend",    "#00d9ff"),
            ], style={"display": "flex", "gap": "12px", "padding": "16px 20px",
                      "flexWrap": "wrap"}),

            # Tab content area
            html.Div(id="tab-content", style={"padding": "0 20px 24px 20px"}),

            # Auto-refresh
            dcc.Interval(id="interval-component", interval=10*1000, n_intervals=0),

        ], style={"flex": "1", "overflowY": "auto", "background": BG_DARK}),

    ], style={"display": "flex", "height": "100vh", "overflow": "hidden"}),

    # ── Chatbot button ──────────────────────────────────────
    html.Button("💬", id="chat-btn", style={
        "position": "fixed", "bottom": "24px", "right": "24px",
        "width": "48px", "height": "48px", "borderRadius": "14px",
        "background": "linear-gradient(135deg,rgba(0,217,255,0.16),rgba(124,58,237,0.24))",
        "border": "1px solid rgba(0,217,255,0.28)", "color": ACCENT,
        "fontSize": "20px", "cursor": "pointer", "zIndex": "9999",
        "boxShadow": "0 0 24px rgba(0,217,255,0.1)",
    }),

    # ── Chat window ─────────────────────────────────────────
    html.Div(id="chat-window", children=[
        html.Div([
            html.Span("🤖 SOC AI Assistant", style={
                "fontWeight": "700", "fontSize": "12px", "color": ACCENT,
                "fontFamily": FONT_MONO,
            }),
            html.Button("×", id="close-chat-btn", style={
                "background": "none", "border": "none", "color": "#475569",
                "fontSize": "18px", "cursor": "pointer", "lineHeight": "1",
            }),
        ], style={"display": "flex", "justifyContent": "space-between", "alignItems": "center",
                  "padding": "12px 14px", "borderBottom": f"1px solid {BORDER}"}),

        html.Div(id="chat-messages", children=[
            html.Div("Hello! I'm your SOC assistant. Ask me about threats, MITRE tactics, countries, or attack patterns.",
                     style={"padding": "10px 12px", "margin": "8px",
                            "background": "rgba(255,255,255,0.04)",
                            "border": f"1px solid {BORDER}", "borderRadius": "10px",
                            "fontSize": "11px", "color": "#94a3b8", "fontFamily": FONT_MONO}),
        ], style={"maxHeight": "280px", "overflowY": "auto", "padding": "4px"}),

        html.Div([
            dcc.Input(id="chat-input", type="text", placeholder="Ask about threat data...",
                      style={
                          "flex": "1", "padding": "8px 12px",
                          "background": "rgba(255,255,255,0.04)",
                          "border": f"1px solid {BORDER}", "borderRadius": "8px",
                          "color": "#e2e8f0", "fontSize": "11px",
                          "fontFamily": FONT_MONO, "outline": "none",
                      }),
            html.Button("Send", id="send-btn", style={
                "padding": "8px 14px",
                "background": "rgba(0,217,255,0.1)",
                "border": "1px solid rgba(0,217,255,0.28)",
                "borderRadius": "8px", "color": ACCENT,
                "fontSize": "11px", "cursor": "pointer", "fontFamily": FONT_MONO,
                "fontWeight": "700",
            }),
        ], style={"display": "flex", "gap": "8px", "padding": "10px 12px",
                  "borderTop": f"1px solid {BORDER}"}),
    ], style={
        "position": "fixed", "bottom": "84px", "right": "24px", "width": "320px",
        "background": "rgba(5,12,22,0.97)",
        "border": "1px solid rgba(0,217,255,0.15)", "borderRadius": "16px",
        "boxShadow": "0 20px 60px rgba(0,0,0,0.8)", "zIndex": "9998",
        "display": "none",
    }),

], style={"background": BG_DARK, "fontFamily": FONT_MONO})


# ══════════════════════════════════════════════════════════════
# CALLBACKS
# ══════════════════════════════════════════════════════════════

# ── Tab navigation ───────────────────────────────────────────
@app.callback(
    Output("active-tab", "data"),
    [Input(f"nav-{t}", "n_clicks") for t, _, _ in NAV_TABS],
    prevent_initial_call=True,
)
def switch_tab(*clicks):
    from dash import ctx
    if not ctx.triggered_id:
        return "overview"
    return ctx.triggered_id.replace("nav-", "")

# ── Topbar title ─────────────────────────────────────────────
@app.callback(Output("topbar-title", "children"), Input("active-tab", "data"))
def update_title(tab):
    labels = {t: l for t, _, l in NAV_TABS}
    return labels.get(tab, "Overview")

# ── Chat toggle ──────────────────────────────────────────────
@app.callback(
    Output("chat-window", "style"),
    Input("chat-btn", "n_clicks"),
    Input("close-chat-btn", "n_clicks"),
    State("chat-window", "style"),
    prevent_initial_call=True,
)
def toggle_chat(open_clicks, close_clicks, style):
    from dash import ctx
    base = {
        "position": "fixed", "bottom": "84px", "right": "24px", "width": "320px",
        "background": "rgba(5,12,22,0.97)",
        "border": "1px solid rgba(0,217,255,0.15)", "borderRadius": "16px",
        "boxShadow": "0 20px 60px rgba(0,0,0,0.8)", "zIndex": "9998",
    }
    if ctx.triggered_id == "close-chat-btn":
        return {**base, "display": "none"}
    cur = style.get("display", "none") if style else "none"
    return {**base, "display": "none" if cur != "none" else "block"}

# ── Chat messages ─────────────────────────────────────────────
@app.callback(
    Output("chat-messages", "children"),
    Input("send-btn", "n_clicks"),
    State("chat-input", "value"),
    State("chat-messages", "children"),
    prevent_initial_call=True,
)
def send_message(n, user_msg, messages):
    if not user_msg or not user_msg.strip():
        return messages

    QA = [
        (["total","how many","count","threat"],
         f"Database: {len(df):,} threats — {df['severity'].value_counts().get('Critical',0):,} Critical, "
         f"{df['severity'].value_counts().get('High',0):,} High."),
        (["countr","origin","geo"],
         f"Top origins: {', '.join(f'{c}({n})' for c,n in df['country'].value_counts().head(5).items())}."),
        (["attack","type","method"],
         f"Top attacks: {', '.join(f'{a}({n})' for a,n in df['attack_type'].value_counts().head(4).items())}."),
        (["mitre","att&ck","tactic"],
         f"Top MITRE: {', '.join(f'{m}({n})' for m,n in df['mitre'].value_counts().head(4).items())}."),
        (["target","system","victim"],
         f"Top targets: {', '.join(f'{t}({n})' for t,n in df['target_system'].value_counts().head(4).items())}."),
        (["score","risk","sever"],
         "Scores 0-100: Critical ≥90, High ≥70, Medium ≥40, Low ≥10."),
        (["report","summary"],
         f"Summary: {len(df):,} events | {df['severity'].value_counts().get('Critical',0)} Critical "
         f"| Top country: {df['country'].value_counts().index[0]} "
         f"| Top attack: {df['attack_type'].value_counts().index[0]}."),
        (["response","contain","block"],
         "Response: 1) Validate IP via VirusTotal. 2) Block at firewall. 3) Isolate system. 4) Log incident."),
    ]

    bot_reply = "Try: 'top attacks', 'affected countries', 'MITRE techniques', 'threat score', 'generate report'."
    l = user_msg.lower()
    for keys, ans in QA:
        if any(k in l for k in keys):
            bot_reply = ans
            break

    def msg_div(sender, text, is_user):
        return html.Div([
            html.Strong(f"{sender}: ", style={"color": ACCENT if is_user else "#64748b"}),
            text,
        ], style={
            "padding": "8px 12px", "margin": "6px 8px",
            "background": "rgba(0,217,255,0.06)" if is_user else "rgba(255,255,255,0.03)",
            "border": f"1px solid {'rgba(0,217,255,0.2)' if is_user else BORDER}",
            "borderRadius": "10px", "fontSize": "11px",
            "color": "#e2e8f0" if is_user else "#94a3b8",
            "fontFamily": FONT_MONO,
        })

    return list(messages or []) + [msg_div("You", user_msg, True), msg_div("AI", bot_reply, False)]


# ── MAIN DASHBOARD CALLBACK ───────────────────────────────────
@app.callback(
    Output("tab-content",    "children"),
    Output("kpi_critical",   "children"),
    Output("kpi_high",       "children"),
    Output("kpi_countries",  "children"),
    Output("kpi_trend",      "children"),
    Output("total_threats",  "children"),
    Output("last_updated",   "children"),
    Input("active-tab",         "data"),
    Input("severity_filter",    "value"),
    Input("time_range",         "value"),
    Input("attack_filter",      "value"),
    Input("interval-component", "n_intervals"),
)
def update_dashboard(tab, sel_sev, time_range, attack_type, _n):

    try:
        fresh = pd.read_csv("threat_data_10K.csv")
        fresh["timestamp"] = pd.to_datetime(fresh["timestamp"], errors="coerce")
        fresh = fresh.dropna(subset=["timestamp"])
        for col, default in [("severity","Unknown"),("score",0),("country","Unknown"),
                             ("attack_type","Unknown"),("mitre","T0000"),
                             ("source_ip","0.0.0.0"),("target_system","Unknown")]:
            if col not in fresh.columns:
                fresh[col] = default
        fresh["country_iso3"] = fresh["country"].map(lambda x: ISO2_TO_ISO3.get(x, x))
        fresh["date"]         = fresh["timestamp"].dt.date
        fresh["hour"]         = fresh["timestamp"].dt.hour
        fresh["day_of_week"]  = fresh["timestamp"].dt.day_name()
        fresh["severity_rank"]= fresh["severity"].map({"Critical":4,"High":3,"Medium":2,"Low":1,"Unknown":0})
        filt = fresh.copy()
    except Exception:
        filt = df.copy()

    if sel_sev:
        filt = filt[filt["severity"].isin(sel_sev)]
    if time_range != "all":
        days = {"7d":7,"14d":14,"30d":30}.get(time_range,30)
        cutoff = datetime.now() - timedelta(days=days)
        filt = filt[filt["timestamp"] >= cutoff]
    if attack_type != "all":
        filt = filt[filt["attack_type"] == attack_type]

    critical_count  = len(filt[filt["severity"] == "Critical"])
    high_count      = len(filt[filt["severity"] == "High"])
    countries_count = filt["country"].nunique()
    if len(filt) > 10:
        mid   = len(filt) // 2
        r_avg = filt.tail(mid)["score"].mean()
        p_avg = filt.head(mid)["score"].mean()
        trend = ((r_avg - p_avg) / p_avg * 100) if p_avg > 0 else 0
    else:
        trend = 0
    trend_sym   = "↑" if trend > 0 else "↓"
    trend_color = "#ef4444" if trend > 0 else "#10b981"

    kpi_c  = str(critical_count)
    kpi_h  = str(high_count)
    kpi_co = str(countries_count)
    kpi_t  = html.Span(f"{trend_sym} {abs(trend):.1f}%", style={"color": trend_color})
    total  = f"Analysed: {len(filt):,} threats"
    upd    = f"Updated: {datetime.now().strftime('%H:%M:%S')}"

    content = build_tab(tab, filt)
    return content, kpi_c, kpi_h, kpi_co, kpi_t, total, upd


def build_tab(tab, filt):
    if tab == "overview":  return build_overview(filt)
    elif tab == "trends":  return build_trends(filt)
    elif tab == "geomap":  return build_geomap(filt)
    elif tab == "attacks": return build_attacks(filt)
    elif tab == "heatmap": return build_heatmap(filt)
    elif tab == "mitre":   return build_mitre(filt)
    elif tab == "targets": return build_targets(filt)
    elif tab == "anomaly": return build_anomaly(filt)
    elif tab == "threats": return build_threats(filt)
    return html.Div("Select a tab from the sidebar.")


# ── Tab builders ─────────────────────────────────────────────

def build_overview(filt):
    daily = filt.groupby("date").size().reset_index(name="count")
    trend_fig = go.Figure()
    trend_fig.add_trace(go.Scatter(
        x=daily["date"], y=daily["count"],
        fill="tozeroy", fillcolor="rgba(0,217,255,0.08)",
        line=dict(color=ACCENT, width=2), mode="lines", name="Attacks",
    ))
    for sev, col in SEV_COLORS.items():
        if sev == "Unknown": continue
        sd = filt[filt["severity"]==sev].groupby("date").size().reset_index(name="count")
        trend_fig.add_trace(go.Scatter(x=sd["date"], y=sd["count"], name=sev,
                             line=dict(color=col, width=1.5), mode="lines"))
    trend_fig.update_layout(**PLOTLY_LAYOUT, height=220,
                            title=dict(text="Daily Attack Volume by Severity", font=dict(size=11, color="#475569")))

    sev_counts = filt["severity"].value_counts().reset_index()
    sev_counts.columns = ["severity","count"]
    pie_fig = px.pie(sev_counts, values="count", names="severity", hole=0.5,
                     color="severity", color_discrete_map=SEV_COLORS)
    pie_fig.update_traces(textfont_size=10, textfont_color="#94a3b8",
                          marker=dict(line=dict(color=BG_DARK, width=2)))
    pie_fig.update_layout(**PLOTLY_LAYOUT, height=220,
                          title=dict(text="Severity Distribution", font=dict(size=11, color="#475569")))

    cc_data = filt["country"].value_counts().head(8).reset_index()
    cc_data.columns = ["country","count"]
    cc_fig = px.bar(cc_data, x="count", y="country", orientation="h",
                    color="count", color_continuous_scale="Reds")
    cc_fig.update_layout(**PLOTLY_LAYOUT, height=220, showlegend=False,
                         title=dict(text="Top Threat Countries", font=dict(size=11, color="#475569")))
    cc_fig.update_traces(marker_line_width=0)

    top10 = filt.nlargest(10, "score")[
        ["timestamp","severity","attack_type","country","source_ip","target_system","score"]
    ]
    table = dash_table.DataTable(
        data=top10.to_dict("records"),
        columns=[{"name": c, "id": c} for c in top10.columns],
        style_table={"overflowX": "auto"},
        style_cell={"backgroundColor":"transparent","color":"#94a3b8",
                    "border":f"1px solid {BORDER}","textAlign":"left",
                    "padding":"8px 10px","fontSize":"10px","fontFamily":FONT_MONO},
        style_header={"backgroundColor":"rgba(255,255,255,0.025)","fontWeight":"700",
                       "border":f"1px solid {BORDER}","color":"#475569","fontSize":"9px",
                       "textTransform":"uppercase","letterSpacing":"0.1em"},
        style_data_conditional=[
            {"if":{"filter_query":"{severity} = 'Critical'"},
             "backgroundColor":"rgba(239,68,68,0.07)","color":"#fca5a5"},
            {"if":{"filter_query":"{severity} = 'High'"},
             "backgroundColor":"rgba(249,115,22,0.07)","color":"#fdba74"},
        ],
    )

    return html.Div([
        html.Div([
            card(dcc.Graph(figure=trend_fig, config={"displayModeBar":False}), {"flex":"2","marginBottom":"0","marginRight":"12px"}),
            card(dcc.Graph(figure=pie_fig,   config={"displayModeBar":False}), {"flex":"1","marginBottom":"0"}),
        ], style={"display":"flex","marginBottom":"12px"}),
        html.Div([
            card(dcc.Graph(figure=cc_fig, config={"displayModeBar":False}), {"flex":"1","marginBottom":"0","marginRight":"12px"}),
            card([
                section_title("Dataset Info"),
                *[html.Div([
                    html.Span(k, style={"color":"#334155","fontSize":"10px","fontFamily":FONT_MONO}),
                    html.Span(v, style={"color":c,"fontSize":"10px","fontFamily":FONT_MONO}),
                ], style={"display":"flex","justifyContent":"space-between","marginBottom":"6px"})
                  for k,v,c in [
                      ("Total Events", f"{len(filt):,}", "#e2e8f0"),
                      ("Critical", str(len(filt[filt.severity=="Critical"])), "#ef4444"),
                      ("High", str(len(filt[filt.severity=="High"])), "#f97316"),
                      ("Countries", str(filt["country"].nunique()), "#7c3aed"),
                      ("Attack Types", str(filt["attack_type"].nunique()), "#f97316"),
                      ("MITRE Techniques", str(filt["mitre"].nunique()), "#7c3aed"),
                  ]
                ],
            ], {"flex":"1","marginBottom":"0"}),
        ], style={"display":"flex","marginBottom":"12px"}),
        card([section_title("Top 10 Critical Threats"), table]),
    ])


def build_trends(filt):
    daily_sev = filt.groupby(["date","severity"]).size().reset_index(name="count")
    fig1 = go.Figure()
    for sev, col in SEV_COLORS.items():
        if sev == "Unknown": continue
        d = daily_sev[daily_sev["severity"]==sev]
        fig1.add_trace(go.Scatter(x=d["date"], y=d["count"], name=sev,
                        mode="lines", stackgroup="one",
                        line=dict(color=col, width=1.5)))
    fig1.update_layout(**PLOTLY_LAYOUT, height=280,
                       title=dict(text="Stacked Daily Severity Volume", font=dict(size=11,color="#475569")))

    daily = filt.groupby("date").size().reset_index(name="count")
    fig2 = px.bar(daily, x="date", y="count", color="count", color_continuous_scale="Blues")
    fig2.update_layout(**PLOTLY_LAYOUT, height=180, showlegend=False,
                       title=dict(text="Daily Attack Frequency", font=dict(size=11,color="#475569")))
    fig2.update_traces(marker_line_width=0)

    return html.Div([
        card(dcc.Graph(figure=fig1, config={"displayModeBar":False})),
        card(dcc.Graph(figure=fig2, config={"displayModeBar":False})),
    ])


def build_geomap(filt):
    geo_data = filt.groupby("country_iso3").agg(total_score=("score","sum"), count=("severity","count")).reset_index()
    fig = px.choropleth(
        geo_data, locations="country_iso3", locationmode="ISO-3",
        color="total_score", hover_data=["count"],
        color_continuous_scale="Reds",
    )
    fig.update_layout(**PLOTLY_LAYOUT, height=460,
                      geo=dict(bgcolor="rgba(0,0,0,0)", showframe=False,
                               showcoastlines=True, coastlinecolor=BORDER,
                               showland=True, landcolor="rgba(255,255,255,0.03)"),
                      title=dict(text="Global Cyber Threat Heatmap", font=dict(size=11,color="#475569")))

    cc = filt["country"].value_counts().head(12).reset_index()
    cc.columns = ["country","count"]
    bar = px.bar(cc, x="count", y="country", orientation="h",
                 color="count", color_continuous_scale="Reds")
    bar.update_layout(**PLOTLY_LAYOUT, height=260, showlegend=False,
                      title=dict(text="Top Countries by Threat Count", font=dict(size=11,color="#475569")))
    bar.update_traces(marker_line_width=0)

    return html.Div([
        card(dcc.Graph(figure=fig, config={"displayModeBar":False})),
        card(dcc.Graph(figure=bar, config={"displayModeBar":False})),
    ])


def build_attacks(filt):
    atk = filt.groupby(["attack_type","severity"]).size().reset_index(name="count")
    fig = px.bar(atk, y="attack_type", x="count", color="severity", orientation="h",
                 color_discrete_map=SEV_COLORS)
    fig.update_layout(**PLOTLY_LAYOUT, height=400, barmode="stack",
                      title=dict(text="Attack Types by Severity", font=dict(size=11,color="#475569")))
    fig.update_traces(marker_line_width=0)

    top6 = filt["attack_type"].value_counts().head(6)
    radar = go.Figure(go.Scatterpolar(
        r=top6.values.tolist() + [top6.values[0]],
        theta=top6.index.tolist() + [top6.index[0]],
        fill="toself", fillcolor="rgba(0,217,255,0.08)",
        line=dict(color=ACCENT, width=2),
    ))
    radar.update_layout(**PLOTLY_LAYOUT, height=300,
                        polar=dict(
                            bgcolor="rgba(0,0,0,0)",
                            radialaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(size=8,color="#334155")),
                            angularaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(size=9,color="#475569")),
                        ),
                        title=dict(text="Attack Type Radar", font=dict(size=11,color="#475569")))

    return html.Div([
        html.Div([
            card(dcc.Graph(figure=fig,   config={"displayModeBar":False}), {"flex":"2","marginBottom":"0","marginRight":"12px"}),
            card(dcc.Graph(figure=radar, config={"displayModeBar":False}), {"flex":"1","marginBottom":"0"}),
        ], style={"display":"flex"}),
    ])


def build_heatmap(filt):
    day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    hourly = filt.groupby(["day_of_week","hour"]).size().reset_index(name="count")
    pivot  = hourly.pivot(index="day_of_week", columns="hour", values="count").fillna(0)
    pivot  = pivot.reindex(day_order)

    fig = go.Figure(go.Heatmap(
        z=pivot.values, x=pivot.columns, y=pivot.index,
        colorscale="Reds", hoverongaps=False,
        colorbar=dict(tickfont=dict(size=9,color="#475569")),
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=340,
                      title=dict(text="Attack Pattern: Day of Week vs Hour of Day", font=dict(size=11,color="#475569")),
                      xaxis=dict(title="Hour of Day", tickfont=dict(size=9,color="#475569")),
                      yaxis=dict(tickfont=dict(size=9,color="#475569")))

    dow = filt["day_of_week"].value_counts().reindex(day_order).reset_index()
    dow.columns = ["day","count"]
    dow_fig = px.bar(dow, x="day", y="count", color="count", color_continuous_scale="Blues")
    dow_fig.update_layout(**PLOTLY_LAYOUT, height=200, showlegend=False,
                          title=dict(text="Total Attacks by Day of Week", font=dict(size=11,color="#475569")))
    dow_fig.update_traces(marker_line_width=0)

    return html.Div([
        card(dcc.Graph(figure=fig,     config={"displayModeBar":False})),
        card(dcc.Graph(figure=dow_fig, config={"displayModeBar":False})),
    ])


def build_mitre(filt):
    tree = px.treemap(filt, path=["mitre","attack_type","severity"],
                      values="score", color="severity_rank",
                      color_continuous_scale="RdYlGn_r")
    tree.update_layout(**PLOTLY_LAYOUT, height=420,
                       title=dict(text="MITRE ATT&CK Technique Analysis", font=dict(size=11,color="#475569")))

    mitre_bar = filt["mitre"].value_counts().head(10).reset_index()
    mitre_bar.columns = ["mitre","count"]
    bar = px.bar(mitre_bar, x="mitre", y="count", color="count", color_continuous_scale="Purples")
    bar.update_layout(**PLOTLY_LAYOUT, height=220, showlegend=False,
                      title=dict(text="Top MITRE Techniques", font=dict(size=11,color="#475569")))
    bar.update_traces(marker_line_width=0)

    return html.Div([
        card(dcc.Graph(figure=tree, config={"displayModeBar":False})),
        card(dcc.Graph(figure=bar,  config={"displayModeBar":False})),
    ])


def build_targets(filt):
    tgt = filt.groupby("target_system").agg(total_score=("score","sum"), count=("severity","count")).reset_index()
    tgt = tgt.sort_values("total_score", ascending=False).head(10)
    tgt = tgt.rename(columns={"target_system": "system"})
    fig = px.bar(tgt, x="total_score", y="system",
                 orientation="h", color="count", color_continuous_scale="Reds")
    fig.update_layout(**PLOTLY_LAYOUT, height=360, showlegend=False,
                      title=dict(text="Top 10 Targeted Systems by Threat Score", font=dict(size=11,color="#475569")),
                      xaxis_title="Total Threat Score", yaxis_title="")
    fig.update_traces(marker_line_width=0)

    tgt2 = filt["target_system"].value_counts().head(8).reset_index()
    tgt2.columns = ["system","count"]
    pie = px.pie(tgt2, values="count", names="system", hole=0.4)
    pie.update_layout(**PLOTLY_LAYOUT, height=300,
                      title=dict(text="Target Distribution", font=dict(size=11,color="#475569")))
    pie.update_traces(textfont_size=9, textfont_color="#94a3b8",
                      marker=dict(line=dict(color=BG_DARK, width=2)))

    return html.Div([
        html.Div([
            card(dcc.Graph(figure=fig, config={"displayModeBar":False}), {"flex":"2","marginBottom":"0","marginRight":"12px"}),
            card(dcc.Graph(figure=pie, config={"displayModeBar":False}), {"flex":"1","marginBottom":"0"}),
        ], style={"display":"flex"}),
    ])


def build_anomaly(filt):
    daily = filt.groupby("date").size().reset_index(name="count")
    daily["rolling_mean"] = daily["count"].rolling(7, min_periods=1).mean()
    daily["rolling_std"]  = daily["count"].rolling(7, min_periods=1).std().fillna(0)
    daily["upper"] = daily["rolling_mean"] + 2 * daily["rolling_std"]
    daily["lower"] = (daily["rolling_mean"] - 2 * daily["rolling_std"]).clip(lower=0)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=daily["date"], y=daily["upper"], mode="lines",
                             line=dict(color="rgba(239,68,68,0.3)", width=1, dash="dot"),
                             name="Upper Bound"))
    fig.add_trace(go.Scatter(x=daily["date"], y=daily["lower"], mode="lines",
                             line=dict(color="rgba(239,68,68,0.3)", width=1, dash="dot"),
                             fill="tonexty", fillcolor="rgba(239,68,68,0.05)",
                             name="Normal Range"))
    fig.add_trace(go.Scatter(x=daily["date"], y=daily["rolling_mean"], name="7-Day Avg",
                             line=dict(color="#10b981", width=2, dash="dash"), mode="lines"))
    fig.add_trace(go.Scatter(x=daily["date"], y=daily["count"], name="Actual",
                             line=dict(color=ACCENT, width=2),
                             mode="lines+markers", marker=dict(size=4, color=ACCENT)))

    anomalies = daily[daily["count"] > daily["upper"]]
    if len(anomalies):
        fig.add_trace(go.Scatter(x=anomalies["date"], y=anomalies["count"],
                                 mode="markers", marker=dict(color="#ef4444", size=10, symbol="x"),
                                 name="Anomaly"))

    fig.update_layout(**PLOTLY_LAYOUT, height=380, hovermode="x unified",
                      title=dict(text="Anomaly Detection — 7-Day Rolling Average ± 2σ",
                                 font=dict(size=11,color="#475569")))

    return card(dcc.Graph(figure=fig, config={"displayModeBar":False}))


def build_threats(filt):
    top = filt.nlargest(10, "score")[
        ["timestamp","severity","score","country","attack_type","mitre","source_ip","target_system"]
    ]
    table = dash_table.DataTable(
        data=top.to_dict("records"),
        columns=[{"name": c, "id": c} for c in top.columns],
        sort_action="native",
        filter_action="native",
        style_table={"overflowX": "auto"},
        style_cell={"backgroundColor":"transparent","color":"#94a3b8",
                    "border":f"1px solid {BORDER}","textAlign":"left",
                    "padding":"9px 12px","fontSize":"10px","fontFamily":FONT_MONO,
                    "whiteSpace":"nowrap"},
        style_header={"backgroundColor":"rgba(255,255,255,0.025)","fontWeight":"700",
                       "border":f"1px solid {BORDER}","color":"#475569","fontSize":"9px",
                       "textTransform":"uppercase","letterSpacing":"0.1em"},
        style_data_conditional=[
            {"if":{"filter_query":"{severity} = 'Critical'"},
             "backgroundColor":"rgba(239,68,68,0.08)","color":"#fca5a5"},
            {"if":{"filter_query":"{severity} = 'High'"},
             "backgroundColor":"rgba(249,115,22,0.08)","color":"#fdba74"},
            {"if":{"column_id":"score"},"color":"#ef4444","fontWeight":"700"},
        ],
    )

    sev_counts = filt["severity"].value_counts()
    badges = html.Div([
        html.Div([
            html.Div(str(sev_counts.get(s,0)),
                     style={"fontSize":"28px","fontWeight":"700","color":SEV_COLORS[s],"fontFamily":FONT_MONO}),
            html.Div(s, style={"fontSize":"9px","color":"#475569","textTransform":"uppercase",
                               "letterSpacing":"0.1em","fontFamily":FONT_MONO,"marginTop":"2px"}),
        ], style={
            "background":BG_CARD, "border":f"1px solid {BORDER}",
            "borderLeft":f"3px solid {SEV_COLORS[s]}",
            "borderRadius":"12px","padding":"14px 18px","flex":"1",
        }) for s in ["Critical","High","Medium","Low"]
    ], style={"display":"flex","gap":"10px","marginBottom":"14px"})

    return html.Div([badges, card([section_title("Top 10 Threats by Score"), table])])


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 54)
    print("  🛡️   SOC Threat Intelligence Dashboard")
    print("  URL  → http://127.0.0.1:8050")
    print("=" * 54)
    app.run(host="127.0.0.1", port=8050, debug=True)
