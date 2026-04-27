"""
dashboard.py  –  SentinelMesh Dashboard
Original light purple / white theme + enhanced pages:
  Live Feed | Analytics | Blocked IPs | MITRE ATT&CK | Live Capture | Reports | Settings
"""

from __future__ import annotations

import os
import time

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
import streamlit.components.v1 as components

API_BASE = os.getenv("SENTINEL_API_BASE", "http://127.0.0.1:8000")


# ─── helpers ─────────────────────────────────────────────────────────────────

def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _get(path: str, default=None):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=4)
        return r.json() if r.ok else default
    except Exception:
        return default


def _post(path: str, **kwargs):
    try:
        r = requests.post(f"{API_BASE}{path}", timeout=6, **kwargs)
        return r.json() if r.ok else {}
    except Exception:
        return {}


def _post_simulation(path: str, attempts: int = 1) -> bool:
    for _ in range(attempts):
        try:
            resp = requests.post(f"{API_BASE}{path}", timeout=4)
            if resp.status_code >= 400:
                st.error(f"Simulation failed ({resp.status_code}). Check API terminal.")
                return False
        except requests.RequestException:
            st.error("Unable to reach API. Make sure uvicorn is running.")
            return False
    return True


def _incident_df(raw: list) -> pd.DataFrame:
    df = pd.DataFrame(raw or [])
    if df.empty:
        return df
    defaults = {
        "incident_id": "N/A", "timestamp": None, "severity": "UNKNOWN",
        "attack_pattern": "UNKNOWN", "anomaly_score": 0.0, "confidence": 0.0,
        "geo_country": "N/A", "blocked": False, "event": {},
        "recommended_action": "Review incident.", "mitre_tactic": "",
        "attack_type": "UNKNOWN",
    }
    for col, val in defaults.items():
        if col not in df.columns:
            df[col] = val
    df["event"] = df["event"].apply(_as_dict)
    return df


def _sev_color(sev: str) -> str:
    return {"CRITICAL": "#ff5f7a", "HIGH": "#ff9c45",
            "MEDIUM": "#f5c842", "LOW": "#23c380"}.get(sev, "#7081a0")


# ─── page config ─────────────────────────────────────────────────────────────

st.set_page_config(page_title="SentinelMesh Dashboard", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
  :root {
    --bg-main:    #f4f7ff;
    --card-white: #ffffff;
    --text-strong:#1f2a44;
    --text-soft:  #7081a0;
    --accent:     #6f6af8;
    --accent-2:   #8f8bff;
    --success:    #23c380;
    --danger:     #ff5f7a;
    --warn:       #ff9c45;
    --line:       #e8ecf9;
    --shadow:     0 10px 24px rgba(50,77,168,.12);
  }
  .stApp {
    background: radial-gradient(circle at 20% -20%,#e7ebff 0%,#f4f7ff 48%,#f6f8ff 100%);
    color: var(--text-strong);
  }
  section[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#ffffff 0%,#f6f8ff 100%);
    border-right: 1px solid var(--line);
  }
  .hero-wrap {
    background: linear-gradient(120deg,#6f6af8 0%,#908bff 55%,#5ec5ff 100%);
    border-radius: 20px; padding: 20px 24px;
    box-shadow: var(--shadow); margin-bottom: 1rem;
  }
  .hero-title { font-size:2rem; font-weight:800; color:#fff; margin-bottom:.15rem; }
  .hero-sub   { color:#eef2ff; font-size:.95rem; }
  .metric-card {
    background: var(--card-white); border:1px solid var(--line);
    border-radius:16px; padding:14px 16px; box-shadow:var(--shadow);
    transition: transform .2s ease;
  }
  .metric-card:hover { transform: translateY(-2px); }
  .metric-label { color:var(--text-soft); font-size:.82rem; font-weight:600; }
  .metric-value { color:var(--text-strong); font-size:1.8rem; font-weight:800; margin-top:3px; }
  .pill {
    display:inline-block; padding:4px 10px; border-radius:999px;
    font-size:.78rem; font-weight:700; margin-top:8px;
  }
  .pill-ok   { background:rgba(35,195,128,.14); color:var(--success); }
  .pill-risk { background:rgba(255,95,122,.14);  color:var(--danger);  }
  .pill-warn { background:rgba(255,156,69,.14);  color:var(--warn);    }
  .glass-card {
    background:rgba(255,255,255,.88); border:1px solid var(--line);
    border-radius:16px; padding:12px; box-shadow:var(--shadow);
  }
  .inc-row {
    background:#fff; border:1px solid var(--line); border-radius:12px;
    padding:10px 16px; margin-bottom:6px; box-shadow:0 2px 8px rgba(50,77,168,.06);
  }
  .sev-badge {
    display:inline-block; border-radius:6px; padding:2px 10px;
    font-size:.75rem; font-weight:700; letter-spacing:.5px;
  }
  .mitre-card {
    background:#fff; border:1px solid var(--line); border-radius:10px;
    padding:12px 18px; margin-bottom:8px; box-shadow:0 2px 8px rgba(50,77,168,.06);
  }
  .stDataFrame, .stPlotlyChart { border-radius:14px !important; overflow:hidden; border:1px solid var(--line); }
  .stButton > button {
    border-radius:10px; border:1px solid #dbe3ff; background:#ffffff;
    color:var(--text-strong) !important; font-weight:600;
    box-shadow:0 6px 14px rgba(37,63,148,.08);
  }
  .stButton > button:hover { border-color:#a4b8ff; transform:translateY(-1px); }
  .stTabs [data-baseweb="tab-list"] button { font-weight:700; color:#7a8bac; }
  .stTabs [aria-selected="true"] { color:var(--accent) !important; }
</style>
""", unsafe_allow_html=True)

# Animated pulse line
components.html("""
<div id="pulse" style="height:3px;width:100%;background:linear-gradient(90deg,#0ea5e9,#6366f1,#22d3ee);border-radius:8px;opacity:.8"></div>
<script>
const el=document.getElementById("pulse"); let n=0;
setInterval(()=>{ n+=.08; el.style.filter=`brightness(${60+Math.sin(n)*35}%)`; },60);
</script>""", height=20)

# Hero banner
st.markdown("""
<div class="hero-wrap">
  <div class="hero-title">🛡️ SentinelMesh Control Dashboard</div>
  <div class="hero-sub">Real-time anomaly defense · AI-powered threat detection · Policy-first response</div>
</div>
""", unsafe_allow_html=True)


# ─── sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## Workspace")
    st.caption("SOC operator controls")

    health = _get("/health", {})
    status_dot = "🟢" if health.get("status") == "ok" else "🔴"
    model_src  = health.get("model_source", "N/A").upper()
    uptime     = int(health.get("uptime_seconds", 0))
    cap_active = health.get("capture_active", False)

    st.markdown(f"{status_dot} API: **{'Online' if health.get('status')=='ok' else 'Offline'}**")
   
    st.markdown(f"⏱ Uptime: **{uptime}s**")
    st.markdown(f"📡 Capture: **{'ON' if cap_active else 'OFF'}**")
    st.markdown("---")

    page = st.radio("Navigation", [
        "🔴 Live Feed", "📊 Analytics", "🚫 Blocked IPs",
        "🎯 MITRE ATT&CK", "📡 Live Capture", "📄 Reports", "⚙️ Settings",
    ], label_visibility="collapsed")

    st.markdown("---")
    refresh       = st.button("🔄 Refresh Data",           use_container_width=True)
    sim_mixed     = st.button("🌐 Simulate Mixed Traffic",  use_container_width=True)
    sim_attack    = st.button("💥 Simulate Attack Burst",   use_container_width=True)
    sim_bulk      = st.button("📦 Generate 40 Demo Events", use_container_width=True)
    gen_report    = st.button("📄 Generate 24h Report",     use_container_width=True)
    st.markdown("---")
    auto_refresh   = st.checkbox("Auto refresh every 3s", value=False)
    incident_limit = st.slider("Incidents to view", 20, 500, 120, 20)

if sim_mixed:
    _post_simulation("/simulate", attempts=4)
if sim_attack:
    _post_simulation("/simulate?force_anomaly=true", attempts=12)
if sim_bulk:
    ok = all(_post_simulation(f"/simulate?force_anomaly={'true' if i%3==0 else 'false'}") for i in range(40))
    if ok:
        st.success("Generated 40 demo events.")
if gen_report:
    result = _post("/reports/generate?hours=24")
    st.success(f"Report saved: `{result['report_path']}`") if "report_path" in result else st.error("Failed.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Live Feed
# ══════════════════════════════════════════════════════════════════════════════

if page == "🔴 Live Feed":
    metrics = _get("/metrics", {})
    inc_raw = _get(f"/incidents?limit={incident_limit}", [])
    ev_raw  = _get("/events?limit=200", [])

    if not health.get("model_loaded"):
        st.warning("Model not loaded. Run: `python trainer.py`")

    critical_count = sum(1 for i in inc_raw if i.get("severity") == "CRITICAL")
    kpi_data = [
        ("Total Events",    metrics.get("total_events", 0),    "pill-ok",   "Live"),
        ("Incidents",       metrics.get("total_incidents", 0), "pill-risk", "Review"),
        ("Blocked IPs",     metrics.get("blocked_ips", 0),     "pill-ok",   "Secured"),
        ("Critical Alerts", critical_count,                     "pill-risk", "Urgent"),
    ]
    cols = st.columns(4)
    for col, (label, val, pill_cls, pill_txt) in zip(cols, kpi_data):
        with col:
            st.markdown(f"""
<div class="metric-card">
  <div class="metric-label">{label}</div>
  <div class="metric-value">{val}</div>
  <span class="pill {pill_cls}">{pill_txt}</span>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    bc1, bc2, bc3, bc4, bc5 = st.columns(5)
    if bc1.button("⚡ Random"):
        _post("/simulate"); st.rerun()
    if bc2.button("🔴 Force Anomaly"):
        _post("/simulate?force_anomaly=true"); st.rerun()
    if bc3.button("🔑 Brute Force"):
        _post("/simulate/attack", json={"attack_type": "BRUTE_FORCE"}); st.rerun()
    if bc4.button("💣 DDoS"):
        _post("/simulate/attack", json={"attack_type": "DDOS"}); st.rerun()
    if bc5.button("📤 Exfiltration"):
        _post("/simulate/attack", json={"attack_type": "EXFIL"}); st.rerun()

    st.markdown("---")
    tab1, tab2, tab3, tab4 = st.tabs(["Incidents", "Traffic Timeline", "Blocked IPs", "Analyst View"])

    with tab1:
        if not inc_raw:
            st.warning("No incidents yet. Click 'Simulate Attack Burst' or any button above.")
        else:
            df = _incident_df(inc_raw)
            for _, row in df.sort_values("timestamp", ascending=False).head(50).iterrows():
                sev   = row.get("severity", "LOW")
                color = _sev_color(sev)
                ts    = str(row.get("timestamp", ""))[:19]
                blocked_tag = "🚫 BLOCKED" if row.get("blocked") else ""
                ev    = _as_dict(row.get("event", {}))
                st.markdown(f"""
<div class="inc-row" style="border-left:4px solid {color}">
  <span class="sev-badge" style="background:{color}20;color:{color}">{sev}</span>
  &nbsp;<b>{row.get("attack_pattern","UNKNOWN")}</b>&nbsp;
  <code>{ev.get("src_ip","?")} → {ev.get("dst_ip","?")}:{ev.get("dst_port","?")}</code>
  &nbsp;score=<code>{row.get("anomaly_score",0):.3f}</code>
  conf=<code>{row.get("confidence",0):.0%}</code>
  <span style="color:var(--text-soft);font-size:.8rem"> {ts}</span>
  <span style="color:var(--danger);font-size:.8rem"> {blocked_tag}</span>
</div>""", unsafe_allow_html=True)

            c1, c2 = st.columns(2)
            with c1:
                sev_df = df["severity"].value_counts().reset_index()
                sev_df.columns = ["severity", "count"]
                fig = px.pie(sev_df, values="count", names="severity", title="Severity Breakdown",
                             color_discrete_sequence=["#6f6af8","#23c380","#ff9c45","#ff5f7a"])
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
                st.plotly_chart(fig, use_container_width=True)
            with c2:
                proto_df = df["event"].apply(lambda x: _as_dict(x).get("protocol","UNKNOWN")).value_counts().reset_index()
                proto_df.columns = ["protocol", "count"]
                fig2 = px.bar(proto_df, x="protocol", y="count", title="Protocol Distribution",
                              color_discrete_sequence=["#8f8bff"])
                fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
                st.plotly_chart(fig2, use_container_width=True)

    with tab2:
        if ev_raw:
            ev = pd.DataFrame(ev_raw)
            ev["timestamp"] = pd.to_datetime(ev["timestamp"])
            ev["minute"]    = ev["timestamp"].dt.floor("min")
            grouped = ev.groupby(["minute","result"]).size().reset_index(name="count")
            fig3 = px.line(grouped, x="minute", y="count", color="result", markers=True,
                           color_discrete_sequence=["#23c380","#ff5f7a","#6f6af8"])
            fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig3, use_container_width=True)
            st.dataframe(ev.tail(40), use_container_width=True)
        else:
            st.write("No event data yet.")

    with tab3:
        blocked = _get("/blocked-ips", [])
        if blocked:
            st.dataframe(pd.DataFrame(blocked), use_container_width=True)
        else:
            st.success("No IPs currently blocked.")

    with tab4:
        if inc_raw:
            latest    = inc_raw[-1] if isinstance(inc_raw[-1], dict) else {}
            latest_ev = _as_dict(latest.get("event", {}))
            st.json({
                "incident_id":        latest.get("incident_id"),
                "severity":           latest.get("severity"),
                "attack_type":        latest.get("attack_type"),
                "pattern":            latest.get("attack_pattern"),
                "score":              latest.get("anomaly_score"),
                "source":             latest_ev.get("src_ip"),
                "destination":        latest_ev.get("dst_ip"),
                "mitre_tactic":       latest.get("mitre_tactic"),
                "recommended_action": latest.get("recommended_action"),
            })
            st.markdown("#### Top Risk Sources")
            df = _incident_df(inc_raw)
            src_counts = df["event"].apply(lambda x: _as_dict(x).get("src_ip","N/A")).value_counts().head(5)
            st.dataframe(src_counts.rename_axis("src_ip").reset_index(name="incident_count"), use_container_width=True)
        else:
            st.write("No incidents yet.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Analytics
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📊 Analytics":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">📊 Analytics</div>', unsafe_allow_html=True)
    inc_raw = _get(f"/incidents?limit=500", [])
    df = _incident_df(inc_raw)

    if df.empty:
        st.info("No data yet. Generate events from the Live Feed page.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            sev_df = df["severity"].value_counts().reset_index(); sev_df.columns = ["Severity","Count"]
            cmap   = {"CRITICAL":"#ff5f7a","HIGH":"#ff9c45","MEDIUM":"#f5c842","LOW":"#23c380"}
            fig = px.bar(sev_df, x="Severity", y="Count", color="Severity",
                         color_discrete_map=cmap, title="Incidents by Severity")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            ap_df = df["attack_pattern"].value_counts().head(8).reset_index(); ap_df.columns = ["Pattern","Count"]
            fig2  = px.pie(ap_df, values="Count", names="Pattern", title="Attack Pattern Distribution",
                           color_discrete_sequence=px.colors.qualitative.Bold)
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig2, use_container_width=True)

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df_t = df.set_index("timestamp").resample("1min")["severity"].count().reset_index()
            df_t.columns = ["Time","Events"]
            fig3 = px.area(df_t, x="Time", y="Events", title="Incident Timeline (1-min bins)",
                           color_discrete_sequence=["#6f6af8"])
            fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig3, use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            geo = df["geo_country"].dropna().value_counts().head(10).reset_index(); geo.columns = ["Country","Count"]
            fig4 = px.bar(geo, x="Count", y="Country", orientation="h",
                          title="Top Attack Origins", color_discrete_sequence=["#ff5f7a"])
            fig4.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig4, use_container_width=True)
        with c4:
            fig5 = px.histogram(df["anomaly_score"].dropna(), nbins=30,
                                title="Anomaly Score Distribution",
                                color_discrete_sequence=["#6f6af8"])
            fig5.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#2a3655")
            st.plotly_chart(fig5, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Blocked IPs
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🚫 Blocked IPs":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">🚫 Blocked IPs</div>', unsafe_allow_html=True)
    blocked = _get("/blocked-ips", [])
    if not blocked:
        st.success("No IPs currently blocked.")
    else:
        st.dataframe(pd.DataFrame(blocked), use_container_width=True)
        st.markdown("---")
        st.markdown("### Unblock an IP")
        ip_in = st.text_input("Enter IP address")
        if st.button("Unblock") and ip_in:
            r = _post(f"/unblock/{ip_in.strip()}")
            st.success(f"✅ {ip_in} unblocked.") if "unblocked" in r else st.error("IP not found.")
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: MITRE ATT&CK
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🎯 MITRE ATT&CK":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">🎯 MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
    st.caption("Which ATT&CK tactics have been observed in detected incidents.")

    inc_raw  = _get("/incidents?limit=500", [])
    df       = _incident_df(inc_raw)
    observed = set(df["mitre_tactic"].dropna().unique()) if not df.empty else set()

    MITRE = {
        "TA0007 – Discovery":           ("Recon / port scanning",           "#9b59b6"),
        "TA0006 – Credential Access":   ("Brute-force / auth attacks",      "#e74c3c"),
        "TA0040 – Impact":              ("DoS / DDoS traffic floods",        "#e67e22"),
        "TA0010 – Exfiltration":        ("Unusual large outbound data",      "#3498db"),
        "TA0011 – Command and Control": ("C2 beaconing patterns",            "#1abc9c"),
        "TA0001 – Initial Access":      ("Suspicious web / exploit traffic", "#f39c12"),
        "TA0003 – Persistence":         ("Repeated attacker patterns",       "#e74c3c"),
        "TA0043 – Reconnaissance":      ("Unknown anomalies / probing",      "#7081a0"),
    }

    for tactic, (desc, color) in MITRE.items():
        hit   = tactic in observed
        count = df[df["mitre_tactic"] == tactic].shape[0] if not df.empty else 0
        border = color if hit else "#e8ecf9"
        badge  = (f'<span style="background:{color};color:#fff;padding:2px 9px;border-radius:6px;font-size:.72rem;font-weight:700">DETECTED ×{count}</span>'
                  if hit else '<span style="color:#aab4cc;font-size:.75rem">Not observed</span>')
        st.markdown(f"""
<div class="mitre-card" style="border-left:4px solid {border}">
  <b style="color:{color}">{tactic}</b> &nbsp; {badge}<br>
  <span style="color:var(--text-soft);font-size:.85rem">{desc}</span>
</div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Live Capture
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📡 Live Capture":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">📡 Live Network Capture</div>', unsafe_allow_html=True)
    cap      = _get("/capture/status", {})
    active   = cap.get("active", False)
    scapy_ok = cap.get("scapy_available", False)

    st.markdown(f"**Scapy available:** {'✅ Yes' if scapy_ok else '❌ No — run: `pip install scapy`'}")
    st.markdown(f"**Capture status:** {'🟢 Running' if active else '⚪ Stopped'}")
    st.markdown(f"**Interface:** `{cap.get('interface','N/A')}`")
    st.markdown("---")

    if not scapy_ok:
        st.warning("Install Scapy: `pip install scapy`\nLinux/macOS needs root. Windows needs Npcap.")
    else:
        iface = st.text_input("Network interface", value=cap.get("interface","eth0"),
                              help="e.g. eth0, Wi-Fi, en0, Ethernet")
        c1, c2 = st.columns(2)
        if c1.button("▶ Start Live Capture", disabled=active):
            r = _post(f"/capture/start?interface={iface}")
            st.success("Capture started!") if r.get("status") == "started" else st.error(str(r))
            st.rerun()
        if c2.button("⏹ Stop Capture", disabled=not active):
            _post("/capture/stop"); st.info("Stopping…"); st.rerun()

    st.info("💡 Requires **root / admin** privileges.\n"
            "Linux: `sudo streamlit run dashboard.py`\n"
            "Windows: run as Administrator + install [Npcap](https://npcap.com)")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Reports
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📄 Reports":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">📄 Forensic Report Generator</div>', unsafe_allow_html=True)
    hours = st.slider("Report time window (hours)", 1, 168, 24)
    if st.button("📄 Generate Report"):
        with st.spinner("Generating…"):
            result = _post(f"/reports/generate?hours={hours}")
        if "report_path" in result:
            path = result["report_path"]
            st.success(f"✅ Saved: `{path}`")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                st.code(content, language="text")
                st.download_button("⬇️ Download Report", content, file_name=path.split("/")[-1])
            except FileNotFoundError:
                st.warning("Report is on server side. Check `reports/` folder.")
        else:
            st.error("Failed. Is the API running?")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Settings
# ══════════════════════════════════════════════════════════════════════════════

elif page == "⚙️ Settings":
    st.markdown('<div class="hero-title" style="font-size:1.4rem">⚙️ Settings & Model</div>', unsafe_allow_html=True)
    st.markdown(f"**Model source:** `{health.get('model_source','N/A')}`")
    st.markdown(f"**Model loaded:** {'✅ Yes' if health.get('model_loaded') else '❌ No — run trainer.py'}")
    st.markdown("---")
    st.markdown("### 🔄 Retrain Model")
    ds = st.text_input("Kaggle CSV path (blank = synthetic)", placeholder="/path/to/CICIDS2017.csv")
    if st.button("🚀 Start Training"):
        r = _post("/train", params={"dataset_path": ds})
        st.success(f"Training started – dataset: {r.get('dataset_path','?')}")
    st.markdown("---")
    st.markdown("### 📋 API Reference")
    st.code("""GET  /health           – system health
GET  /metrics          – detection stats
GET  /incidents        – recent incidents
GET  /events           – raw event log
GET  /blocked-ips      – firewall blocks
POST /simulate         – random event
POST /simulate/attack  – specific attack type
POST /ingest           – real NetworkEvent
POST /unblock/{ip}     – remove from blocklist
POST /train            – retrain model
POST /capture/start    – start live Scapy capture
POST /capture/stop     – stop capture
POST /reports/generate – forensic report""", language="text")


# ─── auto-refresh ─────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(3)
    st.rerun()
