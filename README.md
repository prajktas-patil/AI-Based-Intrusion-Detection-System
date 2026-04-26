# SentinelMesh: AI Network Security Guard

SentinelMesh is a real-time, anomaly-based network defense platform designed for small teams and modern enterprises.  
It combines adaptive AI detection, precision alerting, and controlled auto-response to reduce mean-time-to-detect (MTTD) and mean-time-to-respond (MTTR).

## Why This Project Stands Out

- **Zero-day focused:** Learns normal behavior and flags unknown threats without signature updates.
- **Human-centered security UX:** Minimal, bilingual-ready dashboard design
- **Safe automation:** Policy-based auto-blocking with whitelists, cooldown windows, and explainable evidence.
- **Forensic-first design:** Structured event logs and timeline-ready evidence for post-incident analysis.
- **Production-minded architecture:** API-first, modular services, typed schemas, and extensible detection pipeline.

## Target Users

- **SMB Security Teams:** Need practical defense without large SOC budgets.
- **IT Admins / SREs:** Need low-noise alerts and fast triage during incidents.
- **University Labs / R&D Networks:** Need anomaly detection against unknown traffic patterns.
  

## Core Problem and Solution

**Problem:** Traditional signature-based tools miss novel attacks and overwhelm teams with noisy alerts.  
**Solution:** SentinelMesh uses unsupervised anomaly detection with explainable scoring, real-time alert orchestration, and optional firewall response to stop suspicious activity fast and safely.

## Global-Grade Product Design (Minimal + Precise)

- **Layout:** Left nav, top status strip, right-side detail drawer for selected incident.
- **Views:** Live feed, Incident timeline, Blocked IPs, Investigation detail, Policy settings.
- **Design language:** Neutral palette, subtle color semantics, high information density with low cognitive load.
- **Interaction principles:**
  - One primary action per screen.
  - Alert cards prioritize `severity`, `confidence`, and `recommended action`.
  - Keyboard-friendly operations for analyst workflows.
- **Localization readiness:** Content keys and date/number formatting prepared for i18n.

## Recommended Tech Stack

- **Frontend:** Next.js (TypeScript), Tailwind CSS, Recharts, TanStack Query
- **Backend API:** FastAPI + Pydantic + Uvicorn
- **Streaming/Event Bus:** Redis Streams (or Kafka in advanced setup)
- **Database:** PostgreSQL (incidents, policies), TimescaleDB extension for event metrics
- **AI/ML:** scikit-learn (IsolationForest), pandas, numpy
- **Packet Capture:** PyShark / Scapy
- **Background Jobs:** Celery + Redis (alerts, reports, cleanup)
- **Ops:** Docker Compose, Prometheus, Grafana, GitHub Actions

## Suggested Folder Structure

```text
sentinelmesh/
  backend/
    app/
      api/
      core/
      detection/
      capture/
      response/
      schemas/
      services/
      db/
    tests/
  frontend/
    src/
      app/
      components/
      features/
      lib/
  infra/
    docker/
    k8s/
  docs/
    architecture.md
    threat-model.md
```

## System Flow

1. **Capture:** Packet/flow metadata is ingested from network interfaces.
2. **Feature Engineering:** Extract protocol, byte, time-window, host behavior features.
3. **Detection:** IsolationForest generates anomaly score and label.
4. **Correlation:** Events deduplicated + grouped by source/attack pattern.
5. **Decision Engine:** Rule policy decides alerting and optional auto-block.
6. **Notification:** Telegram/Email/Slack/SMS based on severity policy.
7. **Persistence + Dashboard:** Incident data stored and visualized in real time.

## MVP Features

- Real-time network anomaly detection
- Severity scoring and explainable alert context
- Live incident feed (API + dashboard)
- Basic policy engine (threshold + cooldown + whitelist)
- Telegram/email alert integration
- Incident logging and CSV/JSON export

## Advanced Features (Recruiter-Wow)

- eBPF-based telemetry collector (Linux)
- Hybrid detection (IsolationForest + rules + sequence model)
- Risk scoring with MITRE ATT&CK tactic mapping
- Adaptive thresholds by time-of-day baseline
- Multi-tenant architecture with RBAC
- SOAR-style playbooks (block, isolate, ticket, notify)
- Japanese/English UI localization
- Security scorecard and executive weekly report generator

## Implementation Roadmap

### Phase 1 - Foundation (Week 1)
- Define data schema, config, and service boundaries
- Build packet feature pipeline
- Train baseline model and evaluation script

### Phase 2 - Detection Core (Week 2)
- Real-time detector loop
- Incident object generation
- Rule policy engine for severity and escalation

### Phase 3 - Product Layer (Week 3)
- FastAPI endpoints (`/health`, `/incidents`, `/metrics`)
- Streamlit or Next.js dashboard prototype
- Alert integration (Telegram/email) and retries

### Phase 4 - Reliability (Week 4)
- Docker setup, structured logs, tests
- CI pipeline, linting, formatting
- Documentation, demo scenarios, performance tuning

### Phase 5 - Portfolio Polish (Week 5)
- Add architecture diagrams and benchmark metrics
- Record short product demo video
- Publish results and impact narrative

## Starter Modules Included

- `security_config.py` - centralized settings
- `models.py` - typed domain models
- `detector.py` - anomaly detector service
- `alerting.py` - notification + policy control
- `trainer.py` - baseline model training
- `api_server.py` - FastAPI endpoints
- `dashboard.py` - Streamlit monitoring view


## Quick Start

```bash
pip install -r requirements.txt
python trainer.py
uvicorn api_server:app --reload
streamlit run dashboard.py
```

## Enhanced Runtime

```bash
pip install -r requirements_enhanced.txt
python trainer.py
python run_enhanced.py
uvicorn api_server:app --reload
streamlit run dashboard.py
python model_evaluator.py
```

### Enhanced Modules

- `config_enhanced.py`: production-style config for firewall, notifications, and reports
- `packet_sniffer.py`: simulation + optional live PyShark capture
- `alert_manager_enhanced.py`: correlation, pattern tagging, multi-channel alerts, auto-block
- `firewall_manager.py`: block/unblock lifecycle and expiry handling
- `forensic_logger.py`: telemetry/incident logs + report generation
- `model_evaluator.py`: baseline model quality report
- `run_enhanced.py`: CLI monitoring entrypoint

---

Built for high signal, low noise, and real-world incident response.
