# SOC Sentinel — Alert Triage & Response Automation Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-FortiSOAR--Inspired-orange.svg)]()
[![Safety](https://img.shields.io/badge/Safety-Dry--Run%20Simulation-success.svg)]()
[![Tests](https://img.shields.io/badge/Tests-73%20Passing-brightgreen.svg)]()
[![UI](https://img.shields.io/badge/Console-Streamlit%20Dark%20Theme-red.svg)]()

A modular, Python-based Security Operations Center (SOC) alert triage, risk scoring, and automated response orchestration engine inspired by **FortiSOAR Playbook Architecture**.

Designed as a demonstration and portfolio platform for cybersecurity engineering, SOC Sentinel automates alert ingestion, contextual enrichment, transparent risk calculation, conditional playbook routing, response containment simulation, lifecycle incident tracking, and granular execution tracing — with zero external runtime dependencies for core CLI execution and a dedicated Streamlit operations dashboard.

---

## 1. High-Level Architecture & Pipeline Workflow

The pipeline models a modern Security Orchestration, Automation, and Response (SOAR) architecture:

```
[Raw Alert Telemetry JSON]
           │
           ▼
┌─────────────────────────┐
│     Alert Processor     │ ──► Schema validation (10 required fields), type & timestamp checks
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│    Enrichment Engine    │ ──► RFC1918 classification, mock Threat Intel, privileged user & critical asset tags
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│       Risk Engine       │ ──► Deduplicated 0–100 weighted scoring (Base + Threat Intel + Assets + Behavior)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│     Playbook Engine     │ ──► Conditional workflow branching (PB-CRIT-001, PB-HIGH-002, PB-MED-003, PB-LOW-004)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│    Response Simulator   │ ──► Generates analyst-gated containment actions (Isolation, Account Lock, IP Block)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│     Incident Manager    │ ──► Formal incident tracking (INC-YYYYMMDD-XXXX) with state machine transitions
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│     Audit & Tracing     │ ──► Structured JSON/CSV reports, audit logs, and microsecond-level execution traces
└─────────────────────────┘
```

---

## 2. FortiSOAR Playbook Alignment

| SOAR Concept | FortiSOAR Architecture Equivalent | SOC Sentinel Implementation |
| :--- | :--- | :--- |
| **Trigger Step** | Alert Ingestion Trigger (File / Webhook / API) | `AlertProcessor`: Schema validation, normalization, and quality checks |
| **Context Enrichment** | Threat Intel & Directory Connector Steps | `EnrichmentModule`: Mock threat intel reputation, IP classification, and asset tagging |
| **Decision Branch** | Decision Node / Condition Gate | `RiskScoringEngine` & `PlaybookEngine`: Conditional branch routing (`>=80`, `>=60`, `>=30`, `<30`) |
| **Referenced Playbooks**| Modular Child / Sub-Playbooks | `PB-CRIT-001`, `PB-HIGH-002`, `PB-MED-003`, `PB-LOW-004` |
| **Containment Actions** | Connector Execution Steps (EDR, Firewall, IAM) | `ResponseSimulator`: Dry-run simulation with strict analyst-approval safeguards |
| **Case Management** | Incident Module & Record Lifecycle | `IncidentManager`: Formal state machine (`NEW` $\rightarrow$ `ASSIGNED` $\rightarrow$ `IN_PROGRESS` $\rightarrow$ `RESOLVED` / `CLOSED`) |
| **Execution Governance**| Playbook Execution History & Audit Logs | `ExecutionTracer` & `AuditLogger`: Microsecond-resolution execution steps & tamper-evident audit history |

---

## 3. Key Capabilities

- **Strict Schema Validation & Quality Assessment**:
  Validates 10 core alert fields (`alert_id`, `timestamp`, `event_source`, `severity`, `title`, `description`, `source_ip`, `destination_ip`, `user`, `hostname`) with ISO 8601 parsing and non-blocking data quality warnings.
- **Contextual Threat Intelligence Enrichment**:
  Maps external indicators against threat intelligence databases, identifies RFC1918 private vs. public IP addresses, and flags privileged identities (`admin`, `svc-backup`, `root`) and critical infrastructure (`dc01.corp.internal`, `vpn-gateway-01`).
- **Deduplicated 0–100 Weighted Risk Scoring**:
  Calculates risk deterministically without double-counting factors. Base severity points are supplemented by specific behavioral indicators (e.g., suspicious PowerShell flags `-enc`, repeated failed logins, threat intel hits) capped at 100.
- **Conditional Playbook Routing**:
  - `PB-CRIT-001` (Score $\ge$ 80): Critical containment & automated tier-2 escalation.
  - `PB-HIGH-002` (Score $\ge$ 60): High-risk tier-1 analyst review & firewall perimeter block.
  - `PB-MED-003` (Score $\ge$ 30): Medium triage queue placement & data quality checks.
  - `PB-LOW-004` (Score $<$ 30): Low-priority telemetry logging, noise suppression & auto-archive.
- **Safe Dry-Run Response Containment**:
  Simulates remediation commands (EDR host isolation, Active Directory account lockout, firewall IP block) marked `SIMULATED_PENDING_APPROVAL`. Commands are never executed against live systems.
- **Incident Lifecycle State Machine**:
  Tracks formal incident records with unique incident IDs, priority rankings, assignment workflows, and validated status transitions with mandatory resolution notes.
- **Microsecond Execution Traces**:
  Records step-by-step execution metrics including module entry, parameter values, execution timing in milliseconds, and status transitions for complete post-incident review.
- **Streamlit SOC Operations Console**:
  A dark-themed SOC operations interface featuring:
  - **SOC Overview**: High-level telemetry, severity distributions, and incident posture metrics.
  - **Alert Management**: Filterable alert explorer with master-detail telemetry inspection and non-mutating preview.
  - **Playbook Center**: Playbook catalog, real-time compatibility validation, analyst approval safety gate, simulation execution, and execution trace inspection.

---

## 4. Repository Structure

```
soc-automation/
├── config/
│   ├── enrichment_db.json        # Mock Threat Intel, privileged users & critical assets
│   └── rules.json                # Risk scoring weights and threshold definitions
├── data/
│   └── alerts/                   # Realistic demonstration alert fixtures
│       ├── 01_failed_logins_suspicious_ip.json
│       ├── 02_powershell_windows_endpoint.json
│       ├── 03_privileged_account_anomaly.json
│       ├── 04_low_risk_info.json
│       └── 05_missing_fields_alert.json
├── logs/                         # Runtime logs directory (soc_automation.log)
├── modules/                      # Core pipeline and orchestration engine
│   ├── __init__.py
│   ├── alert_processor.py        # Telemetry ingestion and schema validation
│   ├── audit_logger.py           # Structured event logging
│   ├── enrichment.py             # IP, identity, and threat intelligence context
│   ├── execution_tracer.py       # Playbook step tracing and timing metrics
│   ├── incident_manager.py       # Incident entities and lifecycle state machine
│   ├── pipeline.py               # SOCTriagePipeline central coordinator
│   ├── playbook_engine.py        # Playbook definitions and conditional gates
│   ├── reporter.py               # Incident export to JSON and CSV summaries
│   ├── response_simulator.py     # Safe dry-run mitigation actions
│   └── risk_engine.py            # Deduplicated scoring algorithm
├── reports/                      # Runtime incident exports and CSV summaries
├── tests/                        # Comprehensive unit and integration test suite
│   ├── test_alert_processor.py
│   ├── test_audit_logger.py
│   ├── test_end_to_end.py
│   ├── test_enrichment.py
│   ├── test_execution_tracer.py
│   ├── test_incident_manager.py
│   ├── test_pipeline.py
│   ├── test_playbook_center.py
│   ├── test_playbook_engine.py
│   ├── test_risk_engine.py
│   ├── test_soc_service.py
│   ├── test_theme.py
│   └── test_views_step23a.py
├── ui/                           # Streamlit Web Operations Console
│   ├── __init__.py
│   ├── app.py                    # Streamlit entry point and routing
│   ├── services/
│   │   ├── __init__.py
│   │   └── soc_service.py        # UI-to-backend service adapter
│   ├── styles/
│   │   ├── __init__.py
│   │   └── theme.py              # Dark SOC theme tokens and SVG components
│   └── views/
│       ├── __init__.py
│       ├── alerts_view.py         # Master-detail alert explorer
│       ├── overview_view.py       # Global SOC dashboard
│       └── playbook_view.py       # Playbook catalog & execution console
├── .gitignore                    # Production git hygiene exclusions
├── main.py                       # CLI application entry point
├── README.md                     # Project documentation
└── requirements.txt              # Dependency specification (Streamlit optional UI)
```

---

## 5. Technology Stack

- **Language**: Python 3.10+ (Standard Library only for CLI pipeline and tests)
- **Web Console**: Streamlit 1.30+
- **Data Formats**: JSON (Alerts, Rules, Incident Exports), CSV (Executive Summaries)
- **Testing Framework**: Python `unittest` standard library

---

## 6. Installation & Quick Start

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/your-username/soc-sentinel.git
cd soc-sentinel

# Create and activate a virtual environment
python3 -m venv .venv

# On macOS/Linux:
source .venv/bin/activate

# On Windows:
# .venv\Scripts\activate
```

### 2. Install Dependencies

The core CLI and test suite require **no external dependencies**. To run the interactive web dashboard:

```bash
pip install -r requirements.txt
```

---

## 7. Usage Guide

### Running via Command Line Interface (CLI)

#### Process All Sample Alerts (with Detailed Execution Traces)
```bash
python3 main.py
```

#### Process a Specific Alert Scenario
```bash
python3 main.py --file data/alerts/02_powershell_windows_endpoint.json
```

#### Run in Quiet Mode (Summary Table Only)
```bash
python3 main.py --no-trace
```

### Running the Streamlit Operations Console

Launch the web console:
```bash
streamlit run ui/app.py
```

Navigate to `http://localhost:8501` in your browser.

#### Console Navigation:
1. **SOC Overview**: View overall alert distribution, processed incidents, and severity breakdowns.
2. **Alert Management**: Filter alerts by source or severity, review raw and normalized telemetry, and run non-mutating preview risk evaluations.
3. **Playbook Center**:
   - Filter playbooks by severity or execution mode.
   - Select an alert to view real-time compatibility and recommended playbook routing.
   - Review execution prerequisites and simulated mitigation actions.
   - Check the **Analyst Confirmation** gate and click **Execute Playbook** to run the simulation.
   - Inspect the created incident ID, simulated actions, and granular execution trace.

---

## 8. Test Scenarios Included

| Scenario File | Description | Risk Score | Routed Playbook | Simulated Actions |
| :--- | :--- | :--- | :--- | :--- |
| `01_failed_logins_suspicious_ip.json` | 50 failed VPN logins from known malicious external IP (`198.51.100.45`) | **95 (CRITICAL)** | `PB-CRIT-001` | PagerDuty Tier-2 notify, EDR host isolation, AD account suspension |
| `02_powershell_windows_endpoint.json` | Encoded PowerShell command executing network beaconing to C2 IP | **95 (CRITICAL)** | `PB-CRIT-001` | PagerDuty Tier-2 notify, EDR host isolation, AD account suspension |
| `03_privileged_account_anomaly.json` | Interactive domain admin login on critical Domain Controller `dc01` | **65 (HIGH)** | `PB-HIGH-002` | Tier-1 analyst ticket, perimeter firewall IP block |
| `04_low_risk_info.json` | Standard print spooler service restart on internal workstation | **10 (LOW)** | `PB-LOW-004` | Baseline telemetry archive, noise suppression |
| `05_missing_fields_alert.json` | IDS alert with missing source IP and blank username | **35 (MEDIUM)** | `PB-MED-003` | Data quality penalty, tier-1 triage investigation ticket |

---

## 9. Running Automated Tests

Run the complete test suite (73 passing tests covering unit, integration, UI bridge, and safety rules):

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Expected output:
```text
Ran 73 tests in 0.105s

OK
```

---

## 10. Safety Guardrails & Operational Scope

> [!IMPORTANT]
> **Educational & Demonstration Prototype**:
> - **Dry-Run Containment**: All mitigation actions (`ENDPOINT_ISOLATION`, `ACCOUNT_SUSPENSION`, `IP_BLOCK`) are strictly simulated. No network commands, API calls, or configuration changes are made to live systems.
> - **Synthetic Threat Intelligence**: IP reputation feeds and asset directories are read from local JSON configurations (`config/enrichment_db.json`).
> - **No Direct SIEM/EDR Integrations**: The prototype does not connect directly to live SIEMs (Splunk/Sentinel) or EDR agents (CrowdStrike/Defender).
> - **In-Memory Session Persistence**: When running the Streamlit console, incident and trace updates are retained within the active service instance and exported to local reports.

---

## 11. Roadmap & Future Enhancements

- [ ] **MITRE ATT&CK Matrix Mapping**: Tag alerts and playbooks with formal tactic and technique identifiers (e.g., T1059, T1078).
- [ ] **REST API Interface**: FastAPI wrapper exposing endpoints for alert ingestion webhooks and incident queries.
- [ ] **Database Persistence**: SQLite/PostgreSQL storage layer for persistent cross-session incident records.
- [ ] **Connector Extensibility**: Pluggable connector interface for live SIEM webhook receivers and sandbox environments.
- [ ] **Expanded Playbook Library**: Additional workflows for phishing triage, cloud IAM privilege escalation, and ransomware containment.

---

## 12. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
