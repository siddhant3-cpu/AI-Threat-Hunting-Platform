# ASATL - AI-Powered Threat Hunting & Detection Platform

ASATL (AI-Powered Threat Hunting & Detection Platform) is an advanced, recruiter-level cybersecurity portfolio project that simulates a real-world **Security Operations Center (SOC)** console. It features automated simulated log ingestion, a lightweight **Sigma Rule Detection Engine**, a **Real-Time Alerts Correlation Engine** that groups telemetry into incidents, interactive **MITRE ATT&CK Tactics Mapping**, and automatic indicator enrichment via threat intelligence feeds.

---

## 🏛️ Architecture & Data Flow

Below is the end-to-end data pipeline showing how simulated attack telemetry is ingested, analyzed, correlated, and enriched:

```mermaid
graph TD
    subgraph Client Panel (React Frontend)
        UI[ASATL Dashboard / Incident Manager / Sim Lab]
    end

    subgraph Simulation Telemetry
        MIMI[Mimikatz execution]
        BRUTE[SSH Brute Force]
        REV[Reverse Shell script]
    end

    subgraph SOC SIEM Backend (FastAPI)
        API[FastAPI Router /api]
        SE[Sigma Engine]
        CE[Correlation Engine]
        TI[Threat Intel enrichment]
        AI[AI Analyst helper]
    end

    subgraph Data Store (SQLite)
        DB_RAW[(RawEvents Table)]
        DB_ALERTS[(Alerts Table)]
        DB_INC[(Incidents Table)]
    end

    %% Telemetry Ingestion Flow
    MIMI & BRUTE & REV -->|Trigger Attack Payload| API
    API -->|Ingest Raw Logs| DB_RAW

    %% Detection Engine Flow
    DB_RAW -->|Stream Logs| SE
    SE -->|Compile & Match Rules| DB_ALERTS

    %% Correlation Flow
    DB_ALERTS -->|Window-based Aggregation| CE
    CE -->|Compound Risk Calculation| DB_INC

    %% Enrichment Flow
    DB_INC -->|Enrich IPs/Domains| TI
    DB_INC -->|Prompt Generation| AI

    %% Frontend Sync
    DB_RAW & DB_ALERTS & DB_INC -->|Serve REST APIs| API
    API -->|Feed Dashboard Metrics| UI
```

---

## ✨ Features

- **Automated SIEM Log Ingestion:** Captures structured Sysmon (Windows) and Auditd (Linux) logging telemetry in real time.
- **Custom Sigma Rule Engine:** Evaluates logs against standardized Sigma YAML rule configurations. Supports **case-insensitive matching** and automatic mapping between Windows mixed-case `EventID` properties and relational column schemas.
- **Dynamic Correlation & Grouping:** Evaluates temporal clusters of alerts on individual host endpoints, linking related anomalies under a unified Incident ID and dynamically calculating severity and risk scores.
- **MITRE ATT&CK Visualizer:** Renders an interactive matrix of active security alarms aligned with the MITRE tactics framework (Credential Access, Persistence, Execution, etc.).
- **Threat Intelligence Enrichment:** Automatically checks indicators (IPs, domains, hashes) against intelligence feeds (with simulated fallback records for attack vectors).
- **Docker-Compose Ready:** reviewer-friendly container orchestration that spins up the entire backend/frontend stack in a single command.

---

## 🛠️ Tech Stack

- **Frontend:**
  - React 19 (TypeScript)
  - Vite (build compiler)
  - Vanilla CSS / Tailwind (Aesthetics, neon dark mode glassmorphism)
  - Lucide React (vector icons)
  - Recharts (incident metrics and line graphs)
- **Backend:**
  - FastAPI (REST API routes)
  - Python 3.11+
  - SQLAlchemy ORM (SQLite database engine)
  - PyYAML (Sigma rule parsing)
  - reportlab (PDF SOC report generation)
  - PyJWT (Token-based analyst session authentication)
- **Testing:**
  - Pytest (comprehensive unit/integration testing)
  - HTTPX & FastAPI TestClient (REST routing simulation)

---

## 📂 Folder Structure

```text
project/
├── docker-compose.yml              # Multi-container orchestration
├── README.md                       # Documentation index
│
├── backend/                        # SOC FastAPI Python Backend
│   ├── Dockerfile                  # Backend build recipe
│   ├── run.py                      # Uvicorn boot script
│   ├── requirements.txt            # Python dependencies
│   ├── threat_hunting.db           # Persistent Sqlite SQLite DB
│   │
│   ├── app/
│   │   ├── main.py                 # FastAPI application bootstrapper
│   │   ├── config.py               # Global Pydantic environment configurations
│   │   ├── database.py             # SQLAlchemy Session connection
│   │   ├── models.py               # Database schemas (RawEvent, Alert, Incident, User)
│   │   ├── schemas.py              # Pydantic serializer models
│   │   │
│   │   ├── routers/                # FastAPI endpoint handlers
│   │   │   ├── auth.py             # Login, registers & sessions
│   │   │   ├── rules.py            # Sigma Rule query and creation
│   │   │   ├── simulator.py        # Threat vector dispatch trigger
│   │   │   └── incidents.py        # Incident details and analyst comments
│   │   │
│   │   ├── detection/              # Core Sigma Rules parser
│   │   │   ├── engine.py           # Log parser and matching engine
│   │   │   └── rules/              # Active detection rule repository (.yml files)
│   │   │
│   │   ├── correlation/
│   │   │   └── engine.py           # Temporal aggregation and risk scoring engine
│   │   │
│   │   └── enrichment/
│   │       └── threat_intel.py     # IP, Domain and Hash intelligence checks
│   │
│   └── tests/                      # Automated test coverage
│       ├── test_api.py             # FastAPI REST endpoints verification
│       ├── test_detection.py       # Rule and correlation verification
│       └── test_utils.py           # JWT, encryption, and casing utility tests
│
└── frontend/                       # Interactive Vite React Frontend
    ├── Dockerfile                  # Multi-stage production Nginx compiler
    ├── nginx.conf                  # Nginx server config supporting React SPA routing
    ├── package.json                # Frontend package dependencies
    ├── index.html                  # Core HTML structure
    │
    └── src/
        ├── App.tsx                 # Core App layout & navigation
        ├── index.css               # Premium design token system styles
        ├── components/             # Reusable UI component modules
        │   ├── Dashboard.tsx       # Live status graphs & MITRE ATT&CK Matrix
        │   ├── Incidents.tsx       # Incident workflow & comments
        │   ├── Hunting.tsx         # Raw SIEM telemetry viewer
        │   ├── Rules.tsx           # Sigma rule editor & verifier
        │   └── Simulator.tsx       # Simulation Lab threat dispatcher
        └── services/
            └── api.ts              # Fetch backend client wrapper
```

---

## ⚡ Quick Start: Containerized Setup (Recommended)

To build and launch the entire ASATL stack (frontend and backend) automatically inside Docker containers:

1. Clone or copy the project workspace.
2. From the root directory (where `docker-compose.yml` is located), execute:
   ```bash
   docker compose up --build -d
   ```
3. Open your browser and navigate to:
   - **ASATL Management Console (Frontend)**: [http://localhost](http://localhost) (runs on Nginx HTTP port 80)
   - **Interactive API Documentation (Backend)**: [http://localhost:8000/docs](http://localhost:8000/docs) (Uvicorn backend port 8000)

*Note: The SQLite database file (`threat_hunting.db`) is mapped as a volume. All incidents, rules, and telemetry records are persistently saved on your host computer inside `./backend/threat_hunting.db`.*

---

## ⚙️ Manual Developer Setup

If you prefer to run the frontend and backend locally on your host machine:

### 1. Backend Configuration
1. Open a terminal and navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI server:
   ```bash
   python run.py
   ```
   *The backend will boot on [http://localhost:8000](http://localhost:8000).*

### 2. Frontend Configuration
1. Open a new terminal and navigate to the frontend folder:
   ```bash
   cd frontend
   ```
2. Install npm packages:
   ```bash
   npm install
   ```
3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   *The frontend will boot on [http://localhost:5173](http://localhost:5173).*

---

## 🧪 Running Automated Tests

A comprehensive test suite using Pytest is provided in `backend/tests/`.

To execute all tests (API, Detection engine, and Security Utilities):
1. Navigate to the `backend/` folder and activate the virtual environment.
2. Execute the pytest module:
   ```bash
   python -m pytest
   ```

---

## 📖 User & Simulation Guide

1. **Dashboard Overview:**
   Open the web app interface. You will see a dark-themed glassmorphic console showing real-time logs ingestion rates, aggregated incident lists, and a live-updating **MITRE ATT&CK Matrix**.
2. **Launch a Simulation (Simulation Lab):**
   Go to the **Simulation Lab** tab and trigger a threat vector:
   - **Mimikatz execution:** Simulates LSASS process dumps, writing process events (Sysmon ID 1), registry modifications (Sysmon ID 13), and file creations (Sysmon ID 11).
   - **Brute Force Campaign:** Ingests 15 failed logins and 1 successful entry. Evaluates logs against authentication rules, escalating the incidents as risk metrics accumulate.
   - **Reverse Shell:** Dispatches Auditd execution telemetry.
3. **Investigate (Incident Manager):**
   Check the **Incident Manager** to review triggered incidents. Click on any incident to read full attack details, review the nested alerts, and write analyst comments to update ticket states.
4. **Threat Intel Checks:**
   Under **Threat Hunting**, view raw log streams and look up specific indicators (e.g. IPs) to review live reputation scorecards.
