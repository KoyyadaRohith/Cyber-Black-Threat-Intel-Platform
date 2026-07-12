# 🛡️ Cyber Black Threat Intel Platform (CBTIP)

### AI-Powered Threat Intelligence & Security Investigation Platform

---

The **Cyber Black Threat Intel Platform (CBTIP)** is a full-stack, web-based threat intelligence platform built for **security analysts**, **SOC engineers**, **system administrators**, and **network operations teams**. It provides real-time and mock IP reputation analysis, multi-vendor threat aggregation, automated risk classification, bulk log ingestion, watchlist surveillance, and exportable incident audit reports — all through a modern glassmorphism dark-themed dashboard.

The platform integrates with three major threat intelligence APIs — **AbuseIPDB**, **VirusTotal v3**, and **ip-api.com** (WHOIS/GeoLocation) — and includes a fully functional **mock engine** that generates deterministic, realistic threat intelligence data without requiring any API credentials, making it immediately runnable out of the box.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Technology Stack & Architecture](#-technology-stack--architecture)
- [System Architecture Diagram](#-system-architecture-diagram)
- [Setting Up & Running Locally](#-setting-up--running-locally)
- [Environment Variables Configuration](#-environment-variables-configuration)
- [Dual Engine Modes](#-dual-engine-modes-mock-vs-live)
- [Platform Pages & Modules](#-platform-pages--modules)
- [API Integrations Deep Dive](#-api-integrations-deep-dive)
- [Risk Scoring Algorithm](#-risk-scoring-algorithm)
- [Threat Classification Thresholds](#-threat-classification-thresholds)
- [Remediation Playbook Engine](#-remediation-playbook-engine)
- [Bulk File Ingestion Pipeline](#-bulk-file-ingestion-pipeline)
- [Report Generation & Export Formats](#-report-generation--export-formats)
- [Database Schema](#-database-schema)
- [Authentication & Session Management](#-authentication--session-management)
- [Google OAuth 2.0 Integration](#-google-oauth-20-integration)
- [Directory Structure](#-directory-structure)
- [Testing](#-testing)
- [Security Analyst Test Profiles (Mock Mode)](#-security-analyst-test-profiles-mock-mode)
- [Screenshots & UI Overview](#-screenshots--ui-overview)
- [Future Enhancements](#-future-enhancements)
- [License](#-license)

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| **Individual IP Investigation** | Inspect threat metrics, GeoLocation profiles, ISP details, ASN information, security tags, abuse confidence ratios, and receive tailored remediation recommendations. |
| **Bulk File Ingestion** | Upload CSV, TXT, or raw firewall log files. The regex engine extracts all IPv4 addresses, deduplicates them, runs parallel AJAX-streamed analysis queries, and generates aggregate batch reports. |
| **Watchlist & Surveillance** | Tag high-risk IP assets to a persistent watchlist with automated threshold-based auto-tagging. Export watchlist registers as CSV. |
| **Historical Auditing** | Every manual and bulk investigation is permanently archived in a searchable investigation history log with full metadata. |
| **Threat Analytics Dashboard** | Real-time interactive analytics powered by Chart.js — 7-day scan trend lines, threat classification doughnut charts, and recent activity feeds. |
| **Multi-Format Report Export** | Download incident audit reports as Plaintext (TXT), raw spreadsheet registers (CSV), or print-optimized HTML layouts (Save-as-PDF). |
| **Dual Engine Modes** | Toggle between **Mock Mode** (deterministic test data) and **Live Mode** (real-time API queries) from the Settings panel. |
| **Google OAuth 2.0** | Supports Google Sign-In with both real OAuth 2.0 flows and a built-in mock consent screen for local development. |
| **User Profile Management** | Full profile editing, avatar upload, role assignment, and organization tagging. |
| **In-App Notification System** | Session-based notification center tracking investigation events, watchlist actions, and system changes. |
| **Responsive Design** | Fully responsive layout with mobile viewport overrides, media print CSS for report generation, and collapsible sidebar navigation. |
| **Auto-Watchlist Automation** | Configurable risk score threshold that automatically adds high-risk IPs to the watchlist during investigation. |

---

## 🛠️ Technology Stack & Architecture

| Layer | Technology |
|---|---|
| **Backend Framework** | Python 3.8+ with Flask 3.0.3 micro-framework |
| **Templating Engine** | Jinja2 (server-side HTML rendering) |
| **Database** | Flat-file CSV databases with thread-safe retry-based I/O locking |
| **API Client** | Python `requests` 2.31.0 library with timeout/fallback handling |
| **Environment Config** | `python-dotenv` 1.0.1 for `.env` credential management |
| **Frontend Styling** | Vanilla CSS with glassmorphism panels, custom CSS variables, dark theme, and micro-animations |
| **Charts & Visualization** | Chart.js for interactive line and doughnut chart rendering |
| **JavaScript** | Vanilla JS for clipboard hooks, mobile hamburger navigation, table sorting/filtering, drag-and-drop file upload, and AJAX streaming |
| **Authentication** | Session-based auth with SHA-256 password hashing + Google OAuth 2.0 (real & mock flows) |
| **Threat Intelligence APIs** | AbuseIPDB API v2, VirusTotal API v3, ip-api.com (WHOIS/Geo) |

---

## 🏗️ System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER (UI LAYER)                        │
│                                                                         │
│   ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────┐            │
│   │  Login   │  │Dashboard │  │ IP Invest. │  │ Reports  │  ...       │
│   │ Register │  │Analytics │  │ File Upload│  │ Watchlist │            │
│   └────┬─────┘  └────┬─────┘  └─────┬──────┘  └────┬─────┘            │
│        │              │              │               │                  │
│        └──────────────┴──────────────┴───────────────┘                  │
│                              │  HTTP / AJAX                             │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────────┐
│                     FLASK APPLICATION SERVER                            │
│                         (app.py — 1250 lines)                           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Route Controllers: login, register, dashboard, investigate,   │    │
│  │  file_upload, analysis, results, watchlist, history, reports,  │    │
│  │  settings, profile, Google OAuth, API endpoints                │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                              │                                          │
│  ┌───────────────────────────┼──────────────────────────────────┐       │
│  │              SERVICE LAYER (services/)                       │       │
│  │                                                              │       │
│  │  ┌───────────────┐  ┌────────────────┐  ┌────────────────┐  │       │
│  │  │  abuseipdb.py │  │ virustotal.py  │  │ whois_lookup.py│  │       │
│  │  │ (AbuseIPDB    │  │ (VirusTotal v3 │  │ (ip-api.com    │  │       │
│  │  │  API + Mock)  │  │  API + Mock)   │  │  WHOIS + Mock) │  │       │
│  │  └───────┬───────┘  └───────┬────────┘  └───────┬────────┘  │       │
│  │          │                  │                    │           │       │
│  │          └──────────────────┼────────────────────┘           │       │
│  │                             │                                │       │
│  │  ┌──────────────────────────▼──────────────────────────────┐ │       │
│  │  │              RISK ENGINE PIPELINE                       │ │       │
│  │  │                                                         │ │       │
│  │  │  risk_scoring.py → threat_summary.py → recommendations │ │       │
│  │  │    (Weighted      (Analyst-style      .py (Priority-   │ │       │
│  │  │     Score)         Diagnosis)          based Playbook)  │ │       │
│  │  └─────────────────────────────────────────────────────────┘ │       │
│  │                                                              │       │
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐  │       │
│  │  │  db_operations.py   │  │    report_generator.py        │  │       │
│  │  │  (CSV CRUD + Schema │  │    (TXT / CSV / HTML Print    │  │       │
│  │  │   Migration Engine) │  │     Export Formatters)         │  │       │
│  │  └─────────────────────┘  └───────────────────────────────┘  │       │
│  └──────────────────────────────────────────────────────────────┘       │
│                                                                         │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────────┐
│                      DATA LAYER (database/)                             │
│                                                                         │
│  ┌──────────────────┐  ┌────────────────────────┐                      │
│  │   users.csv      │  │ investigation_history   │                      │
│  │ (User Accounts   │  │       .csv              │                      │
│  │  & Credentials)  │  │ (Search Archive Logs)   │                      │
│  └──────────────────┘  └────────────────────────┘                      │
│  ┌──────────────────┐  ┌────────────────────────┐                      │
│  │  watchlist.csv   │  │  malicious_ips.csv     │                      │
│  │ (Active Watch    │  │ (High-Threat IP Cache  │                      │
│  │  Registers)      │  │  & Reputation Index)   │                      │
│  └──────────────────┘  └────────────────────────┘                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   EXTERNAL THREAT INTELLIGENCE APIs                      │
│                                                                         │
│  ┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐    │
│  │   AbuseIPDB    │  │   VirusTotal v3  │  │  ip-api.com (WHOIS) │    │
│  │   API v2       │  │   IP Address API │  │  GeoLocation API    │    │
│  │                │  │                  │  │                      │    │
│  │ Abuse Score    │  │ AV Engine Scans  │  │ Country, City, ISP   │    │
│  │ Report Count   │  │ Malicious Count  │  │ ASN, Coordinates     │    │
│  │ ISP, Domain    │  │ Reputation Score │  │ Timezone, Region     │    │
│  │ Usage Type     │  │ Tags, Network    │  │ Organization         │    │
│  └────────────────┘  └──────────────────┘  └──────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Setting Up & Running Locally

### Prerequisites

- **Python 3.8+** installed and accessible from the terminal
- **pip** package manager

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/Malicious-IP-Intelligence-System.git
cd Malicious-IP-Intelligence-System
```

### Step 2 — Create a Virtual Environment (Recommended)

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

The project requires only three Python packages:

| Package | Version | Purpose |
|---|---|---|
| `Flask` | 3.0.3 | Web framework for routing, templating, and session management |
| `requests` | 2.31.0 | HTTP client for external API calls |
| `python-dotenv` | 1.0.1 | Environment variable loading from `.env` file |

### Step 4 — Run the Application

```bash
python app.py
```

The development server starts on **[http://localhost:5000](http://localhost:5000)**. Open this URL in your web browser to access the platform.

> **Note:** The application runs in **Mock Mode by default** — no API keys required. You'll see realistic, deterministic threat intelligence data immediately.

---

## 🔐 Environment Variables Configuration

Create a `.env` file in the project root directory (a template is included). The following variables are supported:

| Variable | Required | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | No | Your AbuseIPDB v2 API key. Enables live abuse reputation queries. Get one free at [abuseipdb.com](https://www.abuseipdb.com/). |
| `VIRUSTOTAL_API_KEY` | No | Your VirusTotal v3 API key. Enables live AV engine scanning. Get one free at [virustotal.com](https://www.virustotal.com/). |
| `GOOGLE_OAUTH_CLIENT_ID` | No | Google OAuth 2.0 Client ID for real Google Sign-In. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | No | Google OAuth 2.0 Client Secret for real Google Sign-In. |
| `SECRET_KEY` | No | Flask session encryption key. A default is provided if omitted. |
| `PORT` | No | Server port number. Defaults to `5000`. |
| `DEBUG` | No | Flask debug mode toggle. Defaults to `True`. |

**Example `.env` file:**
```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here

GOOGLE_OAUTH_CLIENT_ID=
GOOGLE_OAUTH_CLIENT_SECRET=

SECRET_KEY=your-custom-secret-key
PORT=5000
DEBUG=True
```

---

## 🔄 Dual Engine Modes (Mock vs Live)

The platform supports two operational modes, toggled from the **Settings** panel:

### Mock Mode (Default)

- **No API keys required** — the system is immediately functional.
- Generates **deterministic, realistic threat intelligence** using MD5-hash-based seeding of the target IP, ensuring the same IP always produces the same mock data.
- Simulates AbuseIPDB abuse scores, VirusTotal AV detections, WHOIS geolocation data, security tags, ISP profiles, and more.
- Risk distribution: ~50% Safe, ~30% Suspicious, ~20% Malicious based on the IP's hash.

### Live Mode

- Requires valid **AbuseIPDB** and/or **VirusTotal** API keys entered in the Settings panel or configured in `.env`.
- Queries **real-time threat intelligence** from external API endpoints.
- WHOIS/GeoLocation data is always fetched live from `ip-api.com` (free tier, 45 queries/minute).
- If an API call fails, the system gracefully falls back to mock data for that vendor.

---

## 📄 Platform Pages & Modules

The application includes **18 Jinja2 templates** organized across the following pages:

### Public Pages (No Authentication Required)

| Page | Route | Template | Description |
|---|---|---|---|
| **Home / Landing** | `/` or `/home` | `home.html` | Public landing page with platform overview, live stats counters, and feature highlights. |
| **Login** | `/login` | `login.html` | User authentication form with Google OAuth button and mock consent fallback. |
| **Register** | `/register` | `register.html` | New analyst account registration with full name, email, mobile, and password fields. |
| **Forgot Password** | `/forgot-password` | `forgot_password.html` | Password reset request form (simulated). |

### Authenticated Pages (Login Required)

| Page | Route | Template | Description |
|---|---|---|---|
| **Dashboard** | `/dashboard` | `dashboard.html` | Main control hub with stat widgets, 7-day scan trend chart, and recent activity feed. |
| **Threat Analytics** | `/analytics` | `threat_analytics.html` | Detailed analytics with threat breakdown doughnut chart, trend lines, and scan history table. |
| **IP Investigation** | `/investigate` | `ip_investigation.html` | Core investigation console — enter an IP to receive full threat profile, risk score gauge, abuse data, VT detections, WHOIS info, threat summary, and remediation playbook. |
| **File Upload** | `/file-upload` | `file_upload.html` | Drag-and-drop file upload interface for bulk CSV/TXT/LOG ingestion. |
| **Analysis Pipeline** | `/analysis` | `analysis.html` | Real-time AJAX-streamed bulk analysis progress view with per-IP status updates. |
| **Batch Results** | `/results` | `results.html` | Aggregated batch results console with threat breakdown stats and sortable results table. |
| **Watchlist** | `/watchlist` | `watchlist.html` | Persistent watchlist table with add/remove operations and CSV export. |
| **History** | `/history` | `history.html` | Full searchable investigation history archive sorted by date descending. |
| **Reports** | `/reports` | `reports.html` | Report gallery listing individual IP reports and bulk batch audit cards with download options. |
| **Profile** | `/profile` | `profile.html` | User profile management — edit name, username, email, location, role, organization, bio, and avatar. |
| **Settings** | `/settings` | `settings.html` | System configuration panel — API key management, mock/live mode toggle, auto-watchlist threshold, notification preferences, and system info display. |

### Special Pages

| Page | Template | Description |
|---|---|---|
| **Google Mock Consent** | `google_mock_consent.html` | Simulated Google OAuth consent screen for local development without real OAuth credentials. |
| **Base Layout** | `base.html` | Minimal base template for public pages. |
| **Authenticated Base** | `base_auth.html` | Full dashboard layout with sidebar navigation, notification bell, user avatar, and breadcrumbs. |

---

## 🌐 API Integrations Deep Dive

### 1. AbuseIPDB API v2 (`services/abuseipdb.py`)

- **Endpoint**: `https://api.abuseipdb.com/api/v2/check`
- **Method**: GET with API key header authentication
- **Parameters**: IP address, 90-day lookback window, verbose mode
- **Data Returned**: Abuse confidence score (0–100%), total abuse reports, last reported timestamp, country, ISP, domain, usage type
- **Fallback**: On API failure or missing key, returns deterministic mock data seeded by IP hash

### 2. VirusTotal API v3 (`services/virustotal.py`)

- **Endpoint**: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **Method**: GET with `x-apikey` header authentication
- **Data Returned**: Malicious/suspicious/harmless/undetected engine counts, reputation score, security tags (botnet, malware, C2, etc.), network CIDR, ASN
- **Fallback**: On API failure or missing key, returns deterministic mock data seeded by IP hash

### 3. ip-api.com WHOIS/GeoLocation (`services/whois_lookup.py`)

- **Endpoint**: `http://ip-api.com/json/{ip}`
- **Method**: GET (no authentication — free tier)
- **Rate Limit**: 45 queries per minute
- **Data Returned**: Country, country code, region, city, ISP, organization, ASN, latitude/longitude, timezone
- **Fallback**: On API failure, returns deterministic mock WHOIS data seeded by IP hash

---

## 📊 Risk Scoring Algorithm

The risk score engine (`services/risk_scoring.py`) computes an **aggregate weighted threat score from 0 to 100** using data from all three API vendors:

```
Final Score = Abuse Contribution (50%) + VirusTotal Contribution (35%) + Profile Contribution (15%)
```

### Weight Breakdown

| Component | Weight | Source | Calculation |
|---|---|---|---|
| **Abuse Confidence** | 50% | AbuseIPDB `abuse_score` (0–100) | `abuse_score × 0.50` |
| **AV Detection Ratio** | 35% | VirusTotal `malicious / total_engines` | `(malicious ÷ total_engines × 100) × 0.35` (capped at 35) |
| **Hosting Profile** | 15% | AbuseIPDB `usage_type` + VT `tags` | +8 pts if Data Center/Hosting; +7 pts if VPN/Proxy/Tor/Anonymous tags detected |

### Score Bounds

- Final score is clamped between **0** and **100**
- The algorithm returns both the numeric score and the classification label

---

## 🏷️ Threat Classification Thresholds

| Score Range | Classification | Color Code | Description |
|---|---|---|---|
| **0 – 20** | 🟢 **Safe** | Green | No threat indicators. Normal operations permitted. |
| **21 – 60** | 🟡 **Suspicious** | Yellow/Amber | Moderate risk signals. Monitoring recommended. |
| **61 – 100** | 🔴 **Malicious** | Red | Severe threat confirmed. Immediate isolation advised. |

---

## 🔧 Remediation Playbook Engine

The recommendation engine (`services/recommendations.py`) generates priority-tagged, action-oriented playbook items based on the threat classification:

### Safe Classification
| Priority | Action |
|---|---|
| Low | Allow Communication — Normal ingress/egress transit permitted |
| Low | Standard Monitoring — Continue routine firewall log auditing |
| Low | No Policy Changes — No firewall blacklistings required |

### Suspicious Classification
| Priority | Action |
|---|---|
| Medium | Monitor Port Connections — Log all TCP/UDP ports communicating with this IP |
| Medium | Add to Active Watchlist — Monitor daily changes in threat scores |
| Medium | Review Internal Traffic — Check for database/auth server connections from this host |

### Malicious Classification
| Priority | Action |
|---|---|
| High | Block IP Address — Apply immediate perimeter firewall block rules |
| High | Apply Null Route (Null0) — Implement null route rules on primary routers |
| High | Quarantine & Inspect Hosts — Audit local server logs for active shell sessions |
| High | Escalate to Incident Response — File Severity 2/1 IR ticket for intrusion investigation |

---

## 📦 Bulk File Ingestion Pipeline

The bulk analysis workflow processes uploaded log files through the following stages:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌───────────────┐
│  File Upload │────▶│ IP Extraction│────▶│ Deduplication   │────▶│ AJAX Parallel │
│  (.csv/.txt/ │     │ (Regex IPv4) │     │ (Set-based      │     │ Analysis Loop │
│   .log)      │     │              │     │  unique list)   │     │ (per-IP)      │
└─────────────┘     └──────────────┘     └─────────────────┘     └───────┬───────┘
                                                                         │
                    ┌──────────────┐     ┌─────────────────┐             │
                    │ Batch Report │◀────│ Results Console │◀────────────┘
                    │ Export (CSV/  │     │ (Aggregated     │
                    │  TXT/HTML)   │     │  Stats + Table) │
                    └──────────────┘     └─────────────────┘
```

**Pipeline Details:**

1. **File Upload**: Accepts `.csv`, `.txt`, and `.log` files via a drag-and-drop interface or file picker
2. **IP Extraction**: Applies regex pattern `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` to extract all IPv4 addresses
3. **Deduplication**: Removes duplicate IPs using Python set operations
4. **AJAX Streaming**: Each unique IP is analyzed individually via the `/api/analyze-single` endpoint with real-time progress updates in the browser
5. **Batch Tagging**: Results are tagged with a unique batch ID (`filename_YYYYMMDD_HHMMSS`) for audit trail tracking
6. **Results Console**: Displays aggregate threat breakdown (safe/suspicious/malicious counts) with a sortable results table
7. **Report Export**: Batch results can be downloaded as CSV, TXT, or print-optimized HTML

---

## 📝 Report Generation & Export Formats

The report generator (`services/report_generator.py`) supports multiple export formats:

### Individual IP Reports
| Format | Description |
|---|---|
| **HTML (Print/PDF)** | Print-optimized white-background layout that triggers `window.print()` on load. Includes threat summary, infrastructure profile, security feeds telemetry, and remediation playbook. Save as PDF via browser print dialog. |
| **TXT** | Professional plaintext audit report with ASCII-formatted sections, formatted tables, and full diagnostic details. |

### Bulk Batch Reports
| Format | Description |
|---|---|
| **CSV** | Raw spreadsheet register with all investigation fields for import into SIEM tools or spreadsheets. |
| **TXT** | Batch ingestion summary with aggregate threat statistics and an IP reputation directory table. |
| **HTML (Print/PDF)** | Print-optimized bulk audit layout with metric boxes, remediation playbook summary, and full IP analysis table. |

### Backup Exports
| Export | Description |
|---|---|
| **History CSV/TXT** | Complete investigation history archive export. |
| **Watchlist CSV/TXT** | Complete watchlist register export. |

---

## 🗄️ Database Schema

The application uses flat-file CSV databases with thread-safe retry-based I/O operations. The database layer (`services/db_operations.py`) includes automatic schema migration for backward compatibility.

### `database/users.csv` — User Accounts Registry

| Field | Type | Description |
|---|---|---|
| `username` | String | Unique login identifier (min 3 characters) |
| `email` | String | Unique email address |
| `password_hash` | String | SHA-256 hashed password |
| `full_name` | String | Display name |
| `mobile_number` | String | Contact number (optional) |
| `location` | String | Geographic location (default: Hyderabad, Telangana, India) |
| `created_at` | ISO 8601 | Account creation timestamp |
| `bio` | String | User biography |
| `role` | String | Job title (default: Threat Analyst) |
| `organization` | String | Organization name |
| `profile_photo_url` | String | Avatar URL (Google OAuth or uploaded) |
| `provider` | String | Auth provider: `local` or `google` |
| `account_created_date` | ISO 8601 | Duplicate of `created_at` for display purposes |

### `database/investigation_history.csv` — Search Archive Logs

| Field | Type | Description |
|---|---|---|
| `id` | Integer | Auto-incrementing log ID |
| `username` | String | Analyst who performed the search |
| `ip` | String | Target IP address investigated |
| `country` | String | GeoLocation country |
| `isp` | String | Internet Service Provider |
| `asn` | String | Autonomous System Number |
| `risk_score` | Integer | Computed aggregate risk score (0–100) |
| `classification` | Enum | `Safe`, `Suspicious`, or `Malicious` |
| `threat_summary` | String | Full analyst-style threat diagnosis text |
| `recommendations` | String | Semicolon-delimited remediation actions |
| `abuse_score` | Integer | AbuseIPDB abuse confidence score |
| `vt_detections` | Integer | VirusTotal malicious engine count |
| `date` | ISO 8601 | Investigation timestamp |
| `source` | String | `manual` for individual lookups; batch ID for bulk uploads |

### `database/watchlist.csv` — Active Watch Registers

| Field | Type | Description |
|---|---|---|
| `ip` | String | Watched IP address |
| `username` | String | Analyst who added the entry |
| `risk_score` | Integer | Risk score at time of watchlisting |
| `classification` | Enum | Threat classification at time of watchlisting |
| `date_added` | ISO 8601 | Watchlist entry creation timestamp |
| `reason` | String | Reason for watchlisting (manual or auto-threshold) |
| `status` | String | Entry status (default: `Active`) |

### `database/malicious_ips.csv` — High-Threat Reputation Cache

| Field | Type | Description |
|---|---|---|
| `ip` | String | Confirmed malicious IP address |
| `risk_score` | Integer | Risk score at detection time |
| `classification` | String | Always `Malicious` |
| `last_detected` | ISO 8601 | Last detection timestamp (updates on re-scan) |
| `reason` | String | Threat summary text |

---

## 🔑 Authentication & Session Management

### Local Authentication
- **Registration**: Full name, username (min 3 chars), email, mobile number, password (min 6 chars), confirm password
- **Password Security**: SHA-256 one-way hashing before storage
- **Session Management**: Flask server-side sessions with encrypted cookies
- **Login Decorator**: `@login_required` decorator protects all authenticated routes
- **Session Variables**: `username`, `email`, `full_name`, `mobile_number`, `photo_url`, `settings`, `notifications`

### Profile Management
- Edit full name, username, email, location, role, organization, and bio
- Upload custom avatar images (PNG, JPG, JPEG, GIF)
- Username changes cascade automatically to history and watchlist records
- Google OAuth users receive auto-generated usernames from their email prefix

---

## 🔗 Google OAuth 2.0 Integration

The platform supports Google Sign-In through two pathways:

### Real Google OAuth Flow
1. User clicks **"Sign in with Google"** on the login page
2. App redirects to Google's authorization endpoint with CSRF state token
3. Google returns authorization code to `/login/google/callback`
4. App exchanges code for access token, then fetches user profile from Google
5. If email matches an existing account → log in. Otherwise → auto-register new account

### Mock Google OAuth Flow (Local Development)
1. When `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` are empty, the app redirects to a built-in mock consent page (`/login/google/mock-consent`)
2. The mock consent screen lets you enter any name, email, and profile picture URL
3. On submission, the app creates or logs in the user with those mock credentials
4. This allows full OAuth flow testing without configuring real Google Cloud credentials

---

## 📂 Directory Structure

```
Malicious-IP-Intelligence-System/
│
├── app.py                              # Core Flask application (1250 lines)
│                                       # — Route controllers & middleware
│                                       # — Session management & auth decorators
│                                       # — Google OAuth 2.0 flow handlers
│                                       # — API endpoints for AJAX bulk analysis
│                                       # — Report download & export controllers
│                                       # — Notification system helpers
│                                       # — Context processors for global template vars
│
├── config.py                           # Application configuration
│                                       # — Directory path registries (uploads, reports, exports)
│                                       # — API credential loading from .env
│                                       # — Google OAuth credential loading
│                                       # — Server port & debug settings
│                                       # — Auto-init folder creation on startup
│
├── requirements.txt                    # Python dependencies (Flask, requests, python-dotenv)
├── test_pipeline.py                    # Automated test suite (4 test categories)
├── .env                                # Environment variables (API keys, OAuth credentials)
├── README.md                           # This documentation file
│
├── services/                           # Backend service modules
│   ├── abuseipdb.py                    # AbuseIPDB API v2 client + mock data generator
│   ├── virustotal.py                   # VirusTotal API v3 client + mock data generator
│   ├── whois_lookup.py                 # ip-api.com WHOIS/Geo client + mock data generator
│   ├── risk_scoring.py                 # Weighted multi-vendor risk score calculator
│   ├── threat_summary.py              # Analyst-style threat diagnosis text generator
│   ├── recommendations.py             # Priority-based remediation playbook engine
│   ├── report_generator.py            # Multi-format report compiler (TXT, CSV, HTML Print)
│   └── db_operations.py               # Flat-file CSV database CRUD operations
│                                       # — Thread-safe read/write/append with retry logic
│                                       # — Auto schema migration on startup
│                                       # — User, History, Watchlist, Malicious IP management
│
├── templates/                          # Jinja2 HTML templates (18 files)
│   ├── base.html                       # Minimal base layout for public pages
│   ├── base_auth.html                  # Full dashboard layout (sidebar, navbar, notifications)
│   ├── home.html                       # Public landing page with feature showcase
│   ├── login.html                      # Login form with Google OAuth button
│   ├── register.html                   # Registration form with validation
│   ├── forgot_password.html            # Password reset request form
│   ├── google_mock_consent.html        # Mock Google OAuth consent screen
│   ├── dashboard.html                  # Main dashboard with stats & charts
│   ├── threat_analytics.html           # Advanced analytics with trend visualization
│   ├── ip_investigation.html           # IP investigation console with full threat profile
│   ├── file_upload.html                # Drag-and-drop bulk file upload interface
│   ├── analysis.html                   # Real-time bulk analysis progress view
│   ├── results.html                    # Batch results aggregation console
│   ├── watchlist.html                  # Watchlist management table
│   ├── history.html                    # Investigation history archive
│   ├── reports.html                    # Report gallery with download cards
│   ├── profile.html                    # User profile editor with avatar upload
│   └── settings.html                   # System configuration panel
│
├── static/                             # Static frontend assets
│   ├── css/
│   │   ├── style.css                   # Global design system (CSS variables, glass panels,
│   │   │                               #   forms, buttons, animations, color scheme)
│   │   ├── dashboard.css               # Dashboard-specific (sidebar nav, badges, widgets,
│   │   │                               #   chart containers, activity feed cards)
│   │   └── responsive.css              # Responsive breakpoints & media print overrides
│   │
│   ├── js/
│   │   ├── main.js                     # Clipboard copy hooks, mobile hamburger toggle,
│   │   │                               #   notification panel interactions
│   │   ├── dashboard.js                # Table sorting, column filtering, search bindings
│   │   ├── charts.js                   # Chart.js line & doughnut chart render functions
│   │   └── upload.js                   # Drag/drop file handling, AJAX bulk analysis loop,
│   │                                   #   progress bar animations, batch session saving
│   │
│   ├── img/
│   │   ├── logo_shield.png             # Platform shield logo
│   │   ├── holographic_globe.png       # Decorative holographic globe graphic
│   │   └── cyber_hacker.png            # Landing page hero illustration
│   │
│   └── uploads/
│       └── avatars/                    # User-uploaded profile avatars
│
├── database/                           # Flat-file CSV database storage
│   ├── users.csv                       # User accounts & credentials
│   ├── investigation_history.csv       # Complete search archive
│   ├── watchlist.csv                   # Active watchlist entries
│   └── malicious_ips.csv              # Cached high-threat IP reputation index
│
├── uploads/                            # Temporary uploaded file storage
│   ├── csv/
│   ├── txt/
│   └── logs/
│
├── reports/                            # Generated report file cache
│   ├── pdf/                            # HTML print-format reports
│   ├── csv/                            # CSV export files
│   └── txt/                            # Plaintext report files
│
└── exports/                            # Additional export storage
    ├── generated_reports/
    └── downloaded_files/
```

---

## 🧪 Testing

The project includes an automated test suite (`test_pipeline.py`) that validates the four core subsystems:

```bash
python test_pipeline.py
```

### Test Categories

| # | Test | What It Validates |
|---|---|---|
| 1 | **User Authentication** | Account registration, SHA-256 hashing, user retrieval, email/password verification |
| 2 | **Threat Intelligence Pipeline** | Mock data generation, AbuseIPDB/VirusTotal/WHOIS integration, risk scoring accuracy, threat summary generation, recommendation output for Safe & Malicious IPs |
| 3 | **Watchlist Operations** | Add to watchlist, verify presence (`is_in_watchlist`), remove from watchlist, verify deletion |
| 4 | **Report Compilation** | TXT individual report generation (ISP name, IP presence checks), CSV report buffer generation (header/row validation) |

**Expected Output:**
```
[*] COMMENCING SYSTEM TESTS FOR THREAT INTEL PLATFORM...
----------------------------------------------------------------------
[+] Test 1: User Account Registration & Hashing...
    - Registration outcome: True (User registered successfully.)
    - User account validation successful.
[+] Test 2: IP Reputation Diagnostic Pipeline...
    - Querying Safe target: 8.8.8.8...
      * Risk score: X/100 | Class: Safe
    - Querying Malicious target: 198.51.100.9...
      * Risk score: X/100 | Class: Malicious
    - Risk engine scores and classification mappings validated.
[+] Test 3: Watchlist Registers Operations...
    - Add watchlist: True (IP added to watchlist.)
    - Remove watchlist: (True, 'IP removed from watchlist.')
    - Watchlist CRUD operations successful.
[+] Test 4: Security Incident Reports Export Compilation...
    - TXT & CSV report buffers generated successfully.
----------------------------------------------------------------------
[SUCCESS] ALL SYSTEM TESTS COMPLETED SUCCESSFULLY! BASE SYSTEM 100% SOUND.
```

---

## 🔒 Security Analyst Test Profiles (Mock Mode)

When running in **Mock Mode**, the risk score and threat classification are deterministic — computed from the MD5 hash of the target IP address. Use these benchmark IPs to verify risk scoring thresholds:

| Test IP | Expected Classification | Expected Behavior |
|---|---|---|
| `8.8.8.8` | 🟢 **Safe** | Google DNS — Clean reputation, zero abuse reports, no VT detections, reputable ISP profile |
| `198.51.100.12` | 🟡 **Suspicious** | Triggers warning flags — Moderate abuse score, low VT detections, proxy/crawler tags, hosting provider profile |
| `203.0.113.50` | 🔴 **Malicious** | Severe threat level — High abuse confidence, multiple VT engine detections, C2/botnet tags, data center hosting, perimeter blocking remediation |

---

## 🖼️ Screenshots & UI Overview

The platform features a **dark-themed glassmorphism design** with:

- 🎨 **Glass-effect panels** with backdrop blur and translucent borders
- ✨ **Glowing accent effects** on interactive elements
- 📊 **Interactive Chart.js visualizations** (line trends + doughnut breakdowns)
- 🎯 **Custom risk score gauges** with animated color fills
- 📱 **Fully responsive** layout from desktop to mobile viewports
- 🖨️ **Print-optimized** report layouts with clean white backgrounds
- 🔔 **Notification center** with timestamped activity events

---

## 🚧 Future Enhancements

- [ ] **IPv6 Support** — Extend the regex extraction engine and validation to support IPv6 addresses
- [ ] **SQLite/PostgreSQL Migration** — Replace flat-file CSV databases with relational database for production scalability
- [ ] **Real-Time Watchlist Monitoring** — Scheduled background re-scans of watchlisted IPs with change detection alerts
- [ ] **Email Alert Integration** — SMTP-based email notifications when malicious IPs are detected
- [ ] **SIEM Integration** — Syslog/CEF format export for integration with Splunk, ELK, or QRadar
- [ ] **API Rate Limiting** — Token bucket rate limiting for bulk analysis endpoints
- [ ] **Role-Based Access Control (RBAC)** — Admin, Analyst, and Viewer role hierarchies
- [ ] **Geolocation Map Visualization** — Interactive world map plotting investigated IP locations
- [ ] **Dark/Light Theme Toggle** — User-selectable theme preference
- [ ] **Docker Containerization** — Dockerfile and docker-compose for one-command deployment

---

## 📄 License

This project is developed as part of an academic internship program. All rights reserved.

---

<p align="center">
  <strong>🛡️ Cyber Black Threat Intel Platform (CBTIP)</strong><br>
  <em>AI-Powered Threat Intelligence & Security Investigation Platform</em><br><br>
  Built with Python · Flask · Chart.js · Vanilla CSS
</p>
]]>
