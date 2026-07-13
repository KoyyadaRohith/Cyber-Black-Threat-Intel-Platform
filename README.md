<div align="center">

# 🛡️ Cyber Black Threat Intel Platform (CBTIP)

### AI-Powered Threat Intelligence & Security Investigation Platform

A modern, cloud-powered cybersecurity platform for **real-time IP reputation analysis, threat intelligence, AI-assisted security investigation, and professional security reporting**.

---

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Gemini-AI-4285F4?style=for-the-badge&logo=google&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API-E53935?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**🚀 Cloud Powered • 🤖 AI Assisted • 🛡️ Threat Intelligence • 📊 Security Analytics**

</div>

---

# 📖 Overview

**Cyber Black Threat Intel Platform (CBTIP)** is a modern web-based cybersecurity platform developed to streamline **IP reputation analysis, cyber threat investigation, security analytics, and AI-assisted threat intelligence** through a centralized and intuitive interface.

The platform aggregates threat intelligence from multiple trusted security sources, enabling analysts to investigate suspicious IP addresses, monitor security events, generate professional investigation reports, and gain AI-powered insights for improved decision-making.

Designed with a scalable architecture powered by **Flask**, **Supabase PostgreSQL**, and **Google Gemini AI**, CBTIP combines cloud technologies with cybersecurity workflows to deliver an efficient investigation platform suitable for learning, portfolio demonstration, and future enterprise expansion.

---

# 🎯 Project Objectives

The primary objectives of Cyber Black Threat Intel Platform are to:

- 🛡️ Investigate IP reputation using multiple threat intelligence providers.
- 🌐 Centralize cyber threat investigation into a single dashboard.
- 📊 Visualize investigation history and security analytics.
- 🤖 Enhance investigations using AI-generated threat summaries and recommendations.
- 📁 Manage historical investigations and watchlists efficiently.
- 📄 Generate professional investigation reports.
- ☁️ Utilize a secure cloud-hosted PostgreSQL database through Supabase.
- 🚀 Provide a scalable foundation for future cybersecurity products within the Cyber Black World (CBW) ecosystem.

---

# ⭐ Key Highlights

- 🛡️ AI-Powered Threat Intelligence Platform
- 🌐 Multi-Source IP Reputation Analysis
- ☁️ Cloud-Native Architecture using Supabase
- 🤖 AI-Assisted Threat Investigation
- 📊 Interactive Dashboard & Analytics
- 🔍 Real-Time Threat Intelligence
- 📈 Investigation History & Timeline
- 🚨 Watchlist Management
- 📄 Professional Report Generation
- 🔐 Secure Authentication & User Management
- ⚡ Fast, Modern & Responsive User Interface
- 🚀 Modular Architecture for Future Expansion

---

# ✨ Core Features

## 🔍 Threat Investigation

- Real-Time IP Reputation Analysis
- Individual IP Investigation
- Bulk IP Investigation
- AI-Assisted Threat Analysis
- Threat Classification Engine
- Investigation Timeline
- Investigation History
- Investigation Notes & Severity
- Threat Recommendations

---

## 🌐 Threat Intelligence

CBTIP combines information from multiple trusted intelligence providers.

### Supported Integrations

- 🛡️ AbuseIPDB
- 🦠 VirusTotal
- 🌍 WHOIS & IP Geolocation
- 🤖 Google Gemini AI

The platform intelligently correlates data from these services to generate comprehensive threat intelligence results.

---

## 🤖 AI Intelligence Layer

The integrated AI Intelligence Layer enhances investigations by automatically generating:

- 🧠 Executive Threat Summaries
- 📌 Indicators of Compromise (IOC) Explanations
- ⚠️ Risk Assessments
- 💡 Security Recommendations
- 📊 Dashboard Insights
- 📝 AI-Assisted Investigation Reports

> **Note:** AI-generated analysis should always be reviewed before taking security actions.

---

## 📊 Dashboard & Analytics

The interactive dashboard provides valuable operational insights including:

- Total Investigations
- Safe IP Statistics
- Low Risk IP Statistics
- Suspicious IP Statistics
- High Risk IP Statistics
- Malicious IP Statistics
- Investigation Trends
- Top Threat Countries
- Top Autonomous Systems (ASN)
- Watchlist Overview
- Recent Investigation Activity

---

## 📁 Investigation Management

Organize and manage security investigations efficiently with:

- Investigation History
- Timeline Tracking
- Analyst Notes
- Tags & Severity Levels
- Watchlist Management
- Threat Classification
- Investigation Search
- AI Investigation Support

---

## 📄 Professional Reporting

Generate comprehensive investigation reports in multiple formats.

Supported formats:

- 📑 CSV Reports
- 📄 TXT Reports
- 🌐 HTML Reports
- 🖨️ Print-Friendly Reports

Each report includes investigation details, threat intelligence, classifications, and analyst observations.

---

## 👤 User Management

The platform includes secure account management features.

- Secure Authentication
- Google OAuth Login
- User Profiles
- Notification Center
- Personal Settings
- Session Management

---

# 🛠️ Technology Stack

| Category | Technologies |
|------------|--------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python, Flask |
| **Database** | Supabase PostgreSQL |
| **Authentication** | Supabase Auth, Google OAuth |
| **Artificial Intelligence** | Google Gemini AI |
| **Threat Intelligence APIs** | AbuseIPDB, VirusTotal, WHOIS/IP Geolocation |
| **Data Visualization** | Chart.js |
| **Cloud Platform** | Supabase |
| **Version Control** | Git & GitHub |

---

# 💡 Why Cyber Black Threat Intel Platform?

Cyber Black Threat Intel Platform was developed to demonstrate how modern cybersecurity applications can integrate **cloud infrastructure**, **threat intelligence services**, **artificial intelligence**, and **interactive analytics** into a unified investigation platform.

Rather than relying on a single data source, CBTIP aggregates intelligence from multiple providers, helping analysts perform more informed investigations while maintaining an intuitive and efficient workflow.

The platform also serves as a strong foundation for future cybersecurity solutions within the **Cyber Black World (CBW)** ecosystem, emphasizing scalability, modularity, and continuous innovation.

---

# 🏗️ System Architecture

Cyber Black Threat Intel Platform follows a modular, cloud-based architecture designed for scalability, maintainability, and secure threat investigation.

```text
                        ┌───────────────────────────┐
                        │        End User           │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │      Web Interface        │
                        │ HTML • CSS • JavaScript   │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │      Flask Backend        │
                        │ Authentication • Routing  │
                        │ Business Logic • APIs     │
                        └─────────────┬─────────────┘
                                      │
             ┌────────────────────────┼────────────────────────┐
             ▼                        ▼                        ▼
 ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
 │ Threat Intelligence│     │ AI Intelligence │      │ Supabase Cloud   │
 │ AbuseIPDB         │     │ Google Gemini   │      │ PostgreSQL DB    │
 │ VirusTotal        │     │ Threat Summary  │      │ Authentication   │
 │ WHOIS Lookup      │     │ Recommendations │      │ Storage          │
 └──────────────────┘      └──────────────────┘      └──────────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Reports & Analytics       │
                        │ Dashboard • History       │
                        │ Watchlists • Exports      │
                        └───────────────────────────┘
```

---

# 📂 Project Structure

```text
Cyber-Black-Threat-Intel-Platform/

│
├── app.py
├── config.py
├── requirements.txt
├── schema.sql
├── migrate_data.py
├── README.md
├── LICENSE
├── .env
│
├── services/
│   ├── ai_engine.py
│   ├── ai_provider.py
│   ├── ai_prompts.py
│   ├── db_operations.py
│   ├── report_generator.py
│   ├── risk_scoring.py
│   └── ...
│
├── templates/
│
├── static/
│   ├── css/
│   ├── js/
│   ├── images/
│   └── icons/
│
├── reports/
│
├── uploads/
│
└── database/
    ├── migrations/
    └── legacy_csv/
```

---

# ⚙️ Prerequisites

Before running the application, ensure the following software is installed:

- Python 3.10 or later
- Git
- Supabase Account
- Google AI Studio Account (Gemini API)
- AbuseIPDB API Key
- VirusTotal API Key

---

# 🚀 Installation

## Create a Virtual Environment

### Windows

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

---

## 3. Install Required Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 Environment Variables

Create a `.env` file in the project root.

Example:

```env
SECRET_KEY=

SUPABASE_URL=

SUPABASE_ANON_KEY=

SUPABASE_SERVICE_ROLE_KEY=

ABUSEIPDB_API_KEY=

VIRUSTOTAL_API_KEY=

GEMINI_API_KEY=
```

> **Important:** Never commit your `.env` file or API keys to GitHub.

---

# ☁️ Supabase Configuration

Create a new Supabase project.

Execute the provided `schema.sql` inside the Supabase SQL Editor to initialize the database schema.

Configure the following services:

- PostgreSQL Database
- Authentication
- Row Level Security (RLS)
- Storage (Optional)

After creating your project, copy the following values into the `.env` file:

- Project URL
- Anonymous API Key
- Service Role Key

---

# 🤖 Gemini AI Configuration

Generate an API key from Google AI Studio.

https://aistudio.google.com/

Copy your API key and add it to the `.env` file.

```env
GEMINI_API_KEY=YOUR_API_KEY
```

CBTIP uses Gemini AI to generate:

- Threat Summaries
- IOC Explanations
- Investigation Recommendations
- AI Security Insights

If the API key is unavailable, the platform gracefully falls back to deterministic rule-based analysis where applicable.

---

# 🌐 Threat Intelligence APIs

The platform integrates multiple security intelligence providers.

| Service | Purpose |
|----------|---------|
| AbuseIPDB | IP Abuse Reputation |
| VirusTotal | Malware & Reputation Analysis |
| WHOIS / IP Geolocation | Network & Ownership Information |
| Google Gemini AI | AI-Assisted Threat Intelligence |

---

# ▶️ Running the Application

Start the development server:

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

# 📊 Platform Modules

The application is organized into modular components.

| Module | Description |
|----------|-------------|
| 🔍 Threat Investigation | Analyze IP reputation using multiple threat intelligence providers |
| 📊 Dashboard | Interactive analytics and investigation statistics |
| 📂 Investigation History | Review previous investigations |
| 🚨 Watchlists | Track suspicious or malicious IP addresses |
| 🤖 AI Intelligence | Generate AI-assisted investigation insights |
| 👤 User Management | Authentication, profiles and settings |
| 📄 Reporting | Export investigation reports in multiple formats |
| 🔔 Notifications | System notifications and updates |

---

# 🔒 Security Features

Cyber Black Threat Intel Platform implements several security best practices.

- 🔐 Secure Authentication
- ☁️ Supabase Authentication
- 🛡️ Row Level Security (RLS)
- 🔑 Environment Variable Protection
- 📜 Secure Session Management
- 🌐 Protected API Integration
- ⚠️ Input Validation
- 📊 Investigation Logging
- 🚫 Secure Error Handling
- 🔒 Password Encryption

---

# ⚡ Performance Optimizations

To provide a smooth investigation experience, CBTIP includes several optimizations.

- Parallel API Requests
- AI Response Caching
- Optimized Database Queries
- Efficient Report Generation
- Cloud Database Integration
- Lightweight Frontend Rendering
- Responsive Dashboard Components
- Modular Service Architecture

---

# 🎯 Use Cases

Cyber Black Threat Intel Platform (CBTIP) is designed to support a wide range of cybersecurity learning, research, and investigation scenarios.

### 🛡️ Threat Intelligence Analysis
- Investigate suspicious IP addresses
- Analyze IP reputation from multiple intelligence providers
- Identify malicious infrastructure
- Perform threat correlation

### 🔍 Security Investigation
- Conduct manual IP investigations
- Review historical investigation records
- Track investigation timelines
- Document analyst observations

### 🚨 Security Operations (SOC)
- Support SOC analyst workflows
- Perform initial threat triage
- Review threat classifications
- Monitor watchlisted IP addresses

### 🌐 Network Security
- Investigate unknown network traffic
- Validate suspicious external connections
- Analyze network ownership and ASN information

### 🎓 Learning & Research
- Learn cybersecurity investigation workflows
- Understand threat intelligence concepts
- Explore API integrations
- Practice investigation techniques

### 💼 Portfolio & Demonstration
- Showcase full-stack development skills
- Demonstrate cloud application architecture
- Present cybersecurity concepts through practical implementation
- Highlight AI-assisted security workflows

---

# 🚀 Future Roadmap

Cyber Black Threat Intel Platform is continuously evolving as part of the **Cyber Black World (CBW)** ecosystem.

## ✅ Completed

- Cloud Database Migration (Supabase PostgreSQL)
- Secure Authentication
- Google OAuth Support
- Real-Time Threat Intelligence
- AI Intelligence Layer
- Dashboard Analytics
- Watchlist Management
- Investigation History
- Report Generation
- Responsive User Interface

---

## 🔜 Planned Features

### Version 1.1

- Email Notifications
- Investigation Filters
- Improved Dashboard Analytics
- Performance Enhancements
- UI/UX Refinements

---

### Version 2.0

- IPv6 Investigation
- Domain Reputation Analysis
- URL Intelligence
- File Hash Investigation
- IOC Correlation Engine
- Threat Feed Aggregation

---

### Future Vision

- Multi-Organization Workspaces
- Role-Based Access Control (RBAC)
- Team Collaboration
- Enterprise Dashboard
- REST API
- SIEM Integration
- Docker Deployment
- Kubernetes Support
- Cloud Deployment
- Mobile Responsive Enhancements

---

# 📈 Learning Outcomes

Developing CBTIP provided practical experience in:

- Python Development
- Flask Framework
- Cloud Database Design
- PostgreSQL
- Supabase
- Authentication Systems
- REST API Integration
- Artificial Intelligence Integration
- Cybersecurity Concepts
- Threat Intelligence
- Report Generation
- Frontend Development
- Responsive UI Design
- Version Control with Git & GitHub

---

# 🤝 Contributing

Contributions are welcome.

If you would like to improve this project:

1. Fork the repository
2. Create a new feature branch

```bash
git checkout -b feature/your-feature
```

3. Commit your changes

```bash
git commit -m "Add new feature"
```

4. Push to GitHub

```bash
git push origin feature/your-feature
```

5. Open a Pull Request

Please ensure your code follows the existing project structure and coding standards.

---

# 📌 Project Status

**Current Status**

🟢 Active Development

The project continues to receive improvements, performance optimizations, bug fixes, and new cybersecurity features as part of the Cyber Black World (CBW) ecosystem.

---

# 🙌 Acknowledgements

Special thanks to the following platforms and services that made this project possible:

- Google Gemini AI
- Supabase
- VirusTotal
- AbuseIPDB
- Flask
- Python Community
- Open Source Community

```

👨‍💻 Developed By

Koyyada Rohith

🔐 Cybersecurity Enthusiast | 🎓 B.Tech CSE | 🚀 Building Projects in Cybersecurity, Collaboration & Technology

```

📌 Version

Version 1.0

```

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.

```
<div align="center">

# 🛡️ Cyber Black Squad — Startup Workspace Platform

### Startup Management & Collaboration Platform

**Part of the Cyber Black World (CBW) Ecosystem**

</div>

```