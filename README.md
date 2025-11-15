# OSINT Mini Project

A modern, privacy-aware, and extensible Open Source Intelligence (OSINT) toolkit for email addresses and IP addresses.
Supports both interactive Streamlit dashboard **and** traditional Python command-line workflows.

***

## Features

### 🔎 Email OSINT

- **Email reputation checking** (PureChecker API with .env credentials, 3s enforced wait)
- **Breach scan/search** (Leak-Lookup API)
- **Social handle \& Gravatar discovery**
- **Credential matches:** Simulated number of credentials for demo visualizations
- **Domain resolution \& reachability test**
- **Export all results as JSON**


### 🌐 IP OSINT

- **IP Geolocation** (ip-api.com, no key required)
- **ISP/org/ASN, hostname reverse, proxy/vpn/hosting detection**
- **Export as JSON for archival**


### 📊 Web Dashboard: `osint.py`

- Modern Streamlit UI
- Visual metrics, bar charts (site breaches, matches), full tables
- Toggle raw API outputs for inspection
- Google Maps IP location
- "Find my IP" function (via `find_ip.py`)
- Requirements and all API secrets configurable via `.env`


### 🖥️ CLI Tools

- **ip_lookup.py:** Command-line IP reporting
- **email_osint.py:** Command-line email OSINT with all above checks

***

## 🚀 Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```


### 2. Prepare your `.env` file

Copy `.env.sample` as `.env` and fill in:

```env
PURECHECKER_USER=your_purechecker_user
PURECHECKER_SECRET=your_purechecker_secret
LEAK_LOOKUP_API_KEY=your_leak_lookup_key
```

> If you only use IP tools, you do not need any API keys.

### 3. To start the web dashboard

```bash
streamlit run osint.py
```


### 4. To use the command-line tools

#### Email OSINT CLI:

```bash
python email_osint.py
```


#### IP OSINT CLI:

```bash
python ip_lookup.py
```


***

## 📦 File Overview

- **osint.py** – Streamlit dashboard for email \& IP OSINT (recommended for demo/reporting)
- **ip_lookup.py** – CLI tool for IP OSINT and export
- **email_osint.py** – CLI tool for email OSINT and export
- **find_ip.py** – Utility for retrieving current public IP inside dashboard or CLI
- **requirements.txt** – Pinned dependency versions
- **.env.sample** – Credentials/API keys template

***

## 📝 Example Usage

#### Web UI

- Open web dashboard at [localhost:8501 when running osint.py](http://localhost:8501)
- Enter any email/IP and view:
    - Reputation (PureChecker)
    - Breach exposure (Leak-Lookup)
    - Social/gravatar footprint
    - Domain/IP location info
    - Download or inspect raw JSON


#### Command-Line

- Just run either script and follow prompts (export option at end).

***

## 🤝 Contributions

Feedback, improvements, and PRs are encouraged—including:

- New OSINT sources (Hibp, hunter.io, or your favorite OSINT SaaS)
- UI/UX enhancements
- More export/report formats (PDF, HTML)
- More API key management improvements

***

## 📜 License

MIT License (c) 2025 - sarahrhemadayal

***

Questions?
Open an issue or reach out [on GitHub](https://github.com/sarahrhemadayal/osint-mini-project).

***