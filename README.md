# SOC Bulk IP Checker (AbuseIPDB + VirusTotal)

Internal web app to check up to **30 IPs at a time** against:

- **AbuseIPDB** (abuse confidence score, reports, ISP, etc.)
- **VirusTotal** (reputation + last analysis stats)

## Setup

### 1) Create API keys

- AbuseIPDB API key: set env var `ABUSEIPDB_API_KEY`
- VirusTotal API key: set env var `VT_API_KEY` (or `VIRUSTOTAL_API_KEY`)
- Set a login password (recommended for public hosting): `APP_PASSWORD`

### 2) Install dependencies

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 3) Run

PowerShell example:

```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VT_API_KEY="your_key_here"
$env:APP_PASSWORD="a_strong_password"
uvicorn main:app --reload --port 8000
```

Open: `http://127.0.0.1:8000`

## Notes

- API keys stay **server-side** (browser never sees them).
- If either API rate-limits, you’ll see per-provider errors in the table; retry later.
- If you host publicly, enable login via `APP_PASSWORD` and consider additional controls (WAF/CAPTCHA/allowlist).

## Hosting (Docker)

Build and run:

```bash
docker build -t soc-ip-checker .
docker run -p 8000:8000 ^
  -e ABUSEIPDB_API_KEY="..." ^
  -e VT_API_KEY="..." ^
  -e APP_PASSWORD="..." ^
  soc-ip-checker
```
