import asyncio
import ipaddress
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


APP_NAME = "SOC Bulk IP Checker"


ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
VT_BASE = "https://www.virustotal.com/api/v3"


def _env(name: str) -> Optional[str]:
    v = os.getenv(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


def _client_ip(request: Request) -> str:
    # If you deploy behind a proxy/load balancer, make sure it is configured
    # to set X-Forwarded-For and that your platform strips untrusted values.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def parse_ips(raw: str, limit: int = 30) -> Tuple[List[str], List[str]]:
    tokens = [t.strip() for t in raw.replace(",", "\n").splitlines()]
    tokens = [t for t in tokens if t]

    seen: set[str] = set()
    valid: List[str] = []
    invalid: List[str] = []

    for t in tokens:
        if len(valid) >= limit:
            break
        if t in seen:
            continue
        seen.add(t)
        try:
            ip = ipaddress.ip_address(t)
            if ip.version != 4 and ip.version != 6:
                invalid.append(t)
                continue
            valid.append(str(ip))
        except ValueError:
            invalid.append(t)

    return valid, invalid


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class ProviderResult:
    ok: bool
    status_code: Optional[int]
    data: Optional[Dict[str, Any]]
    error: Optional[str]
    took_ms: int


async def abuseipdb_check(client: httpx.AsyncClient, ip: str) -> ProviderResult:
    key = _env("ABUSEIPDB_API_KEY")
    if not key:
        return ProviderResult(
            ok=False,
            status_code=None,
            data=None,
            error="Missing ABUSEIPDB_API_KEY",
            took_ms=0,
        )

    t0 = _now_ms()
    try:
        r = await client.get(
            f"{ABUSEIPDB_BASE}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=20.0,
        )
        took = _now_ms() - t0
        if r.status_code >= 400:
            return ProviderResult(
                ok=False,
                status_code=r.status_code,
                data=None,
                error=f"AbuseIPDB HTTP {r.status_code}: {r.text[:300]}",
                took_ms=took,
            )
        return ProviderResult(ok=True, status_code=r.status_code, data=r.json(), error=None, took_ms=took)
    except Exception as e:
        took = _now_ms() - t0
        return ProviderResult(ok=False, status_code=None, data=None, error=f"AbuseIPDB error: {e}", took_ms=took)


async def virustotal_ip(client: httpx.AsyncClient, ip: str) -> ProviderResult:
    key = _env("VT_API_KEY") or _env("VIRUSTOTAL_API_KEY")
    if not key:
        return ProviderResult(
            ok=False,
            status_code=None,
            data=None,
            error="Missing VT_API_KEY (or VIRUSTOTAL_API_KEY)",
            took_ms=0,
        )

    t0 = _now_ms()
    try:
        r = await client.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=20.0,
        )
        took = _now_ms() - t0
        if r.status_code >= 400:
            return ProviderResult(
                ok=False,
                status_code=r.status_code,
                data=None,
                error=f"VirusTotal HTTP {r.status_code}: {r.text[:300]}",
                took_ms=took,
            )
        return ProviderResult(ok=True, status_code=r.status_code, data=r.json(), error=None, took_ms=took)
    except Exception as e:
        took = _now_ms() - t0
        return ProviderResult(ok=False, status_code=None, data=None, error=f"VirusTotal error: {e}", took_ms=took)


def normalize_row(ip: str, abuse: ProviderResult, vt: ProviderResult) -> Dict[str, Any]:
    row: Dict[str, Any] = {"ip": ip}

    row["abuseipdb"] = {
        "ok": abuse.ok,
        "status": abuse.status_code,
        "took_ms": abuse.took_ms,
        "error": abuse.error,
    }
    if abuse.ok and abuse.data:
        d = abuse.data.get("data", {}) if isinstance(abuse.data, dict) else {}
        row["abuseipdb"].update(
            {
                "abuseConfidenceScore": d.get("abuseConfidenceScore"),
                "totalReports": d.get("totalReports"),
                "numDistinctUsers": d.get("numDistinctUsers"),
                "countryCode": d.get("countryCode"),
                "countryName": d.get("countryName"),
                "region": d.get("region"),
                "city": d.get("city"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "hostnames": d.get("hostnames") or [],
                "asn": d.get("asn"),
                "asnName": d.get("asnName"),
                "usageType": d.get("usageType"),
                "lastReportedAt": d.get("lastReportedAt"),
                "isPublic": d.get("isPublic"),
                "isTor": d.get("isTor"),
                "isWhitelisted": d.get("isWhitelisted"),
            }
        )

    row["virustotal"] = {
        "ok": vt.ok,
        "status": vt.status_code,
        "took_ms": vt.took_ms,
        "error": vt.error,
    }
    if vt.ok and vt.data:
        data = vt.data.get("data", {}) if isinstance(vt.data, dict) else {}
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
        row["virustotal"].update(
            {
                "reputation": attrs.get("reputation"),
                "last_analysis_stats": stats,
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "network": attrs.get("network"),
                "asn": attrs.get("asn"),
                "tags": attrs.get("tags") or [],
            }
        )

    row["links"] = {
        "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }
    return row


app = FastAPI(title=APP_NAME)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


SESSION_COOKIE = "spookypass_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
_sessions: Dict[str, int] = {}  # token -> expires_at_epoch_seconds

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20
_rate: Dict[str, List[int]] = {}  # client_ip -> request epoch seconds list


def _auth_enabled() -> bool:
    return bool(_env("APP_PASSWORD"))


def _is_authed(request: Request) -> bool:
    if not _auth_enabled():
        return True
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    exp = _sessions.get(token)
    if not exp:
        return False
    now = int(time.time())
    if exp <= now:
        _sessions.pop(token, None)
        return False
    return True


def _rate_allow(client_ip: str) -> bool:
    now = int(time.time())
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    hits = _rate.get(client_ip, [])
    hits = [t for t in hits if t >= window_start]
    if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
        _rate[client_ip] = hits
        return False
    hits.append(now)
    _rate[client_ip] = hits
    return True


class GateAndRateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path.startswith("/static"):
            return await call_next(request)

        if _auth_enabled():
            if path in ("/login", "/logout", "/healthz"):
                return await call_next(request)
            if not _is_authed(request):
                return RedirectResponse(url="/login", status_code=302)

        if path == "/api/check":
            ip = _client_ip(request)
            if not _rate_allow(ip):
                return JSONResponse(
                    {"ok": False, "error": "Rate limited. Try again in ~60s."},
                    status_code=429,
                )

        return await call_next(request)


app.add_middleware(GateAndRateMiddleware)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request) -> HTMLResponse:
    if not _auth_enabled():
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "app_name": APP_NAME, "error": None},
    )


@app.post("/login")
async def login_post(request: Request, password: str = Form(...)) -> Response:
    expected = _env("APP_PASSWORD")
    if not expected:
        return RedirectResponse(url="/", status_code=302)

    if not secrets.compare_digest(password.strip(), expected):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "app_name": APP_NAME, "error": "Invalid password."},
            status_code=401,
        )

    token = secrets.token_urlsafe(32)
    _sessions[token] = int(time.time()) + SESSION_TTL_SECONDS
    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=bool(_env("COOKIE_SECURE") or "").__bool__(),
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return resp


@app.post("/logout")
async def logout_post(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        _sessions.pop(token, None)
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "has_abuse_key": bool(_env("ABUSEIPDB_API_KEY")),
            "has_vt_key": bool(_env("VT_API_KEY") or _env("VIRUSTOTAL_API_KEY")),
            "auth_enabled": _auth_enabled(),
        },
    )


@app.post("/api/check")
async def api_check(ips: str = Form(...)) -> JSONResponse:
    valid, invalid = parse_ips(ips, limit=30)
    if not valid:
        return JSONResponse(
            {
                "ok": False,
                "error": "No valid IPs found (max 30).",
                "invalid": invalid,
                "results": [],
            },
            status_code=400,
        )

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    async with httpx.AsyncClient(limits=limits) as client:
        sem = asyncio.Semaphore(8)

        async def one(ip: str) -> Dict[str, Any]:
            async with sem:
                abuse_task = abuseipdb_check(client, ip)
                vt_task = virustotal_ip(client, ip)
                abuse, vt = await asyncio.gather(abuse_task, vt_task)
                return normalize_row(ip, abuse, vt)

        results = await asyncio.gather(*[one(ip) for ip in valid])

    return JSONResponse({"ok": True, "invalid": invalid, "results": results})
