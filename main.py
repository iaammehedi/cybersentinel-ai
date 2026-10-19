
import os
import json
import time
import socket
import secrets
import threading
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI(title="CyberSentinel AI")

SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "")
ALLOWED_HOSTS = {
    h.strip().lower().rstrip(".")
    for h in os.environ.get("ALLOWED_HOSTS", "").split(",")
    if h.strip()
}

if not SCAN_TOKEN:
    raise RuntimeError("SCAN_TOKEN environment variable is required")
if not ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS must contain your authorized domain")

HEADERS_TO_CHECK = {
    "strict-transport-security":
        "HTTPS ব্যবহারের পাশাপাশি HSTS কনফিগারেশন যাচাই করুন।",
    "content-security-policy":
        "অ্যাপের উপযোগী Content Security Policy বিবেচনা করুন।",
    "x-content-type-options":
        "X-Content-Type-Options: nosniff বিবেচনা করুন।",
    "referrer-policy":
        "উপযুক্ত Referrer-Policy কনফিগার করুন।",
    "permissions-policy":
        "অপ্রয়োজনীয় browser feature সীমিত করুন।",
}

audit_log = []
last_scan_time = 0.0
scan_lock = threading.Lock()


class ScanRequest(BaseModel):
    url: str = Field(min_length=9, max_length=253)
    confirm_authorized: bool


def validate_target(url: str) -> str:
    parsed = urlsplit(url.strip())

    if parsed.scheme.lower() != "https":
        raise HTTPException(400, "শুধু HTTPS অনুমোদিত।")

    if not parsed.hostname:
        raise HTTPException(400, "সঠিক URL দাও।")

    if parsed.username or parsed.password:
        raise HTTPException(400, "URL-এ credentials অনুমোদিত নয়।")

    try:
        if parsed.port not in (None, 443):
            raise HTTPException(400, "শুধু HTTPS port 443 অনুমোদিত।")
    except ValueError:
        raise HTTPException(400, "URL-এর port সঠিক নয়।")

    if parsed.query or parsed.fragment:
        raise HTTPException(
            400, "প্রথম সংস্করণে query ও fragment অনুমোদিত নয়।"
        )

    if parsed.path not in ("", "/"):
        raise HTTPException(
            400, "শুধু domain-এর root URL পরীক্ষা করা যাবে।"
        )

    host = (
    parsed.hostname.encode("idna")
    .decode("ascii")
    .lower()
    .rstrip(".")
)

if DEMO_MODE:
    raise HTTPException(
        403,
        "Demo mode enabled: scanning is disabled."
    )
    
if host not in ALLOWED_HOSTS:
    raise HTTPException(
        403,
        "এই domain অনুমোদিত তালিকায় নেই।"
    )

    # DNS-এর private, loopback, link-local বা reserved IP ব্লক।
    try:
        addresses = socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )
        if not addresses:
            raise ValueError("No DNS addresses")

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if not ip.is_global:
                raise HTTPException(
                    403, "Domain non-public IP-তে resolve হয়েছে।"
                )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Domain DNS যাচাই করা যায়নি।")

    return f"https://{host}/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run_check(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberSentinel-Passive-Check/1.0",
            "Accept": "text/html,*/*;q=0.1",
        },
        method="GET",
    )

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(),
        NoRedirect(),
    )

    try:
        response = opener.open(request, timeout=8)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return {
                "target": url,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "status": e.code,
                "redirect_followed": False,
                "note": "Redirect অনুসরণ করা হয়নি।",
                "findings": [],
            }
        response = e

    with response:
        headers = response.headers
        findings = []

        for name, advice in HEADERS_TO_CHECK.items():
            present = name in headers
            findings.append({
                "header": name,
                "present": present,
                "observed_value": headers.get(name) if present else None,
                "recommendation": advice if not present else
                    "Header পাওয়া গেছে; এর মান ও কার্যকারিতা যাচাই করুন.",
            })

        return {
            "target": url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": response.status,
            "redirect_followed": False,
            "findings": findings,
            "limitations": [
                "এটি সীমিত passive header check, পূর্ণ penetration test নয়.",
                "Header অনুপস্থিত থাকা একাই vulnerability প্রমাণ করে না.",
                "কোনো exploit বা login attempt চালানো হয়নি.",
            ],
        }


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


@app.get("/health")
def health():
    return {"status": "ok", "scanner": "passive-header-check"}


@app.post("/api/scan")
def scan(
    data: ScanRequest,
    request: Request,
    x_scan_token: str = Header(default=""),
):
    global last_scan_time

    if not secrets.compare_digest(x_scan_token, SCAN_TOKEN):
        raise HTTPException(401, "অনুমোদিত token প্রয়োজন।")

    if data.confirm_authorized is not True:
        raise HTTPException(403, "মালিকের অনুমতি নিশ্চিত করতে হবে।")

    target = validate_target(data.url)

    with scan_lock:
        now = time.monotonic()
        if now - last_scan_time < 15:
            raise HTTPException(
                429, "নিরাপত্তার জন্য ১৫ সেকেন্ড অপেক্ষা করো।"
            )
        last_scan_time = now

    try:
        report = run_check(target)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HTTPException(502, "পরীক্ষা ব্যর্থ হয়েছে; ফলাফল নিশ্চিত নয়।")

    audit_log.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "status": report["status"],
    })
    del audit_log[:-100]

    return report


@app.get("/api/audit")
def get_audit(x_scan_token: str = Header(default="")):
    if not secrets.compare_digest(x_scan_token, SCAN_TOKEN):
        raise HTTPException(401, "অনুমোদিত token প্রয়োজন।")
    return {"events": audit_log}
