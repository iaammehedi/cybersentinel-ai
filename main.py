import os
import time
import socket
import secrets
import threading
import ipaddress
import ssl
import http.client

from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictBool


app = FastAPI(title="CyberSentinel AI")

SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "")
DEMO_MODE = os.environ.get(
    "DEMO_MODE", "true"
).strip().lower() == "true"


def canonical_host(value: str) -> str:
    """Normalize a domain name for allowlist comparison."""
    value = value.strip().rstrip(".")
    if not value:
        raise ValueError("Empty hostname")

    host = value.encode("idna").decode("ascii").lower()

    if len(host) > 253 or "/" in host or ":" in host:
        raise ValueError("Invalid hostname")

    return host


ALLOWED_HOSTS = set()

for entry in os.environ.get("ALLOWED_HOSTS", "").split(","):
    if entry.strip():
        try:
            ALLOWED_HOSTS.add(canonical_host(entry))
        except (ValueError, UnicodeError):
            raise RuntimeError(
                "ALLOWED_HOSTS contains an invalid domain"
            )


if not SCAN_TOKEN:
    raise RuntimeError(
        "SCAN_TOKEN environment variable is required"
    )

if not ALLOWED_HOSTS and not DEMO_MODE:
    raise RuntimeError(
        "ALLOWED_HOSTS must contain an authorized domain"
    )


HEADERS_TO_CHECK = {
    "strict-transport-security":
        "HTTPS ব্যবহারের পাশাপাশি HSTS কনফিগারেশন যাচাই করুন.",
    "content-security-policy":
        "অ্যাপের উপযোগী Content Security Policy বিবেচনা করুন.",
    "x-content-type-options":
        "X-Content-Type-Options: nosniff বিবেচনা করুন.",
    "referrer-policy":
        "উপযুক্ত Referrer-Policy কনফিগার করুন.",
    "permissions-policy":
        "অপ্রয়োজনীয় browser feature সীমিত করুন.",
}


audit_log = []
last_scan_time = 0.0
scan_lock = threading.Lock()
audit_lock = threading.Lock()


class ScanRequest(BaseModel):
    url: str = Field(min_length=9, max_length=253)
    confirm_authorized: StrictBool


def validate_target(url: str) -> tuple[str, str]:
    if DEMO_MODE:
        raise HTTPException(
            403,
            "Demo mode enabled: scanning is disabled."
        )

    parsed = urlsplit(url.strip())

    if parsed.scheme.lower() != "https":
        raise HTTPException(400, "শুধু HTTPS অনুমোদিত।")

    if not parsed.hostname:
        raise HTTPException(400, "সঠিক URL দাও।")

    if parsed.username or parsed.password:
        raise HTTPException(
            400, "URL-এ credentials অনুমোদিত নয়."
        )

    try:
        if parsed.port not in (None, 443):
            raise HTTPException(
                400, "শুধু HTTPS port 443 অনুমোদিত."
            )
    except ValueError:
        raise HTTPException(400, "URL-এর port সঠিক নয়.")

    if parsed.path not in ("", "/"):
        raise HTTPException(
            400, "শুধু domain-এর root URL পরীক্ষা করা যাবে."
        )

    if parsed.query or parsed.fragment:
        raise HTTPException(
            400,
            "প্রথম সংস্করণে query ও fragment অনুমোদিত নয়."
        )

    try:
        host = canonical_host(parsed.hostname)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Domain নামটি সঠিক নয়.")

    if host not in ALLOWED_HOSTS:
        raise HTTPException(
            403, "এই domain অনুমোদিত তালিকায় নেই."
        )

    # Reject IP literals: this version accepts allowlisted
    # domain names only.
    try:
        ipaddress.ip_address(host)
        raise HTTPException(
            400, "IP address নয়, অনুমোদিত domain ব্যবহার করো."
        )
    except ValueError:
        pass

    # Resolve once, reject the entire result if ANY address
    # is non-public, then pin the connection to a validated IP.
    try:
        addresses = socket.getaddrinfo(
            host,
            443,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            raise ValueError("No DNS addresses")

        public_ips = []

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])

            if not ip.is_global:
                raise HTTPException(
                    403,
                    "Domain non-public IP-তে resolve হয়েছে."
                )

            public_ips.append(str(ip))

        pinned_ip = public_ips[0]

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            400, "Domain DNS যাচাই করা যায়নি."
        )

    return host, pinned_ip


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while verifying TLS for the domain."""

    def __init__(self, host: str, pinned_ip: str, timeout: int = 8):
        super().__init__(
            host=host,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self.pinned_ip = pinned_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, 443),
            timeout=self.timeout,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise


def run_check(host: str, pinned_ip: str) -> dict:
    connection = PinnedHTTPSConnection(
        host,
        pinned_ip,
        timeout=8,
    )

    try:
        # Request only the root path; never follow redirects.
        connection.request(
            "GET",
            "/",
            headers={
                "User-Agent": "CyberSentinel-Passive-Check/1.0",
                "Accept": "text/html,*/*;q=0.1",
                "Connection": "close",
            },
        )

        response = connection.getresponse()
        status = response.status
        headers = response.headers

        if 300 <= status < 400:
            return {
                "target": f"https://{host}/",
                "checked_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "status": status,
                "redirect_followed": False,
                "note": "Redirect অনুসরণ করা হয়নি.",
                "findings": [],
                "limitations": [
                    "এটি সীমিত passive header check.",
                    "Redirect-এর গন্তব্য পরীক্ষা করা হয়নি.",
                ],
            }

        findings = []

        for name, advice in HEADERS_TO_CHECK.items():
            present = name in headers

            findings.append({
                "header": name,
                "present": present,
                "observed_value": (
                    headers.get(name) if present else None
                ),
                "recommendation": (
                    advice if not present else
                    "Header পাওয়া গেছে; এর মান ও কার্যকারিতা যাচাই করুন."
                ),
            })

        return {
            "target": f"https://{host}/",
            "checked_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "status": status,
            "redirect_followed": False,
            "findings": findings,
            "limitations": [
                "এটি সীমিত passive header check, পূর্ণ penetration test নয়.",
                "Header অনুপস্থিত থাকা একাই vulnerability প্রমাণ করে না.",
                "কোনো exploit বা login attempt চালানো হয়নি.",
                "শুধু domain-এর root path পরীক্ষা করা হয়েছে.",
            ],
        }

    finally:
        connection.close()


app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)


@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "scanner": "passive-header-check",
        "demo_mode": DEMO_MODE,
    }


@app.post("/api/scan")
def scan(
    data: ScanRequest,
    x_scan_token: str = Header(default=""),
):
    global last_scan_time

    if not secrets.compare_digest(x_scan_token, SCAN_TOKEN):
        raise HTTPException(
            401, "অনুমোদিত token প্রয়োজন."
        )

    if data.confirm_authorized is not True:
        raise HTTPException(
            403, "মালিকের অনুমতি নিশ্চিত করতে হবে."
        )

    host, pinned_ip = validate_target(data.url)

    global_lock_error = None

    with scan_lock:
        now = time.monotonic()

        if now - last_scan_time < 15:
            global_lock_error = True
        else:
            last_scan_time = now

    if global_lock_error:
        raise HTTPException(
            429, "নিরাপত্তার জন্য ১৫ সেকেন্ড অপেক্ষা করো."
        )

    try:
        report = run_check(host, pinned_ip)
    except (OSError, ssl.SSLError, http.client.HTTPException):
        raise HTTPException(
            502, "পরীক্ষা ব্যর্থ হয়েছে; ফলাফল নিশ্চিত নয়."
        )

    with audit_lock:
        audit_log.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "target": report["target"],
            "status": report["status"],
        })
        del audit_log[:-100]

    return report


@app.get("/api/audit")
def get_audit(
    x_scan_token: str = Header(default=""),
):
    if not secrets.compare_digest(x_scan_token, SCAN_TOKEN):
        raise HTTPException(
            401, "অনুমোদিত token প্রয়োজন."
        )

    with audit_lock:
        return {"events": list(audit_log)}
