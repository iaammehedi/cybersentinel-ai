import os
import re
import time
import socket
import secrets
import threading
import ipaddress
import ssl
import http.client

from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Header, Request
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


# Passive header checks: presence only. Order here only affects the
# order findings are listed in; it has no effect on scoring.
HEADERS_TO_CHECK = {
    "strict-transport-security":
        "HTTPS ব্যবহারের পাশাপাশি HSTS কনফিগারেশন যাচাই করুন.",
    "content-security-policy":
        "অ্যাপের উপযোগী Content Security Policy বিবেচনা করুন.",
    "x-content-type-options":
        "X-Content-Type-Options: nosniff বিবেচনা করুন.",
    "x-frame-options":
        "ক্লিকজ্যাকিং ঠেকাতে X-Frame-Options অথবা CSP frame-ancestors কনফিগার করুন.",
    "referrer-policy":
        "উপযুক্ত Referrer-Policy কনফিগার করুন.",
    "permissions-policy":
        "অপ্রয়োজনীয় browser feature সীমিত করুন.",
}

# Headers that, if present, reveal server/framework details to an
# attacker without providing any benefit to the visitor.
INFO_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


# Security headers sent with every response of THIS application.
# The pages use inline <script>/<style>, so 'unsafe-inline' is needed
# until those are moved into separate files.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


audit_log = []
last_scan_time = 0.0
scan_lock = threading.Lock()
audit_lock = threading.Lock()

# Failed-token attempt limiter (in memory, resets on restart).
FAIL_LIMIT = 10          # wrong tokens allowed ...
FAIL_WINDOW = 300.0      # ... per 5 minutes, per client
failed_attempts: dict[str, list[float]] = {}
fail_lock = threading.Lock()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)

    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


def client_key(request: Request) -> str:
    # Behind Render's proxy the real client is in X-Forwarded-For.
    # The last entry is the one added by the trusted proxy.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()[:64] or "unknown"

    return request.client.host if request.client else "unknown"


def require_token(request: Request, supplied: str) -> None:
    """Check the scan token; limit repeated wrong guesses."""
    key = client_key(request)
    now = time.monotonic()
    blocked = False
    valid = False

    with fail_lock:
        recent = [
            t for t in failed_attempts.get(key, [])
            if now - t < FAIL_WINDOW
        ]

        if len(recent) >= FAIL_LIMIT:
            blocked = True
        else:
            # Compare as bytes: str comparison raises on non-ASCII input.
            valid = secrets.compare_digest(
                supplied.encode("utf-8"),
                SCAN_TOKEN.encode("utf-8"),
            )
            if not valid:
                recent.append(now)

        if recent:
            failed_attempts[key] = recent
        else:
            failed_attempts.pop(key, None)

        # Keep memory bounded.
        if len(failed_attempts) > 1000:
            for k in list(failed_attempts):
                failed_attempts[k] = [
                    t for t in failed_attempts[k]
                    if now - t < FAIL_WINDOW
                ]
                if not failed_attempts[k]:
                    del failed_attempts[k]

    if blocked:
        raise HTTPException(
            429,
            "অনেকবার ভুল token দেওয়া হয়েছে; কিছুক্ষণ পরে চেষ্টা করো.",
            headers={"Retry-After": str(int(FAIL_WINDOW))},
        )

    if not valid:
        raise HTTPException(401, "অনুমোদিত token প্রয়োজন.")


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
            400, "URL-এ credentials অনুমোদিত নয়."
        )

    try:
        if parsed.port not in (None, 443):
            raise HTTPException(
                400, "শুধু HTTPS port 443 অনুমোদিত."
            )
    except ValueError:
        raise HTTPException(400, "URL-এর port সঠিক নয়.")

    if parsed.path not in ("", "/"):
        raise HTTPException(
            400, "শুধু domain-এর root URL পরীক্ষা করা যাবে."
        )

    if parsed.query or parsed.fragment:
        raise HTTPException(
            400,
            "প্রথম সংস্করণে query ও fragment অনুমোদিত নয়."
        )

    try:
        host = canonical_host(parsed.hostname)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Domain নামটি সঠিক নয়.")

    if host not in ALLOWED_HOSTS:
        raise HTTPException(
            403, "এই domain অনুমোদিত তালিকায় নেই."
        )

    # Reject IP literals: this version accepts allowlisted
    # domain names only.
    try:
        ipaddress.ip_address(host)
        raise HTTPException(
            400, "IP address নয়, অনুমোদিত domain ব্যবহার করো."
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
                    "Domain non-public IP-তে resolve হয়েছে."
                )

            public_ips.append(str(ip))

        pinned_ip = public_ips[0]

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            400, "Domain DNS যাচাই করা যায়নি."
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


def analyze_tls(sock: ssl.SSLSocket) -> dict:
    """Read TLS version, cipher and certificate expiry. Passive: no
    extra connections, uses the handshake already performed."""
    info: dict = {}

    try:
        info["protocol"] = sock.version()
    except Exception:
        pass

    try:
        cipher = sock.cipher()
        if cipher:
            info["cipher"] = cipher[0]
    except Exception:
        pass

    try:
        cert = sock.getpeercert() or {}
        not_after = cert.get("notAfter")
        if not_after:
            expires_epoch = ssl.cert_time_to_seconds(not_after)
            expires_dt = datetime.fromtimestamp(
                expires_epoch, tz=timezone.utc
            )
            info["certificate_expires_at"] = expires_dt.isoformat()
            info["certificate_days_remaining"] = (
                expires_dt - datetime.now(timezone.utc)
            ).days
    except Exception:
        pass

    return info


def analyze_cookies(headers) -> list[dict]:
    """Report cookie NAMES and security flags only — never values,
    since a cookie value can be a live session secret."""
    results: list[dict] = []

    try:
        raw_cookies = headers.get_all("Set-Cookie") or []
    except AttributeError:
        raw_cookies = []

    for raw in raw_cookies[:20]:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue

        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue

        attr_names = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        samesite = None
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1].strip()
                break

        results.append({
            "name": name,
            "secure": "secure" in attr_names,
            "httponly": "httponly" in attr_names,
            "samesite": samesite,
        })

    return results


def analyze_info_leak(headers) -> list[dict]:
    found = []
    for name in INFO_LEAK_HEADERS:
        value = headers.get(name)
        if value:
            found.append({"header": name, "value": str(value)[:200]})
    return found


def analyze_header_quality(headers) -> list[str]:
    """Advisory notes about header VALUES, separate from simple
    presence/absence. Informational only — not a pass/fail score."""
    notes = []

    hsts = headers.get("strict-transport-security")
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age < 15552000:  # ~180 days
            notes.append(
                "HSTS-এর max-age ছয় মাসের কম; দীর্ঘ মেয়াদ বিবেচনা করুন."
            )
        if "includesubdomains" not in hsts.lower():
            notes.append("HSTS-এ includeSubDomains নেই.")

    csp = headers.get("content-security-policy")
    if csp:
        lowered = csp.lower()
        if "unsafe-inline" in lowered:
            notes.append(
                "CSP-তে 'unsafe-inline' আছে; এটি XSS সুরক্ষা দুর্বল করে."
            )
        if "unsafe-eval" in lowered:
            notes.append("CSP-তে 'unsafe-eval' আছে; এটি ঝুঁকিপূর্ণ হতে পারে.")

    return notes


def run_check(host: str, pinned_ip: str) -> dict:
    connection = PinnedHTTPSConnection(
        host,
        pinned_ip,
        timeout=8,
    )

    try:
        # Request only the root path; never follow redirects.
        # Only the status line and headers are read; the response
        # body is never downloaded.
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

        base = {
            "target": f"https://{host}/",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "redirect_followed": False,
            "tls": analyze_tls(connection.sock),
            "cookies": analyze_cookies(headers),
            "info_leak": analyze_info_leak(headers),
            "header_quality_notes": analyze_header_quality(headers),
        }

        if 300 <= status < 400:
            base.update({
                "note": "Redirect অনুসরণ করা হয়নি.",
                "findings": [],
                "limitations": [
                    "এটি সীমিত passive header check.",
                    "Redirect-এর গন্তব্য পরীক্ষা করা হয়নি.",
                ],
            })
            return base

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
                    "Header পাওয়া গেছে; এর মান ও কার্যকারিতা যাচাই করুন."
                ),
            })

        base.update({
            "findings": findings,
            "limitations": [
                "এটি সীমিত passive header check, পূর্ণ penetration test নয়.",
                "Header অনুপস্থিত থাকা একাই vulnerability প্রমাণ করে না.",
                "কোনো exploit বা login attempt চালানো হয়নি.",
                "শুধু domain-এর root path পরীক্ষা করা হয়েছে.",
                "TLS ও cookie তথ্য শুধু root path-এর response থেকে নেওয়া.",
            ],
        })
        return base

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
    request: Request,
    x_scan_token: str = Header(default=""),
):
    global last_scan_time

    require_token(request, x_scan_token)

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
            502, "পরীক্ষা ব্যর্থ হয়েছে; ফলাফল নিশ্চিত নয়."
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
    request: Request,
    x_scan_token: str = Header(default=""),
):
    require_token(request, x_scan_token)

    with audit_lock:
        return {"events": list(audit_log)}
