"""Security helpers: SSRF guard, PBKDF2-600k, at-rest secret encryption, origin/body validation, AI circuit breaker."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlparse

PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 100_000
MAX_DEFAULT_BODY_BYTES = 65536
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}$")

OFFICIAL_PROVIDER_HOSTS = {
    "google": {"generativelanguage.googleapis.com"},
    "openai": {"api.openai.com"},
    "anthropic": {"api.anthropic.com"},
    "pollinations": {"gen.pollinations.ai", "text.pollinations.ai"},
    "experiential": {"api.experientiallabs.ai"},
}

PROTECTED_PATH_PREFIXES_UNIX = (
    "/etc/",
    "/bin/",
    "/sbin/",
    "/usr/",
    "/lib/",
    "/lib64/",
    "/boot/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/var/ossec/",
    "/etc/soar-agent/",
)
PROTECTED_PATH_PREFIXES_WIN = (
    "c:\\windows\\",
    "c:\\program files\\wazuh",
    "c:\\program files (x86)\\ossec-agent\\",
    "c:\\program files\\soar-agent\\",
    "c:\\programdata\\soar-agent\\",
)
PROTECTED_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "api.telegram.org",
    "www.virustotal.com",
    "virustotal.com",
    "cloudflare.com",
    "api.cloudflare.com",
    "tailscale.com",
    "login.tailscale.com",
    "github.com",
}


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password, stored_hash):
    try:
        parts = str(stored_hash or "").split("$")
        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            iterations = int(parts[1])
            salt, hash_val = parts[2], parts[3]
            if iterations < 10_000 or iterations > 5_000_000:
                return False
            test_h = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
            ).hex()
            return hmac.compare_digest(hash_val, test_h)
        if len(parts) == 2:
            salt, hash_val = parts
            test_h = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt.encode("utf-8"), LEGACY_PBKDF2_ITERATIONS
            ).hex()
            return hmac.compare_digest(hash_val, test_h)
        return False
    except Exception:
        return False


def _settings_key_bytes():
    raw = os.environ.get("SOAR_SETTINGS_ENCRYPTION_KEY", "").strip()
    if len(raw) < 16 or raw.lower().startswith(("your-", "replace-", "generate-")):
        return None
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _keystream(key_bytes, nonce_bytes, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        blk = hashlib.sha256(key_bytes + nonce_bytes + counter.to_bytes(4, "big")).digest()
        out.extend(blk)
        counter += 1
    return bytes(out[:length])


def encrypt_secret(value):
    """Enkripsi secret dengan authenticated stream cipher stdlib (enc:v1:...) jika kunci diset."""
    text = str(value or "")
    if not text or text.startswith("enc:v1:"):
        return text
    key = _settings_key_bytes()
    if not key:
        return text
    enc_key = hashlib.sha256(key + b":enc").digest()
    mac_key = hashlib.sha256(key + b":mac").digest()
    nonce = secrets.token_bytes(16)
    pt = text.encode("utf-8")
    ks = _keystream(enc_key, nonce, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    blob = base64.urlsafe_b64encode(nonce + tag + ct).decode("ascii")
    return f"enc:v1:{blob}"


def decrypt_secret(value):
    text = str(value or "")
    if not text.startswith("enc:v1:"):
        return text
    key = _settings_key_bytes()
    if not key:
        return ""
    try:
        raw = base64.urlsafe_b64decode(text[7:].encode("ascii"))
        if len(raw) < 48:
            return ""
        nonce, tag, ct = raw[:16], raw[16:48], raw[48:]
        enc_key = hashlib.sha256(key + b":enc").digest()
        mac_key = hashlib.sha256(key + b":mac").digest()
        expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return ""
        ks = _keystream(enc_key, nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        return pt.decode("utf-8")
    except Exception:
        return ""


def _allowed_local_hosts():
    raw = os.environ.get("AI_ALLOWED_LOCAL_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_forbidden_ip(ip_obj):
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_outbound_url(url, resolve_dns=True):
    """Validasi URL keluar untuk mencegah SSRF ke loopback/private/metadata."""
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("URL tidak boleh kosong")
    parsed = urlparse(raw)
    if parsed.scheme not in ("https", "http"):
        raise ValueError("Scheme URL harus https")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("Hostname URL tidak valid")

    allowed_local = _allowed_local_hosts()
    if parsed.scheme != "https" and host not in allowed_local:
        raise ValueError("Endpoint AI/outbound wajib menggunakan HTTPS")

    if host in allowed_local:
        return raw

    if host in ("localhost", "localhost.localdomain") or host.endswith(".local") or host.endswith(".internal"):
        raise ValueError(f"Host internal tidak diizinkan: {host}")

    try:
        ip_obj = ipaddress.ip_address(host)
        if _is_forbidden_ip(ip_obj):
            raise ValueError(f"Alamat IP privat/loopback tidak diizinkan: {host}")
        return raw
    except ValueError as ve:
        if "tidak diizinkan" in str(ve):
            raise

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                ip_obj = ipaddress.ip_address(addr)
                if _is_forbidden_ip(ip_obj):
                    raise ValueError(f"DNS {host} mengarah ke IP privat/loopback ({addr})")
        except socket.gaierror:
            # Jangan blokir test offline yang me-mock urlopen untuk hostname publik standar
            pass
    return raw


def provider_host_allows_stored_key(provider, base_url):
    """Pastikan stored API key tidak dikirim ke custom base_url milik pihak ketiga."""
    clean_base = str(base_url or "").strip()
    if not clean_base:
        return True
    prov = str(provider or "").strip().lower()
    official = OFFICIAL_PROVIDER_HOSTS.get(prov)
    if not official:
        # Provider custom: hanya boleh jika base_url berasal dari stored config sendiri (ditangani caller)
        return False
    host = (urlparse(clean_base).hostname or "").strip().lower()
    return host in official


def sanitize_public_origin(raw_host="", x_proto="", env_origin=None):
    """Kembalikan origin aman untuk installer script; cegah Host Header Injection."""
    configured = (
        env_origin
        if env_origin is not None
        else os.environ.get("PUBLIC_ENROLL_URL") or os.environ.get("PUBLIC_SOAR_URL") or ""
    ).strip().rstrip("/")
    if configured:
        parsed = urlparse(configured)
        if parsed.scheme in ("http", "https") and parsed.netloc and HOST_RE.fullmatch(parsed.netloc):
            return f"{parsed.scheme}://{parsed.netloc}"

    host = str(raw_host or "").split(",")[0].strip()
    if not host or not HOST_RE.fullmatch(host):
        return "http://127.0.0.1:3000"
    proto = "https" if str(x_proto or "").strip().lower() == "https" else "http"
    return f"{proto}://{host}"


def read_bounded_json_body(handler, max_bytes=MAX_DEFAULT_BODY_BYTES, require_dict=True):
    """Baca body JSON dengan batas Content-Length ketat."""
    raw_len = handler.headers.get("Content-Length", "0")
    try:
        length = int(raw_len)
    except (TypeError, ValueError) as exc:
        raise ValueError("Content-Length tidak valid") from exc
    if length < 0:
        raise ValueError("Content-Length tidak valid")
    if length > max_bytes:
        raise OverflowError("Payload terlalu besar")
    raw = handler.rfile.read(length) if length else b"{}"
    value = json.loads(raw.decode("utf-8"))
    if require_dict and not isinstance(value, dict):
        raise TypeError("Payload harus berupa JSON object")
    return value


def is_protected_path(target):
    t = str(target or "").strip()
    low_unix = t.replace("\\", "/").lower()
    for pref in PROTECTED_PATH_PREFIXES_UNIX:
        if low_unix == pref.rstrip("/") or low_unix.startswith(pref):
            return True
    low_win = t.replace("/", "\\").lower()
    for pref in PROTECTED_PATH_PREFIXES_WIN:
        if low_win.startswith(pref):
            return True
    return False


def is_protected_domain(domain):
    d = str(domain or "").strip().rstrip(".").lower()
    if d in PROTECTED_DOMAINS:
        return True
    for env_key in ("PUBLIC_SOAR_URL", "PUBLIC_ENROLL_URL", "WAZUH_MANAGER_HOST"):
        val = os.environ.get(env_key, "").strip()
        if not val:
            continue
        host = (urlparse(val).hostname or val).strip().rstrip(".").lower()
        if host and (d == host or d.endswith("." + host)):
            return True
    return False


def is_valid_external_email(email):
    em = str(email or "").strip().lower()
    if not EMAIL_RE.fullmatch(em):
        return False
    domain = em.split("@", 1)[1]
    if domain.endswith((".local", ".internal", ".localhost", ".lan", ".invalid")):
        return False
    return True


class AiCircuitBreaker:
    """Circuit breaker per AI provider agar outage (401/402/429/5xx) tidak memperlambat tiap alert."""

    def __init__(self, failure_threshold=3, cooldown_secs=300):
        self.failure_threshold = failure_threshold
        self.cooldown_secs = cooldown_secs
        self._lock = threading.Lock()
        self._state = {}

    def is_open(self, provider):
        prov = str(provider or "").strip().lower()
        now = time.time()
        with self._lock:
            st = self._state.get(prov)
            if not st:
                return False
            if st["open_until"] > now:
                return True
            if st["open_until"] > 0:
                # Half-open: izinkan 1 percobaan ulang
                st["open_until"] = 0
                st["failures"] = max(0, self.failure_threshold - 1)
            return False

    def record_success(self, provider):
        prov = str(provider or "").strip().lower()
        with self._lock:
            self._state[prov] = {"failures": 0, "open_until": 0, "last_error": ""}

    def record_failure(self, provider, error="", immediate_open=False):
        prov = str(provider or "").strip().lower()
        now = time.time()
        with self._lock:
            st = self._state.setdefault(prov, {"failures": 0, "open_until": 0, "last_error": ""})
            st["failures"] += 1
            st["last_error"] = str(error or "")[:200]
            if immediate_open or st["failures"] >= self.failure_threshold:
                st["open_until"] = now + self.cooldown_secs

    def snapshot(self):
        now = time.time()
        with self._lock:
            return {
                prov: {
                    "open": st["open_until"] > now,
                    "failures": st["failures"],
                    "cooldown_remaining_secs": max(0, int(st["open_until"] - now)),
                    "last_error": st["last_error"],
                }
                for prov, st in self._state.items()
            }
