"""net_discovery — local network discovery for the Scan Oasis desktop agent.

Runs entirely on the client machine. Discovers live hosts via `nmap -sn`,
merges with the ARP/neighbor table, enriches each host with an OUI vendor
lookup, a heuristic device-type guess and a best-effort OS guess, then writes
the deduped results to Firestore under users/{uid}/network_devices.

Everything degrades gracefully: if nmap / arp / network / the vendor API are
missing or unreachable, it returns whatever it could gather and never raises
into the GUI.
"""

import json
import re
import shutil
import subprocess
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    from config import FIREBASE_PROJECT
except Exception:  # pragma: no cover - config should always import in app
    FIREBASE_PROJECT = ""


# ── Low-level helpers ────────────────────────────────────────────────────────

def _run(cmd, timeout=20):
    """Run a command, returning (stdout, stderr, returncode). Never raises."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return out.stdout.strip(), out.stderr.strip(), out.returncode
    except FileNotFoundError:
        return "", f"not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"timeout: {' '.join(cmd)}", 124
    except Exception as e:  # pragma: no cover - defensive
        return "", str(e), 1


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _norm_mac(mac: str) -> str:
    """Normalise a MAC to lower-case colon form, or '' if not a MAC."""
    if not mac:
        return ""
    m = _MAC_RE.search(mac)
    return m.group(1).lower() if m else ""


# ── Subnet detection ─────────────────────────────────────────────────────────

def detect_subnet() -> str:
    """Best-effort local subnet in CIDR form (e.g. 192.168.1.0/24).

    Parses `ip route` for the kernel-scope link route, falling back to deriving
    a /24 from the default-route source address. Returns '' if undetectable.
    """
    out, _, _ = _run(["ip", "route"], timeout=8)
    src_ip = ""
    for line in out.splitlines():
        # Prefer an explicit on-link subnet route: "192.168.1.0/24 dev ... scope link"
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+dev\s+\S+", line)
        if m and "scope link" in line and "/32" not in m.group(1):
            cidr = m.group(1)
            # Skip loopback / link-local
            if not cidr.startswith(("127.", "169.254.")):
                return cidr
        sm = re.search(r"\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if sm and not src_ip:
            src_ip = sm.group(1)

    if src_ip:
        parts = src_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""


# ── ARP / neighbor table ─────────────────────────────────────────────────────

def _arp_table() -> dict:
    """Return {ip: {'mac': ..., 'hostname': ...}} from arp -a / ip neigh.

    Tries `arp -a` first (gives hostnames), falls back to `ip neigh` which is
    available on modern Linux without net-tools.
    """
    table: dict = {}

    if shutil.which("arp"):
        out, _, rc = _run(["arp", "-a"], timeout=10)
        if rc == 0 and out:
            # "hostname (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            for line in out.splitlines():
                ip_m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
                mac = _norm_mac(line)
                if not ip_m:
                    continue
                ip = ip_m.group(1)
                host = line.split("(")[0].strip()
                if host in ("?", ""):
                    host = ""
                entry = table.setdefault(ip, {"mac": "", "hostname": ""})
                if mac:
                    entry["mac"] = mac
                if host:
                    entry["hostname"] = host

    # Always also consult the kernel neighbor table.
    out, _, rc = _run(["ip", "-j", "neigh", "show"], timeout=8)
    if rc == 0 and out:
        try:
            for n in json.loads(out):
                ip = n.get("dst", "")
                if not ip or ip.startswith("fe80") or ":" in ip:
                    continue
                mac = _norm_mac(n.get("lladdr", ""))
                entry = table.setdefault(ip, {"mac": "", "hostname": ""})
                if mac and not entry["mac"]:
                    entry["mac"] = mac
        except (json.JSONDecodeError, TypeError):
            pass

    return table


# ── nmap host discovery ──────────────────────────────────────────────────────

def _emit(progress, msg: str):
    """Safely forward a live status line to an optional progress callback."""
    if progress:
        try:
            progress(msg)
        except Exception:  # pragma: no cover - never let UI callbacks break a scan
            pass


def _stream(cmd, on_line, timeout=240):
    """Run a command, invoking on_line(line) for each stdout line as it arrives.

    Returns the full captured stdout. Streaming lets the GUI show live progress
    of what nmap is currently probing instead of blocking until completion.
    Never raises — returns whatever was captured before any error/timeout.
    """
    lines: list = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        return ""
    except Exception:  # pragma: no cover - defensive
        return ""

    def _kill_after():
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()

    threading.Thread(target=_kill_after, daemon=True).start()
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip("\n")
            lines.append(line)
            if on_line:
                try:
                    on_line(line)
                except Exception:  # pragma: no cover
                    pass
    except Exception:  # pragma: no cover
        pass
    finally:
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    return "\n".join(lines)


def _nmap_hosts(subnet: str, progress=None) -> list:
    """Run `nmap -sn` and parse hosts into [{ip, mac, hostname, vendor}].

    Streams nmap output so the desktop GUI can show, live, which host is being
    probed. MAC + vendor lines ("MAC Address: AA:BB:.. (Vendor)") only appear
    when nmap runs with privileges on the local LAN, so they're treated as
    optional.
    """
    if not shutil.which("nmap") or not subnet:
        return []

    hosts: list = []
    current: dict = {}

    def _flush():
        if current.get("ip"):
            hosts.append(dict(current))

    def _on_line(line: str):
        if line.startswith("Nmap scan report for"):
            _flush()
            current.clear()
            rest = line[len("Nmap scan report for "):].strip()
            m = re.search(r"\(([^)]+)\)", rest)
            if m:
                current["hostname"] = rest[:rest.index("(")].strip()
                current["ip"] = m.group(1).strip()
            else:
                current["hostname"] = ""
                current["ip"] = rest
            current["mac"] = ""
            current["vendor"] = ""
            label = current["ip"]
            if current["hostname"]:
                label = f"{current['hostname']} ({current['ip']})"
            _emit(progress, f"Host up · {label}")
        elif "MAC Address:" in line:
            mac = _norm_mac(line)
            if mac:
                current["mac"] = mac
            vm = re.search(r"\(([^)]+)\)\s*$", line)
            if vm:
                current["vendor"] = vm.group(1).strip()

    # --stats-every prints "About N% done" lines we surface as progress.
    _stream(["nmap", "-sn", "-T4", "--stats-every", "2s", subnet],
            _on_line, timeout=240)
    _flush()
    return hosts


# ── nmap per-host port / service / OS enrichment ─────────────────────────────

# Friendly names for the most common ports, so a device card reads
# "22/tcp ssh, 80/tcp http" without needing nmap's service-detection probes.
_PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1723: "pptp", 1883: "mqtt",
    1900: "upnp", 2049: "nfs", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5000: "upnp", 5060: "sip", 5353: "mdns", 5432: "postgres",
    5555: "adb", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8008: "http", 8080: "http-proxy", 8443: "https-alt", 8883: "mqtts",
    9000: "http-alt", 9100: "jetdirect", 32400: "plex",
}


def _nmap_enrich(ip: str, progress=None) -> dict:
    """Best-effort port / service / OS probe of a single host.

    Returns {open_ports: [...], services: [...], os_details: str}. Uses a fast
    top-ports TCP-connect scan (no root needed) and adds OS fingerprinting when
    nmap can run privileged. Always returns a dict; never raises.
    """
    result = {"open_ports": [], "services": [], "os_details": ""}
    if not shutil.which("nmap") or not ip:
        return result

    _emit(progress, f"Probing services on {ip}…")
    # -F = top 100 ports, -T4 fast, --version-light for light service banners.
    # -O (OS detect) only works as root; harmless to request — nmap warns and
    # skips it unprivileged, and the connect scan still returns ports.
    out = _stream(
        ["nmap", "-F", "-T4", "--version-light", "-O", "--osscan-guess", ip],
        None, timeout=120)
    if not out:
        # Retry without -O in case the privileged combo aborted early.
        out = _stream(["nmap", "-F", "-T4", ip], None, timeout=90)

    for line in out.splitlines():
        # "22/tcp   open  ssh     OpenSSH 9.6"
        pm = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)?\s*(.*)$", line.strip())
        if pm:
            port = int(pm.group(1))
            proto = pm.group(2)
            svc = (pm.group(3) or _PORT_NAMES.get(port, "")).strip()
            banner = pm.group(4).strip()
            label = f"{port}/{proto}"
            if svc and svc not in ("open", "?"):
                label += f" {svc}"
            result["open_ports"].append(label)
            if svc and svc not in ("open", "?"):
                result["services"].append(f"{svc} {banner}".strip())
        # "OS details: Linux 5.4 - 5.15" / "Running: Linux 5.X"
        elif line.startswith("OS details:"):
            result["os_details"] = line.split(":", 1)[1].strip()
        elif line.startswith("Running:") and not result["os_details"]:
            result["os_details"] = line.split(":", 1)[1].strip()
        elif line.startswith("Aggressive OS guesses:") and not result["os_details"]:
            result["os_details"] = line.split(":", 1)[1].strip().split(",")[0]

    if result["open_ports"]:
        _emit(progress, f"{ip} · {len(result['open_ports'])} open port(s)")
    return result


# ── OUI vendor lookup (macvendors.com) ───────────────────────────────────────

_VENDOR_CACHE: dict = {}


def mac_vendor(mac: str) -> str:
    """Look up the OUI vendor for a MAC via api.macvendors.com.

    Returns the vendor string, or '' on any failure / unknown / no network.
    Results (including misses) are cached per-process by OUI prefix to respect
    the API's rate limit.
    """
    mac = _norm_mac(mac)
    if not mac:
        return ""
    oui = mac[:8]  # first three octets identify the vendor
    if oui in _VENDOR_CACHE:
        return _VENDOR_CACHE[oui]

    vendor = ""
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac}",
            headers={"User-Agent": "ScanOasis/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            vendor = resp.read().decode("utf-8", "replace").strip()
            if len(vendor) > 80 or "<" in vendor:  # guard against HTML error bodies
                vendor = ""
    except urllib.error.HTTPError:
        vendor = ""          # 404 = unknown OUI, 429 = rate limited
    except Exception:
        vendor = ""           # timeout / no network / DNS

    _VENDOR_CACHE[oui] = vendor
    return vendor


# ── Heuristics: device type & OS ─────────────────────────────────────────────

_DEVICE_KEYWORDS = [
    ("Router/Gateway", ("cisco", "netgear", "tp-link", "tplink", "tp link",
                        "ubiquiti", "mikrotik", "asustek", "asus", "d-link",
                        "dlink", "zyxel", "arris", "technicolor", "fritz",
                        "avm", "huawei", "router", "gateway", "openwrt", "eero")),
    ("Apple device", ("apple",)),
    ("Raspberry Pi", ("raspberry",)),
    ("Printer", ("hewlett", "hp inc", "canon", "epson", "brother", "lexmark",
                 "xerox", "kyocera", "printer")),
    ("Android/Mobile", ("samsung", "xiaomi", "huawei", "oppo", "vivo",
                        "oneplus", "motorola", "google", "android", "realme",
                        "nokia", "htc", "lg electronics")),
    ("IoT", ("espressif", "tuya", "sonoff", "shelly", "nest", "ring",
             "amazon", "philips", "hue", "wyze", "tp-link smart", "smart",
             "camera", "thermostat", "roku", "chromecast", "sonos")),
    ("PC/Server", ("intel", "dell", "lenovo", "micro-star", "msi", "gigabyte",
                   "asrock", "supermicro", "realtek", "vmware", "virtualbox",
                   "qemu", "microsoft", "pc engines")),
]


def guess_device_type(vendor: str, hostname: str = "") -> str:
    """Map a vendor / hostname to a coarse device-type label."""
    hay = f"{vendor or ''} {hostname or ''}".lower()
    if not hay.strip():
        return "Unknown"
    for label, keywords in _DEVICE_KEYWORDS:
        if any(k in hay for k in keywords):
            return label
    return "Unknown"


def _ping_ttl(ip: str) -> int | None:
    """Single-packet ping; return the observed TTL or None."""
    if not ip or not shutil.which("ping"):
        return None
    out, _, rc = _run(["ping", "-c", "1", "-W", "1", ip], timeout=4)
    if rc != 0 and not out:
        return None
    m = re.search(r"ttl=(\d+)", out, re.I)
    return int(m.group(1)) if m else None


def guess_os(ip: str, mac: str = "", vendor: str = "", hostname: str = "") -> str:
    """Best-effort OS guess from vendor heuristics + a single ping's TTL.

    No root required. Vendor wins when it's unambiguous (Apple, Raspberry Pi,
    routers); otherwise the TTL of one echo reply hints at the OS family
    (~64 Linux/Unix/macOS, ~128 Windows, ~255 network gear).
    """
    hay = f"{vendor or ''} {hostname or ''}".lower()
    if "apple" in hay:
        return "macOS / iOS"
    if "raspberry" in hay:
        return "Linux (Raspberry Pi OS)"
    dtype = guess_device_type(vendor, hostname)
    if dtype == "Router/Gateway":
        return "Embedded/Network OS"
    if dtype == "Printer":
        return "Embedded (printer firmware)"
    if dtype == "Android/Mobile":
        return "Android"

    ttl = _ping_ttl(ip)
    if ttl is not None:
        if ttl <= 64:
            return "Linux/Unix/macOS"
        if ttl <= 128:
            return "Windows"
        return "Network device"
    return "Unknown"


# ── Top-level discovery ──────────────────────────────────────────────────────

def discover(subnet: str | None = None, progress=None, enrich: bool = True) -> list:
    """Discover devices on the local network.

    Returns a list of dicts:
      {ip, mac, vendor, device_type, os_guess, os_details, open_ports,
       services, hostname, source, first_seen, last_seen}

    Merges nmap host-discovery with the ARP/neighbor table, enriches each entry
    with vendor/device-type/OS guesses and (when enrich=True) a per-host
    port/service/OS probe, then de-duplicates by MAC (falling back to IP when the
    MAC is unknown). `progress` is an optional callable(str) that receives live
    status lines so a GUI can show what is currently being scanned. Always
    returns a list — never raises.
    """
    if not subnet:
        _emit(progress, "Detecting local subnet…")
        subnet = detect_subnet()

    _emit(progress, "Reading ARP / neighbor table…")
    arp = _arp_table()
    _emit(progress, f"Sweeping {subnet or 'local network'} for live hosts…")
    nmap_hosts = _nmap_hosts(subnet, progress) if subnet else []

    # Merge by IP first so ARP hostnames/MACs and nmap MACs reinforce each other.
    by_ip: dict = {}

    def _merge(ip, mac="", hostname="", vendor=""):
        if not ip:
            return
        rec = by_ip.setdefault(ip, {"ip": ip, "mac": "", "hostname": "", "vendor": ""})
        mac = _norm_mac(mac)
        if mac:
            rec["mac"] = mac
        if hostname and not rec["hostname"]:
            rec["hostname"] = hostname
        if vendor and not rec["vendor"]:
            rec["vendor"] = vendor

    for h in nmap_hosts:
        _merge(h.get("ip", ""), h.get("mac", ""),
               h.get("hostname", ""), h.get("vendor", ""))
    for ip, info in arp.items():
        _merge(ip, info.get("mac", ""), info.get("hostname", ""))

    now = _now_iso()
    devices: list = []
    total = len(by_ip)
    for idx, (ip, rec) in enumerate(by_ip.items(), 1):
        mac = rec["mac"]
        vendor = rec["vendor"] or (mac_vendor(mac) if mac else "")
        hostname = rec["hostname"]
        dev = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "device_type": guess_device_type(vendor, hostname),
            "os_guess": guess_os(ip, mac, vendor, hostname),
            "os_details": "",
            "open_ports": [],
            "services": [],
            "hostname": hostname,
            "source": "nmap" if mac or vendor else "arp",
            "first_seen": now,
            "last_seen": now,
        }
        if enrich:
            _emit(progress, f"[{idx}/{total}] Fingerprinting {ip}…")
            extra = _nmap_enrich(ip, progress)
            dev["open_ports"] = extra["open_ports"]
            dev["services"] = extra["services"]
            dev["os_details"] = extra["os_details"]
            # A concrete nmap OS fingerprint beats the TTL/vendor heuristic.
            if extra["os_details"]:
                dev["os_guess"] = extra["os_details"]
        devices.append(dev)

    # Dedup by MAC (or ip_<ip> when MAC unknown); keep the richest record.
    deduped: dict = {}
    for d in devices:
        key = d["mac"] or f"ip_{d['ip']}"
        if key in deduped:
            cur = deduped[key]
            for f in ("vendor", "hostname", "os_details"):
                if not cur.get(f) and d.get(f):
                    cur[f] = d[f]
            for f in ("open_ports", "services"):
                if not cur.get(f) and d.get(f):
                    cur[f] = d[f]
        else:
            deduped[key] = d

    out = list(deduped.values())
    out.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")
                                 if p.isdigit()) or (0,))
    return out


# ── Firestore write (deduped, REST) ──────────────────────────────────────────

def _sanitize_doc_id(device: dict) -> str:
    """Firestore doc id: sanitized MAC, or ip_<ip> when MAC unknown."""
    mac = device.get("mac", "")
    if mac:
        return mac.replace(":", "_")
    return "ip_" + device.get("ip", "unknown").replace(".", "_")


def _to_fields(device: dict) -> dict:
    """Map a device dict to Firestore typed fields.

    Strings stay stringValue; open_ports/services become arrayValues so the web
    dashboard reads them back as native arrays.
    """
    str_keys = ("ip", "mac", "vendor", "device_type", "os_guess", "os_details",
                "hostname", "source", "first_seen", "last_seen")
    fields = {k: {"stringValue": str(device.get(k, "") or "")} for k in str_keys}
    for k in ("open_ports", "services"):
        vals = device.get(k) or []
        fields[k] = {"arrayValue": {"values": [
            {"stringValue": str(v)} for v in vals if v]}}
    return fields


def _device_url(uid: str, doc_id: str) -> str:
    return (f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}"
            f"/databases/(default)/documents/users/{uid}/network_devices/{doc_id}")


def _fetch_first_seen(id_token: str, uid: str, doc_id: str):
    """Return the existing doc's first_seen string, or None if doc absent."""
    req = urllib.request.Request(
        _device_url(uid, doc_id),
        headers={"Authorization": f"Bearer {id_token}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            fs = data.get("fields", {}).get("first_seen", {})
            return fs.get("stringValue")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


def _patch_device(id_token: str, uid: str, doc_id: str, fields: dict):
    """Create/overwrite a device document via Firestore PATCH (upsert).

    Returns (ok, error_detail) so the caller can surface *why* a write failed
    (e.g. '403: Missing or insufficient permissions' = a security-rules problem).
    """
    url = _device_url(uid, doc_id)
    body = json.dumps({"fields": fields}).encode()
    req = urllib.request.Request(
        url, data=body, method="PATCH",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {id_token}"})
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True, None
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")
        except Exception:
            detail = ""
        return False, f"HTTP {e.code}: {detail[:400]}"
    except Exception as e:
        return False, str(e)


def save_devices(id_token: str, uid: str, devices: list) -> dict:
    """Write discovered devices to users/{uid}/network_devices, deduped.

    For each device: if a doc with the same id (sanitized MAC / ip_<ip>) already
    exists, UPDATE ip/vendor/device_type/os_guess/hostname/last_seen but PRESERVE
    the original first_seen. Otherwise create it with first_seen == last_seen.

    Mirrors scanner.firestore_save's REST/auth approach. Returns a summary dict
    {created, updated, failed}; never raises.
    """
    summary = {"created": 0, "updated": 0, "failed": 0, "error": None}
    if not id_token or not uid or not FIREBASE_PROJECT:
        summary["failed"] = len(devices)
        summary["error"] = "missing id_token / uid / FIREBASE_PROJECT"
        return summary

    for d in devices:
        try:
            doc_id = _sanitize_doc_id(d)
            existing_first_seen = _fetch_first_seen(id_token, uid, doc_id)
            fields = _to_fields(d)
            if existing_first_seen:
                # Preserve original first_seen, refresh everything else.
                fields["first_seen"] = {"stringValue": existing_first_seen}
            ok, err = _patch_device(id_token, uid, doc_id, fields)
            if ok:
                summary["updated" if existing_first_seen else "created"] += 1
            else:
                summary["failed"] += 1
                if err and not summary["error"]:
                    summary["error"] = err
        except Exception as e:
            summary["failed"] += 1
            if not summary["error"]:
                summary["error"] = str(e)
    return summary


def discover_and_save(id_token: str, uid: str, subnet: str | None = None,
                      progress=None) -> tuple:
    """Convenience: discover then persist. Returns (devices, summary)."""
    devices = discover(subnet, progress=progress)
    summary = save_devices(id_token, uid, devices)
    return devices, summary


# ── Standalone diagnostics ────────────────────────────────────────────────────
# Discover only:        python net_discovery.py
# Test the Firestore write end-to-end (prints the exact error on failure):
#                       python net_discovery.py <email> <password>
if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3:
        email, password = sys.argv[1], sys.argv[2]
        try:
            from scanner import firebase_login
        except Exception as e:
            print("Could not import firebase_login from scanner:", e)
            sys.exit(1)

        print(f"Project: {FIREBASE_PROJECT!r}")
        print(f"Logging in as {email} …")
        token, uid = firebase_login(email, password)
        if not token:
            print("LOGIN FAILED:", uid)
            sys.exit(1)
        print("Login OK. uid =", uid)

        test_device = {
            "ip": "10.255.255.254", "mac": "00:00:5e:00:53:af", "vendor": "SELFTEST",
            "device_type": "PC/Server", "os_guess": "Linux", "os_details": "",
            "hostname": "netdiscovery-selftest", "open_ports": [], "services": [],
            "source": "selftest", "first_seen": _now_iso(), "last_seen": _now_iso(),
        }
        print(f"Writing 1 test device to users/{uid}/network_devices/ …")
        result = save_devices(token, uid, [test_device])
        print("RESULT:", result)
        if result.get("error"):
            print("\n>>> WRITE FAILED. The error above tells us why.")
            print(">>> '403 / PERMISSION_DENIED' means Firestore security rules block")
            print(">>> writes to users/{uid}/network_devices. '401' means the token expired.")
        else:
            print("\n>>> WRITE OK. Refresh the dashboard Devices tab — the self-test")
            print(">>> device should appear. (You can delete it from Firestore after.)")
    else:
        print(f"Subnet: {detect_subnet()}")
        for d in discover():
            print(d)
