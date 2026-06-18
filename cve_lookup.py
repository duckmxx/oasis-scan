"""CVE lookup for Scan Oasis — no AI, pure data sources.

Sources:
  Arch Linux     : https://security.archlinux.org/json  (full advisory list)
  Debian / Ubuntu: https://api.osv.dev/v1/querybatch   (ecosystem: Debian / Ubuntu)
  RHEL / Fedora  : https://api.osv.dev/v1/querybatch   (ecosystem: Fedora)
"""

import json
import re
import urllib.request
import urllib.error

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_OSV_BATCH = 500   # max queries per OSV request

_VULN_TYPES = [
    ("RCE",      ["arbitrary code execution", "remote code execution", "code execution", "execute arbitrary"]),
    ("DoS",      ["denial of service", "memory exhaustion", "null pointer", "infinite loop", "crash", "out of memory", "resource exhaustion"]),
    ("EscPriv",  ["privilege escalation", "gain root", "local privilege", "escalation of privilege", "gain elevated"]),
    ("InfoDisc", ["information disclosure", "sensitive information", "memory leak", "data leak", "information leak", "uninitialized memory"]),
    ("XSS",      ["cross-site scripting", " xss", "html injection", "script injection"]),
    ("SQLi",     ["sql injection"]),
    ("Overflow", ["buffer overflow", "stack overflow", "heap overflow", "integer overflow", "out-of-bounds write", "stack-based buffer", "heap-based buffer"]),
    ("Bypass",   ["bypass", "restriction bypass", "authentication bypass", "access control bypass", "improper authentication"]),
    ("Traversal",["directory traversal", "path traversal"]),
    ("UAF",      ["use after free", "use-after-free"]),
    ("Corrupt",  ["memory corruption", "heap corruption", "type confusion"]),
]

_REMOTE_KW = ["remote", "network", "unauthenticated", "internet", "http", "web server", "listening", "socket", "tcp", "udp", "attacker-controlled"]
_LOCAL_KW  = ["local user", "local attacker", "local access", "physical access", "console access", "authenticated local"]


def _classify_type(text: str) -> str:
    t = text.lower()
    for label, kws in _VULN_TYPES:
        if any(k in t for k in kws):
            return label
    return ""


def _classify_vector(text: str) -> str:
    t = text.lower()
    if any(k in t for k in _REMOTE_KW):
        return "REMOTE"
    if any(k in t for k in _LOCAL_KW):
        return "LOCAL"
    return ""


# ── Public entry point ────────────────────────────────────────────────────────

def lookup_cves(report: dict) -> list[dict]:
    """Return a sorted list of CVE dicts for packages in *report*."""
    family = report.get("distro_family", "unknown")
    pkgs   = (report.get("packages") or {}).get("packages") or []
    if not pkgs:
        return []

    if family == "arch":
        return _arch_cves(pkgs)

    if family == "debian":
        os_id = (report.get("os") or {}).get("id", "")
        eco   = "Ubuntu" if os_id in ("ubuntu", "linuxmint", "pop") else "Debian"
        return _osv_cves(pkgs, eco)

    if family == "rhel":
        return _osv_cves(pkgs, "Fedora")

    return _osv_cves(pkgs, "Debian")   # best-effort fallback


# ── Arch Linux Security Tracker ───────────────────────────────────────────────

def _arch_cves(packages: list[dict]) -> list[dict]:
    pkg_map = {p["name"]: p.get("version", "") for p in packages}

    try:
        req = urllib.request.Request(
            "https://security.archlinux.org/json",
            headers={"User-Agent": "oasis-scan/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            advisories = json.loads(r.read())
    except Exception:
        return []

    seen   : set[tuple] = set()
    result : list[dict] = []

    for adv in advisories:
        status = (adv.get("status") or "").lower()
        if status == "not affected":
            continue

        severity = (adv.get("severity") or "unknown").lower()
        fixed    = adv.get("fixed") or None
        adv_name = adv.get("name", "")
        issues   = adv.get("issues") or [adv_name]
        summary  = adv.get("type") or adv.get("description") or ""

        for pkg_name in (adv.get("packages") or []):
            if pkg_name not in pkg_map:
                continue

            installed = pkg_map[pkg_name]

            # Skip if the installed version is already >= the fixed version
            if fixed and installed:
                try:
                    if _vercmp(installed, fixed) >= 0:
                        continue
                except Exception:
                    pass  # unknown comparison → keep (conservative)

            for cve_id in issues:
                key = (cve_id, pkg_name)
                if key in seen:
                    continue
                seen.add(key)

                # CVE IDs have a direct Arch tracker page; non-CVE advisory IDs
                # use the advisory path.  NVD is always a reliable fallback.
                if cve_id.startswith("CVE-"):
                    cve_url = f"https://security.archlinux.org/{cve_id}"
                elif adv_name:
                    cve_url = f"https://security.archlinux.org/advisory/{adv_name}"
                else:
                    cve_url = ""

                result.append({
                    "id":        cve_id,
                    "package":   pkg_name,
                    "installed": installed or "?",
                    "fixed":     fixed or "?",
                    "severity":  severity,
                    "cvss":      None,
                    "summary":   summary,
                    "url":       cve_url,
                    "type":      _classify_type(summary),
                    "vector":    _classify_vector(summary),
                })

    result.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 4))
    return result


def _vercmp(v1: str, v2: str) -> int:
    """Simplified vercmp. Returns <0 if v1 < v2, 0 if equal, >0 if v1 > v2."""
    def strip(v: str) -> str:
        v = re.sub(r"^\d+:", "", str(v))   # drop epoch
        v = re.sub(r"-\d+$",  "", v)        # drop pkgrel
        return v

    def parts(v: str) -> list:
        return [int(x) if x.isdigit() else x
                for x in re.split(r"(\d+)", strip(v)) if x]

    p1, p2 = parts(v1), parts(v2)
    for a, b in zip(p1, p2):
        if type(a) is not type(b):
            return 1 if isinstance(a, int) else -1
        if a < b: return -1
        if a > b: return 1
    return len(p1) - len(p2)


# ── OSV API (Debian / Ubuntu / Fedora / fallback) ────────────────────────────

def _osv_cves(packages: list[dict], ecosystem: str) -> list[dict]:
    seen   : set[tuple] = set()
    result : list[dict] = []

    # Cap at 2000 packages to keep the request time reasonable
    packages = packages[:2000]

    for off in range(0, len(packages), _OSV_BATCH):
        chunk   = packages[off : off + _OSV_BATCH]
        queries = [
            {"package": {"name": p["name"], "ecosystem": ecosystem},
             "version": p.get("version", "")}
            for p in chunk
        ]
        try:
            body = json.dumps({"queries": queries}).encode()
            req  = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": "oasis-scan/1.0"},
            )
            with urllib.request.urlopen(req, timeout=45) as r:
                data = json.loads(r.read())
        except Exception:
            continue

        for j, res in enumerate(data.get("results", [])):
            pkg = chunk[j]
            for vuln in res.get("vulns", []):
                vid = vuln.get("id", "")
                key = (vid, pkg["name"])
                if key in seen:
                    continue
                seen.add(key)

                sev   = (vuln.get("database_specific", {}).get("severity") or "unknown").lower()
                cvss  = _extract_cvss(vuln)
                fixed = _extract_fixed(vuln)

                summary = vuln.get("summary", "")
                result.append({
                    "id":        vid,
                    "package":   pkg["name"],
                    "installed": pkg.get("version", "?"),
                    "fixed":     fixed or "?",
                    "severity":  sev,
                    "cvss":      cvss,
                    "summary":   summary,
                    "url":       f"https://osv.dev/vulnerability/{vid}",
                    "type":      _classify_type(summary),
                    "vector":    _classify_vector(summary),
                })

    result.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 4))
    return result


def _extract_cvss(vuln: dict) -> float | None:
    db = vuln.get("database_specific", {})
    cv = db.get("cvss", {})
    if isinstance(cv, dict):
        score = cv.get("baseScore") or cv.get("score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    return None


def _extract_fixed(vuln: dict) -> str | None:
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return str(ev["fixed"])
    return None
