"""Package integrity checks for Oasis Scan.

Three checks, no AI required:

1. File integrity  — package manager verifies installed files against
                     its own database (pacman -Qkk / debsums -c / rpm -Va)
2. Malicious pkgs  — OSV query filtered for MAL-* IDs (supply-chain /
                     typosquat reports from the OSSF malicious-packages DB)
3. Modified bins   — recently changed files inside /usr/bin, /usr/sbin,
                     /bin, /sbin that are owned by a package (possible
                     binary replacement indicator)
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

_BIN_PATHS  = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
_RECENT_DAYS = 7          # flag binaries modified in the last N days
_OSV_BATCH   = 500


# ── Public entry point ────────────────────────────────────────────────────────

def run_integrity(report: dict) -> dict:
    family = report.get("distro_family", "unknown")
    pkgs   = (report.get("packages") or {}).get("packages") or []

    file_issues  = _file_integrity(family)
    malicious    = _malicious_packages(pkgs, family)
    modified_bins = _modified_binaries(family)

    return {
        "file_integrity":  file_issues,
        "malicious":       malicious,
        "modified_bins":   modified_bins,
        "summary": {
            "file_issues":       len(file_issues),
            "malicious_pkgs":    len(malicious),
            "modified_bin_files": len(modified_bins),
            "clean": len(file_issues) == 0 and len(malicious) == 0 and len(modified_bins) == 0,
        },
    }


# ── 1. File integrity via package manager ────────────────────────────────────

def _file_integrity(family: str) -> list[dict]:
    if family == "arch":
        return _pacman_integrity()
    if family == "debian":
        return _debsums_integrity()
    if family == "rhel":
        return _rpm_integrity()
    return []


def _pacman_integrity() -> list[dict]:
    """pacman -Qkk: verify checksums of all installed package files."""
    try:
        proc = subprocess.run(
            ["pacman", "-Qkk"],
            capture_output=True, text=True, timeout=120, check=False
        )
        # pacman writes warnings to stdout; each warning line looks like:
        # warning: /usr/bin/foo: size mismatch (expected 12345, found 67890)
        # warning: /etc/bar: modification time differs
        issues = []
        combined = proc.stdout + proc.stderr
        for line in combined.splitlines():
            line = line.strip()
            if not line.startswith("warning:"):
                continue
            # strip "warning: "
            msg = line[len("warning:"):].strip()
            # extract file path (everything before the first ": " after the path)
            parts = msg.split(": ", 1)
            path  = parts[0].strip()
            detail = parts[1].strip() if len(parts) > 1 else ""

            # Resolve which package owns this file
            pkg = _pacman_owner(path)

            issues.append({
                "package": pkg or "?",
                "file":    path,
                "issue":   _classify_issue(detail),
                "detail":  detail,
            })
        return issues
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return [{"package": "?", "file": "?", "issue": "timeout",
                 "detail": "pacman -Qkk timed out after 120 s"}]


def _pacman_owner(path: str) -> str | None:
    try:
        out = subprocess.run(
            ["pacman", "-Qo", path],
            capture_output=True, text=True, timeout=5, check=False
        ).stdout
        # Output: "/usr/bin/foo is owned by bar 1.2.3-1"
        m = re.search(r"owned by (\S+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _debsums_integrity() -> list[dict]:
    """debsums -c: report files whose MD5 sum differs."""
    try:
        proc = subprocess.run(
            ["debsums", "-c"],
            capture_output=True, text=True, timeout=180, check=False
        )
        issues = []
        for line in (proc.stdout + proc.stderr).splitlines():
            line = line.strip()
            if not line:
                continue
            # debsums -c output: "/path/to/file  FAILED"  or just the path
            path   = line.split()[0]
            detail = "MD5 checksum mismatch"
            pkg    = _dpkg_owner(path)
            issues.append({
                "package": pkg or "?",
                "file":    path,
                "issue":   "checksum_mismatch",
                "detail":  detail,
            })
        return issues
    except FileNotFoundError:
        # debsums not installed — try dpkg --verify as fallback
        return _dpkg_verify()
    except subprocess.TimeoutExpired:
        return []


def _dpkg_verify() -> list[dict]:
    try:
        proc = subprocess.run(
            ["dpkg", "--verify"],
            capture_output=True, text=True, timeout=120, check=False
        )
        issues = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("??"):
                continue
            parts = line.split()
            path  = parts[-1] if parts else line
            detail = line
            issues.append({
                "package": _dpkg_owner(path) or "?",
                "file":    path,
                "issue":   _classify_issue(detail),
                "detail":  detail,
            })
        return issues
    except Exception:
        return []


def _dpkg_owner(path: str) -> str | None:
    try:
        out = subprocess.run(
            ["dpkg", "-S", path],
            capture_output=True, text=True, timeout=5, check=False
        ).stdout
        m = re.match(r"^([^:]+):", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _rpm_integrity() -> list[dict]:
    """rpm -Va: verify all installed RPM packages."""
    try:
        proc = subprocess.run(
            ["rpm", "-Va"],
            capture_output=True, text=True, timeout=120, check=False
        )
        issues = []
        # rpm -Va output: each line is "<flags>  <path>"
        # Flags: S=size, M=mode, 5=MD5, D=device, L=symlink, U=user, G=group, T=mtime
        for line in proc.stdout.splitlines():
            if not line.strip() or re.match(r"^\.{8,}", line):
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            flags, path = parts[0], parts[1].lstrip("cld ")
            path = path.strip()
            detail = _rpm_flag_description(flags)
            issues.append({
                "package": _rpm_owner(path) or "?",
                "file":    path,
                "issue":   _classify_issue(flags),
                "detail":  detail,
            })
        return issues
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []


def _rpm_owner(path: str) -> str | None:
    try:
        out = subprocess.run(
            ["rpm", "-qf", path],
            capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip()
        return out if out and "not owned" not in out else None
    except Exception:
        return None


def _rpm_flag_description(flags: str) -> str:
    desc = []
    mapping = {"5": "MD5 mismatch", "S": "size changed", "M": "permissions changed",
               "U": "owner changed", "G": "group changed", "T": "mtime changed",
               "D": "device major/minor changed", "L": "symlink changed"}
    for ch, label in mapping.items():
        if ch in flags:
            desc.append(label)
    return ", ".join(desc) if desc else flags


def _classify_issue(detail: str) -> str:
    d = detail.lower()
    if "md5" in d or "checksum" in d or "hash" in d:
        return "checksum_mismatch"
    if "size" in d:
        return "size_mismatch"
    if "missing" in d or "not found" in d:
        return "missing_file"
    if "permission" in d or "mode" in d:
        return "permission_changed"
    if "mtime" in d or "modification time" in d or "time" in d:
        return "mtime_changed"
    return "altered"


# ── 2. Malicious package detection via OSV (MAL-* IDs) ───────────────────────

def _malicious_packages(packages: list[dict], family: str) -> list[dict]:
    """Query OSV for each installed package and filter for MAL-* IDs."""
    eco_map = {"arch": "Linux", "debian": "Debian", "rhel": "Fedora"}
    eco     = eco_map.get(family, "Debian")

    packages = packages[:2000]
    found: list[dict] = []
    seen: set[tuple]  = set()

    for off in range(0, len(packages), _OSV_BATCH):
        chunk   = packages[off : off + _OSV_BATCH]
        queries = [
            {"package": {"name": p["name"], "ecosystem": eco},
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
                # MAL- prefix = malicious package reports from OSSF
                if not vid.startswith("MAL-"):
                    continue
                key = (vid, pkg["name"])
                if key in seen:
                    continue
                seen.add(key)
                found.append({
                    "id":      vid,
                    "package": pkg["name"],
                    "version": pkg.get("version", "?"),
                    "summary": vuln.get("summary", "Malicious package report"),
                    "url":     f"https://osv.dev/vulnerability/{vid}",
                })

    return found


# ── 3. Recently modified system binaries ─────────────────────────────────────

def _modified_binaries(family: str) -> list[dict]:
    """Find files in standard binary paths modified within the last week."""
    now     = datetime.now(timezone.utc).timestamp()
    cutoff  = now - (_RECENT_DAYS * 86400)
    results = []

    for base in _BIN_PATHS:
        if not os.path.isdir(base):
            continue
        try:
            with os.scandir(base) as it:
                for entry in it:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        st = entry.stat()
                    except OSError:
                        continue
                    if st.st_mtime >= cutoff:
                        age_h = int((now - st.st_mtime) / 3600)
                        pkg   = _owner(entry.path, family)
                        results.append({
                            "path":     entry.path,
                            "package":  pkg or "?",
                            "modified": datetime.fromtimestamp(
                                st.st_mtime, tz=timezone.utc
                            ).isoformat(),
                            "age_hours": age_h,
                        })
        except PermissionError:
            continue

    # Sort newest first
    results.sort(key=lambda x: x["age_hours"])
    return results[:50]     # cap to avoid overwhelming the UI


def _owner(path: str, family: str) -> str | None:
    try:
        if family == "arch":
            out = subprocess.run(
                ["pacman", "-Qo", path],
                capture_output=True, text=True, timeout=5, check=False
            ).stdout
            m = re.search(r"owned by (\S+)", out)
            return m.group(1) if m else None
        if family == "debian":
            return _dpkg_owner(path)
        if family == "rhel":
            return _rpm_owner(path)
    except Exception:
        return None
    return None
