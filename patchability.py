"""Patchability assessment for Scan Oasis — is a CVE actually fixable right now?

For each vulnerable package we decide, from real data (the CVE 'fixed' version vs
the installed version) and — for Arch — the live repository version:

  patchable      : a fixed version exists and is installable now (upgrade fixes it)
  fix_pending    : a fix exists upstream but the distro repo doesn't ship it yet
  no_fix         : no fixed version has been published -> mitigation only
  already_fixed  : installed version already includes the fix
  unknown        : could not determine

No data is invented: 'no_fix'/'fix_pending' are honest warnings, not guesses.
"""

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

_ARCH_CACHE: dict[str, str | None] = {}


def _norm(v):
    """Reduce a version string to a comparable list of ints (drop epoch/pkgrel)."""
    if not v or v in ("?", "unknown", "no fix yet", ""):
        return None
    v = str(v).split(":")[-1]              # drop epoch  (2:1.2.3 -> 1.2.3)
    v = re.split(r"[-+~ ]", v)[0]          # drop pkgrel/suffix (1.2.3-1 -> 1.2.3)
    nums = re.findall(r"\d+", v)
    return [int(n) for n in nums] if nums else None


def _cmp(a, b):
    """Compare two version strings. Returns -1/0/1, or None if not comparable."""
    na, nb = _norm(a), _norm(b)
    if na is None or nb is None:
        return None
    for i in range(max(len(na), len(nb))):
        x = na[i] if i < len(na) else 0
        y = nb[i] if i < len(nb) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _arch_repo_version(pkg):
    """Look up a package's current version in the official Arch repos (cached)."""
    if pkg in _ARCH_CACHE:
        return _ARCH_CACHE[pkg]
    ver = None
    try:
        url = f"https://archlinux.org/packages/search/json/?name={urllib.parse.quote(pkg)}"
        req = urllib.request.Request(url, headers={"User-Agent": "scan-oasis/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.load(r)
        for res in data.get("results", []):
            # prefer stable repos over testing
            if res.get("repo", "").endswith("testing"):
                continue
            if res.get("pkgver"):
                ver = res["pkgver"]
                break
        if ver is None and data.get("results"):
            ver = data["results"][0].get("pkgver")
    except Exception:
        ver = None
    _ARCH_CACHE[pkg] = ver
    return ver


def assess_patchability(report, cves):
    """Return { package: {status, installed, fixed, repo_version, note, cve_ids} }."""
    family = (report or {}).get("distro_family", "unknown")

    # Group CVEs by package; keep the installed version and the best known fix
    pkgs: dict[str, dict] = {}
    for c in cves or []:
        p = c.get("package")
        if not p:
            continue
        g = pkgs.setdefault(p, {"installed": c.get("installed"), "fixed": None, "cve_ids": []})
        if c.get("id"):
            g["cve_ids"].append(c["id"])
        f = c.get("fixed")
        if f and f not in ("?", "unknown") and not g["fixed"]:
            g["fixed"] = f

    # For Arch, fetch live repo versions in parallel (bounded) to confirm the fix
    # is actually installable. Other distros use the deterministic fixed-vs-installed.
    repo_versions: dict[str, str | None] = {}
    if family == "arch":
        targets = [p for p, info in pkgs.items() if info["fixed"]][:40]
        if targets:
            with ThreadPoolExecutor(max_workers=8) as ex:
                for p, v in zip(targets, ex.map(_arch_repo_version, targets)):
                    repo_versions[p] = v

    out: dict[str, dict] = {}
    for p, info in pkgs.items():
        installed, fixed = info["installed"], info["fixed"]
        repo_version = repo_versions.get(p)
        status, note = "unknown", ""

        if not fixed:
            status = "no_fix"
            note = "No fixed version has been published yet — mitigation only."
        elif (_cmp(installed, fixed) or -1) >= 0:
            status = "already_fixed"
            note = "Installed version already includes the fix."
        elif family == "arch" and repo_version:
            if (_cmp(repo_version, fixed) or -1) >= 0:
                status = "patchable"
                note = f"Fix is available in your repo (v{repo_version}) — upgrade now."
            else:
                status = "fix_pending"
                note = (f"A fix ({fixed}) exists upstream but your repo only has "
                        f"v{repo_version}. Wait for the update or use a mitigation.")
        else:
            status = "patchable"
            note = f"A fixed version ({fixed}) exists — upgrade the package."

        out[p] = {
            "status": status, "installed": installed, "fixed": fixed,
            "repo_version": repo_version, "note": note, "cve_ids": info["cve_ids"],
        }
    return out
