import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

from config import FIREBASE_API_KEY, FIREBASE_PROJECT

ARCH_BASED = {"arch", "artix", "manjaro", "endeavouros", "cachyos", "garuda", "arcolinux", "parabola"}
DEBIAN_BASED = {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
RHEL_BASED = {"fedora", "rhel", "centos", "rocky", "almalinux"}


def run(cmd, timeout=15):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return out.stdout.strip(), out.stderr.strip(), out.returncode
    except FileNotFoundError:
        return "", f"not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"timeout: {' '.join(cmd)}", 124


def read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def parse_os_release():
    data = {}
    raw = read_file("/etc/os-release")
    for line in raw.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip().strip('"')
    return data


def get_os_info():
    osr = parse_os_release()
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "architecture": platform.architecture()[0],
        "hostname": platform.node(),
        "pretty_name": osr.get("PRETTY_NAME", "Unknown"),
        "id": osr.get("ID", ""),
        "id_like": osr.get("ID_LIKE", ""),
        "version_id": osr.get("VERSION_ID", ""),
    }
    return info


def detect_distro_family(os_info):
    ids = {os_info.get("id", "").lower()}
    ids.update(os_info.get("id_like", "").lower().split())
    if ids & ARCH_BASED:
        return "arch"
    if ids & DEBIAN_BASED:
        return "debian"
    if ids & RHEL_BASED:
        return "rhel"
    return "unknown"


def get_memory_info():
    info = {}
    raw = read_file("/proc/meminfo")
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if v.endswith(" kB"):
            try:
                info[k.strip()] = int(v[:-3]) * 1024
            except ValueError:
                info[k.strip()] = v
        else:
            info[k.strip()] = v
    summary = {
        "total_bytes": info.get("MemTotal"),
        "available_bytes": info.get("MemAvailable"),
        "free_bytes": info.get("MemFree"),
        "buffers_bytes": info.get("Buffers"),
        "cached_bytes": info.get("Cached"),
        "swap_total_bytes": info.get("SwapTotal"),
        "swap_free_bytes": info.get("SwapFree"),
    }
    return {"summary": summary, "raw": info}


def get_cpu_info():
    raw = read_file("/proc/cpuinfo")
    cores = []
    current = {}
    for line in raw.splitlines():
        if not line.strip():
            if current:
                cores.append(current)
                current = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            current[k.strip()] = v.strip()
    if current:
        cores.append(current)

    summary = {}
    if cores:
        first = cores[0]
        summary = {
            "model_name": first.get("model name", ""),
            "vendor_id": first.get("vendor_id", ""),
            "cpu_family": first.get("cpu family", ""),
            "model": first.get("model", ""),
            "stepping": first.get("stepping", ""),
            "microcode": first.get("microcode", ""),
            "cpu_mhz": first.get("cpu MHz", ""),
            "cache_size": first.get("cache size", ""),
            "flags": first.get("flags", "").split(),
            "bugs": first.get("bugs", "").split(),
            "logical_cpus": len(cores),
        }

    vulns = {}
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    if os.path.isdir(vuln_dir):
        try:
            for name in os.listdir(vuln_dir):
                vulns[name] = read_file(os.path.join(vuln_dir, name)).strip()
        except OSError:
            pass

    return {"summary": summary, "vulnerabilities": vulns}


def get_block_devices():
    out, _, rc = run(["lsblk", "-J", "-O"])
    if rc == 0 and out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    out, _, _ = run(["lsblk"])
    return {"raw": out}


def get_filesystems():
    out, _, _ = run(["df", "-hT"])
    mounts = read_file("/proc/mounts")
    return {"df": out, "mounts": mounts.strip()}


def get_pci_devices():
    out, _, rc = run(["lspci", "-vmm"])
    if rc != 0:
        return {"available": False}
    devices = []
    block = {}
    for line in out.splitlines():
        if not line.strip():
            if block:
                devices.append(block)
                block = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            block[k.strip()] = v.strip()
    if block:
        devices.append(block)
    return {"available": True, "devices": devices}


def get_usb_devices():
    out, _, rc = run(["lsusb"])
    if rc != 0:
        return {"available": False}
    return {"available": True, "devices": [line for line in out.splitlines() if line.strip()]}


def get_dmi_info():
    base = "/sys/class/dmi/id"
    if not os.path.isdir(base):
        return {}
    fields = ["sys_vendor", "product_name", "product_version", "product_serial",
              "board_vendor", "board_name", "board_version",
              "bios_vendor", "bios_version", "bios_date",
              "chassis_vendor", "chassis_type"]
    out = {}
    for f in fields:
        val = read_file(os.path.join(base, f)).strip()
        if val:
            out[f] = val
    return out


def get_kernel_info():
    return {
        "version": read_file("/proc/version").strip(),
        "cmdline": read_file("/proc/cmdline").strip(),
        "modules_loaded": len([l for l in read_file("/proc/modules").splitlines() if l.strip()]),
    }


def get_network_info():
    addrs, _, _ = run(["ip", "-j", "addr"])
    routes, _, _ = run(["ip", "-j", "route"])
    listening, _, _ = run(["ss", "-tulnp"])

    parsed_addrs = None
    parsed_routes = None
    try:
        if addrs:
            parsed_addrs = json.loads(addrs)
    except json.JSONDecodeError:
        parsed_addrs = addrs
    try:
        if routes:
            parsed_routes = json.loads(routes)
    except json.JSONDecodeError:
        parsed_routes = routes

    return {
        "addresses": parsed_addrs,
        "routes": parsed_routes,
        "listening_sockets": listening,
    }


def get_network_neighbors():
    """ARP/neighbor table — devices recently seen on the local network."""
    out, _, rc = run(["ip", "-j", "neigh", "show"])
    if rc == 0 and out:
        try:
            raw = json.loads(out)
            return [
                {
                    "ip":        n.get("dst", ""),
                    "mac":       n.get("lladdr", ""),
                    "interface": n.get("dev", ""),
                    "state":     n.get("state", []),
                }
                for n in raw
                if n.get("dst") and not n.get("dst", "").startswith("fe80")
            ]
        except json.JSONDecodeError:
            pass
    return []


def get_nmap_scan(subnet: str) -> dict:
    """Run nmap host-discovery on a subnet and return discovered devices."""
    if not shutil.which("nmap"):
        return {"available": False, "reason": "nmap not installed"}
    if not subnet:
        return {"available": False, "reason": "no subnet specified"}
    out, err, rc = run(["nmap", "-sn", "-T4", subnet], timeout=180)
    if rc not in (0, 1):
        return {"available": False, "reason": err or "nmap failed"}
    hosts = []
    current: dict = {}
    for line in out.splitlines():
        if line.startswith("Nmap scan report for"):
            if current:
                hosts.append(current)
            rest = line[len("Nmap scan report for "):].strip()
            m = re.search(r"\(([^)]+)\)", rest)
            if m:
                current = {"hostname": rest[:rest.index("(")].strip(), "ip": m.group(1)}
            else:
                current = {"hostname": rest, "ip": rest}
            current["vendor"] = ""
        elif "MAC Address:" in line:
            mac_m = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line, re.I)
            vendor_m = re.search(r"\(([^)]+)\)", line)
            if mac_m:
                current["mac"] = mac_m.group(1)
            if vendor_m:
                current["vendor"] = vendor_m.group(1)
    if current:
        hosts.append(current)
    return {"available": True, "hosts": hosts, "count": len(hosts)}


def get_services():
    if not shutil.which("systemctl"):
        return {"available": False}
    out, _, _ = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
    services = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if parts:
            services.append(parts[0])
    return {"available": True, "running": services}


def get_suid_files(limit=500):
    paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
    paths = [p for p in paths if os.path.isdir(p)]
    if not paths:
        return []
    cmd = ["find"] + paths + ["-xdev", "-type", "f", "-perm", "-4000"]
    out, _, _ = run(cmd, timeout=30)
    files = [l for l in out.splitlines() if l.strip()][:limit]
    return files


def get_users():
    passwd = read_file("/etc/passwd")
    users = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            users.append({
                "name": parts[0],
                "uid": parts[2],
                "gid": parts[3],
                "home": parts[5],
                "shell": parts[6],
            })
    interactive = [u for u in users if u["shell"] not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "")]
    return {"all": users, "interactive": interactive}


def get_sudo_version():
    out, _, rc = run(["sudo", "-V"])
    if rc != 0:
        return {"available": False}
    first = out.splitlines()[0] if out else ""
    return {"available": True, "version_line": first}


def get_packages(family):
    if family == "arch":
        out, err, rc = run(["pacman", "-Q"], timeout=30)
        if rc != 0:
            return {"manager": "pacman", "available": False, "error": err}
        foreign_out, _, _ = run(["pacman", "-Qm"], timeout=30)
        foreign_names = set()
        for line in foreign_out.splitlines():
            parts = line.split(None, 1)
            if parts:
                foreign_names.add(parts[0])
        pkgs = []
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                name = parts[0]
                pkgs.append({
                    "name": name,
                    "version": parts[1],
                    "source": "foreign" if name in foreign_names else "repo",
                })
        return {
            "manager": "pacman",
            "available": True,
            "count": len(pkgs),
            "foreign_count": len(foreign_names),
            "foreign": sorted(foreign_names),
            "packages": pkgs,
        }

    if family == "debian":
        out, err, rc = run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], timeout=30)
        if rc != 0:
            return {"manager": "dpkg", "available": False, "error": err}
        pkgs = []
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                pkgs.append({"name": parts[0], "version": parts[1]})
        return {"manager": "dpkg", "available": True, "count": len(pkgs), "packages": pkgs}

    if family == "rhel":
        out, err, rc = run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"], timeout=30)
        if rc != 0:
            return {"manager": "rpm", "available": False, "error": err}
        pkgs = []
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                pkgs.append({"name": parts[0], "version": parts[1]})
        return {"manager": "rpm", "available": True, "count": len(pkgs), "packages": pkgs}

    return {"manager": "unknown", "available": False}


def human_bytes(n):
    if not isinstance(n, (int, float)) or n is None:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def print_summary(report):
    os_info = report["os"]
    mem = report["memory"]["summary"]
    cpu = report["cpu"]["summary"]
    dmi = report["dmi"]
    pkgs = report["packages"]

    print("=" * 60)
    print(f"  oasis-scan report  -  {report['scanned_at']}")
    print("=" * 60)
    print(f"Host        : {os_info['hostname']}")
    print(f"OS          : {os_info['pretty_name']} ({os_info['id']})")
    print(f"Kernel      : {os_info['release']}  [{os_info['machine']}]")
    print(f"Family      : {report['distro_family']}")
    if dmi:
        print(f"Vendor      : {dmi.get('sys_vendor', '?')} / {dmi.get('product_name', '?')}")
        print(f"BIOS        : {dmi.get('bios_vendor', '?')} {dmi.get('bios_version', '?')} ({dmi.get('bios_date', '?')})")
    print()
    print(f"CPU         : {cpu.get('model_name', '?')}")
    print(f"  cores     : {cpu.get('logical_cpus', '?')} logical")
    print(f"  bugs      : {', '.join(cpu.get('bugs', [])) or 'none reported'}")
    print()
    print(f"Memory      : {human_bytes(mem.get('total_bytes'))} total, "
          f"{human_bytes(mem.get('available_bytes'))} available")
    print(f"Swap        : {human_bytes(mem.get('swap_total_bytes'))} total, "
          f"{human_bytes(mem.get('swap_free_bytes'))} free")
    print()
    print(f"PCI devices : {len(report['pci'].get('devices', [])) if report['pci'].get('available') else 'n/a'}")
    print(f"USB devices : {len(report['usb'].get('devices', [])) if report['usb'].get('available') else 'n/a'}")
    pkg_line = f"Packages    : {pkgs.get('count', 'n/a')} via {pkgs.get('manager', '?')}"
    if "foreign_count" in pkgs:
        pkg_line += f"  ({pkgs['foreign_count']} foreign/AUR)"
    print(pkg_line)
    print(f"Services    : {len(report['services'].get('running', [])) if report['services'].get('available') else 'n/a'} running")
    print(f"SUID files  : {len(report['suid_files'])}")
    vulns = report["cpu"].get("vulnerabilities", {})
    if vulns:
        bad = [k for k, v in vulns.items() if v and not v.lower().startswith(("not affected", "mitigation"))]
        print(f"CPU vulns   : {len(vulns)} reported, {len(bad)} not fully mitigated")
        for name in bad:
            print(f"   - {name}: {vulns[name]}")
    print("=" * 60)


def scan():
    os_info = get_os_info()
    family = detect_distro_family(os_info)
    report = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "os": os_info,
        "distro_family": family,
        "dmi": get_dmi_info(),
        "kernel": get_kernel_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "block_devices": get_block_devices(),
        "filesystems": get_filesystems(),
        "pci": get_pci_devices(),
        "usb": get_usb_devices(),
        "network":           get_network_info(),
        "network_neighbors": get_network_neighbors(),
        "services": get_services(),
        "users": get_users(),
        "sudo": get_sudo_version(),
        "suid_files": get_suid_files(),
        "packages": get_packages(family),
    }
    return report


def firebase_login(email, password):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    body = json.dumps({"email": email, "password": password, "returnSecureToken": True}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            return data["idToken"], data["localId"]
    except urllib.error.HTTPError as e:
        err = json.loads(e.read()).get("error", {}).get("message", "UNKNOWN")
        return None, err


def firestore_save(id_token, uid, report):
    url = (f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}"
           f"/databases/(default)/documents/users/{uid}/scans")
    # Build a minimal Firestore document with the key device fields
    os_info = report["os"]
    mem = report["memory"]["summary"]
    cpu = report["cpu"]["summary"]
    doc = {
        "fields": {
            "scanned_at":   {"stringValue": report["scanned_at"]},
            "hostname":     {"stringValue": os_info.get("hostname", "")},
            "os":           {"stringValue": os_info.get("pretty_name", "")},
            "kernel":       {"stringValue": os_info.get("release", "")},
            "arch":         {"stringValue": os_info.get("machine", "")},
            "cpu":          {"stringValue": cpu.get("model_name", "")},
            "cpu_cores":    {"integerValue": str(cpu.get("logical_cpus", 0))},
            "mem_total":    {"integerValue": str(mem.get("total_bytes") or 0)},
            "mem_available":{"integerValue": str(mem.get("available_bytes") or 0)},
            "pkg_count":    {"integerValue": str(report["packages"].get("count") or 0)},
            "pkg_manager":  {"stringValue": report["packages"].get("manager", "")},
            "services_running": {"integerValue": str(len(report["services"].get("running", [])))},
            "suid_count":   {"integerValue": str(len(report["suid_files"]))},
            "distro_family":{"stringValue": report.get("distro_family", "")},
        }
    }
    body = json.dumps(doc).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {id_token}",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return True, None
    except urllib.error.HTTPError as e:
        return False, e.read().decode()


def prompt_login():
    print("\n── Oasis Scan ─────────────────────────────")
    print("  Sign in to sync results to your account")
    print("───────────────────────────────────────────")
    email    = input("  Email   : ").strip()
    password = getpass.getpass("  Password: ")
    print("  Authenticating…", end="", flush=True)
    token, result = firebase_login(email, password)
    if token:
        print(" done")
        return token, result  # result is uid
    else:
        print(f" failed ({result})")
        return None, None


def main():
    id_token, uid = prompt_login()
    if not id_token:
        print("Could not sign in. Running scan without syncing.\n")

    report = scan()

    out_path = os.environ.get("OASIS_REPORT", "oasis-report.json")
    try:
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
    except OSError as e:
        print(f"warn: could not write {out_path}: {e}")

    print_summary(report)
    print(f"\nFull report written to: {out_path}")

    if id_token and uid:
        print("Syncing to Firestore…", end="", flush=True)
        ok, err = firestore_save(id_token, uid, report)
        print(" done" if ok else f" failed: {err}")


if __name__ == "__main__":
    main()
