#!/usr/bin/env python3
"""enum_host.py - Windows host enumeration with anomaly-first HTML report.

Standalone, stdlib-only. Runs on the OSED exam box (Python 3.7+).
Generates an HTML report highlighting deviations from a standard
Windows workstation/server baseline.

Usage:
    python enum_host.py
    python enum_host.py -o report.html
    python enum_host.py --quick          # skip slow scans
"""

from __future__ import annotations

import argparse
import datetime
import html
import os
import re
import socket
import subprocess
import sys
from pathlib import Path


STANDARD_LISTEN_PORTS = {
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session",
    445: "SMB",
    5040: "WNS (Windows Notification)",
    5357: "WSDAPI",
    7680: "WUDO (Delivery Optimization)",
    49664: "RPC Dynamic (typical range start)",
    49665: "RPC Dynamic",
    49666: "RPC Dynamic",
    49667: "RPC Dynamic",
    49668: "RPC Dynamic",
    49669: "RPC Dynamic",
    49670: "RPC Dynamic",
}

STANDARD_SERVICES = {
    "AudioEndpointBuilder", "Audiosrv", "BFE", "BITS", "BrokerInfrastructure",
    "CDPSvc", "CDPUserSvc", "COMSysApp", "CoreMessagingRegistrar",
    "CryptSvc", "DPS", "DcomLaunch", "Dhcp", "DiagTrack", "DispBrokerDesktopSvc",
    "Dnscache", "DoSvc", "DsSvc", "EventLog", "EventSystem", "FontCache",
    "LSM", "LanmanServer", "LanmanWorkstation", "MapsBroker", "MpsSvc",
    "NcbService", "Netlogon", "Netman", "NlaSvc", "PcaSvc", "PlugPlay",
    "Power", "ProfSvc", "RpcEptMapper", "RpcSs", "SENS", "SamSs",
    "Schedule", "SecurityHealthService", "ShellHWDetection", "Spooler",
    "SstpSvc", "StateRepository", "StorSvc", "SysMain", "SystemEventsBroker",
    "Themes", "TimeBrokerSvc", "TokenBroker", "TrkWks", "UserManager",
    "UsoSvc", "VaultSvc", "W32Time", "WSearch", "WinDefend", "WinHttpAutoProxySvc",
    "Winmgmt", "WlanSvc", "WpnService", "WpnUserService", "mpssvc",
    "nsi", "wuauserv",
}

STANDARD_PROCESSES = {
    "audiodg.exe", "conhost.exe", "csrss.exe", "ctfmon.exe", "dllhost.exe",
    "dwm.exe", "explorer.exe", "fontdrvhost.exe", "idle", "lsass.exe",
    "lsm.exe", "msdtc.exe", "ntoskrnl.exe", "services.exe", "sihost.exe",
    "smss.exe", "spoolsv.exe", "svchost.exe", "system", "system idle process",
    "taskhostw.exe", "tasklist.exe", "wininit.exe", "winlogon.exe",
    "wlanext.exe", "wmiprvse.exe", "wudfhost.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "applicationframehost.exe",
    "cmd.exe", "powershell.exe", "python.exe", "python3.exe", "py.exe",
    "notepad.exe", "mmc.exe", "taskmgr.exe", "regedit.exe",
    "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
    "windbg.exe", "cdb.exe", "kd.exe", "dbgsrv.exe", "dbgeng.exe",
}

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\", "\\users\\public\\",
]


def run_cmd(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "(command timed out)"
    except Exception as e:
        return f"(error: {e})"


def get_system_info() -> dict:
    info = {}
    raw = run_cmd("systeminfo")
    info["raw"] = raw
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    info["hostname"] = run_cmd("hostname").strip()
    info["whoami"] = run_cmd("whoami").strip()
    info["ipconfig"] = run_cmd("ipconfig /all")
    return info


def get_listening_ports() -> list[dict]:
    raw = run_cmd("netstat -ano -p TCP")
    ports = []
    for line in raw.splitlines():
        line = line.strip()
        if "LISTENING" not in line and "ESTABLISHED" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        pid = parts[4]
        local_addr, _, local_port = local.rpartition(":")
        remote_addr, _, remote_port = remote.rpartition(":")
        try:
            local_port_int = int(local_port)
        except ValueError:
            local_port_int = 0
        ports.append({
            "proto": proto,
            "local_addr": local_addr,
            "local_port": local_port_int,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
        })

    raw_udp = run_cmd("netstat -ano -p UDP")
    for line in raw_udp.splitlines():
        line = line.strip()
        if not line.startswith("UDP"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        local_addr, _, local_port = local.rpartition(":")
        try:
            local_port_int = int(local_port)
        except ValueError:
            local_port_int = 0
        ports.append({
            "proto": "UDP",
            "local_addr": local_addr,
            "local_port": local_port_int,
            "remote_addr": "*",
            "remote_port": "*",
            "state": "LISTENING",
            "pid": parts[-1],
        })
    return ports


def get_processes() -> list[dict]:
    raw = run_cmd('tasklist /V /FO CSV')
    procs = []
    lines = raw.strip().splitlines()
    if not lines:
        return procs
    headers_line = lines[0]
    headers = [h.strip('"') for h in headers_line.split('","')]
    for line in lines[1:]:
        vals = [v.strip('"') for v in line.split('","')]
        if len(vals) < len(headers):
            continue
        entry = dict(zip(headers, vals))
        procs.append(entry)
    return procs


def get_services() -> list[dict]:
    raw = run_cmd('sc query state= all')
    services = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("DISPLAY_NAME:"):
            current["display"] = line.split(":", 1)[1].strip()
        elif line.startswith("STATE"):
            m = re.search(r"(\d+)\s+(\w+)", line)
            if m:
                current["state_code"] = m.group(1)
                current["state"] = m.group(2)
        elif line.startswith("TYPE"):
            m = re.search(r":\s*\S+\s*(.*)", line)
            if m:
                current["type"] = m.group(1).strip()
    if current:
        services.append(current)
    return services


def get_service_configs(services: list[dict]) -> list[dict]:
    for svc in services:
        name = svc.get("name", "")
        if not name:
            continue
        raw = run_cmd(f'sc qc "{name}"', timeout=5)
        svc["config_raw"] = raw
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("START_TYPE"):
                m = re.search(r":\s*\S+\s*(.*)", line)
                if m:
                    svc["start_type"] = m.group(1).strip()
            elif line.startswith("BINARY_PATH_NAME"):
                svc["binary"] = line.split(":", 1)[1].strip()
            elif line.startswith("SERVICE_START_NAME"):
                svc["runas"] = line.split(":", 1)[1].strip()
    return services


def get_scheduled_tasks() -> str:
    return run_cmd("schtasks /query /fo LIST /v", timeout=60)


def get_installed_software() -> str:
    return run_cmd(
        'wmic product get Name,Version,Vendor /format:csv',
        timeout=30,
    )


def get_firewall_status() -> str:
    return run_cmd("netsh advfirewall show allprofiles state")


def get_shares() -> str:
    return run_cmd("net share")


def get_users_and_groups() -> str:
    parts = []
    parts.append("=== Local Users ===\n" + run_cmd("net user"))
    parts.append("=== Local Groups ===\n" + run_cmd("net localgroup"))
    parts.append("=== Administrators ===\n" + run_cmd("net localgroup Administrators"))
    return "\n".join(parts)


def get_env_path() -> str:
    return os.environ.get("PATH", "")


def classify_anomalies(
    ports: list[dict],
    procs: list[dict],
    services: list[dict],
    sysinfo: dict,
) -> list[dict]:
    findings = []

    pid_to_proc = {}
    for p in procs:
        pid = p.get("PID", "")
        name = p.get("Image Name", "")
        pid_to_proc[pid] = name

    listening = [p for p in ports if p["state"] == "LISTENING"]
    for entry in listening:
        port = entry["local_port"]
        pid = entry["pid"]
        proc_name = pid_to_proc.get(pid, "unknown")
        if port not in STANDARD_LISTEN_PORTS and port < 49152:
            findings.append({
                "severity": "HIGH",
                "category": "Non-standard listening port",
                "detail": (
                    f"Port {port}/{entry['proto']} (PID {pid}: {proc_name}) "
                    f"on {entry['local_addr']} -- not in standard Windows baseline"
                ),
            })

    established = [p for p in ports if p["state"] == "ESTABLISHED"]
    for entry in established:
        pid = entry["pid"]
        proc_name = pid_to_proc.get(pid, "unknown")
        remote = f"{entry['remote_addr']}:{entry['remote_port']}"
        findings.append({
            "severity": "INFO",
            "category": "Established connection",
            "detail": (
                f"PID {pid} ({proc_name}) -> {remote} "
                f"from {entry['local_addr']}:{entry['local_port']}"
            ),
        })

    for p in procs:
        name = p.get("Image Name", "").lower()
        if name and name not in STANDARD_PROCESSES:
            findings.append({
                "severity": "MEDIUM",
                "category": "Non-standard process",
                "detail": (
                    f"{p.get('Image Name', '?')} (PID {p.get('PID', '?')}) "
                    f"User: {p.get('User Name', '?')} "
                    f"Mem: {p.get('Mem Usage', '?')}"
                ),
            })

    for svc in services:
        name = svc.get("name", "")
        state = svc.get("state", "")
        if state == "RUNNING" and name not in STANDARD_SERVICES:
            binary = svc.get("binary", "")
            runas = svc.get("runas", "")
            sev = "HIGH"
            cat = "Non-standard service running"
            detail = (
                f"{name} ({svc.get('display', '')}) "
                f"Binary: {binary} RunAs: {runas}"
            )
            if binary:
                lower_bin = binary.lower()
                for sus in SUSPICIOUS_PATHS:
                    if sus in lower_bin:
                        sev = "CRITICAL"
                        cat = "Service running from suspicious path"
                        break
            findings.append({
                "severity": sev,
                "category": cat,
                "detail": detail,
            })

    for svc in services:
        binary = svc.get("binary", "")
        if not binary:
            continue
        bin_path = binary.split('"')[1] if '"' in binary else binary.split()[0] if binary else ""
        if bin_path and os.path.isfile(bin_path):
            try:
                import stat
                st = os.stat(bin_path)
                if st.st_mode & stat.S_IWOTH:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "World-writable service binary",
                        "detail": f"{svc.get('name', '?')}: {bin_path}",
                    })
            except (OSError, ValueError):
                pass
        if binary and not binary.lower().startswith(("c:\\windows\\", '"c:\\windows\\')):
            if svc.get("state") == "RUNNING":
                svc_name = svc.get("name", "")
                if svc_name not in STANDARD_SERVICES:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Service binary outside Windows directory",
                        "detail": f"{svc_name}: {binary}",
                    })

    dep_status = sysinfo.get("raw", "")
    if "DEP" in dep_status:
        pass

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))
    return findings


SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "INFO": "#2563eb",
}


def generate_html(
    findings: list[dict],
    ports: list[dict],
    procs: list[dict],
    services: list[dict],
    sysinfo: dict,
    firewall: str,
    shares: str,
    users: str,
    env_path: str,
) -> str:
    h = html.escape
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = h(sysinfo.get("hostname", "unknown"))

    findings_html = ""
    if not findings:
        findings_html = '<p style="color:#16a34a;font-weight:bold;">No anomalies detected.</p>'
    else:
        crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
        info_count = sum(1 for f in findings if f["severity"] == "INFO")

        findings_html += f"""
        <div class="summary-bar">
            <span class="badge" style="background:{SEVERITY_COLORS['CRITICAL']}">{crit_count} CRITICAL</span>
            <span class="badge" style="background:{SEVERITY_COLORS['HIGH']}">{high_count} HIGH</span>
            <span class="badge" style="background:{SEVERITY_COLORS['MEDIUM']}">{med_count} MEDIUM</span>
            <span class="badge" style="background:{SEVERITY_COLORS['INFO']}">{info_count} INFO</span>
        </div>
        <table class="findings">
        <tr><th>Severity</th><th>Category</th><th>Detail</th></tr>
        """
        for f in findings:
            sev = f["severity"]
            color = SEVERITY_COLORS.get(sev, "#666")
            findings_html += (
                f'<tr>'
                f'<td><span class="sev" style="background:{color}">{h(sev)}</span></td>'
                f'<td>{h(f["category"])}</td>'
                f'<td class="detail">{h(f["detail"])}</td>'
                f'</tr>\n'
            )
        findings_html += "</table>"

    listening = [p for p in ports if p["state"] == "LISTENING"]
    listening.sort(key=lambda p: p["local_port"])
    ports_html = "<table><tr><th>Port</th><th>Proto</th><th>Address</th><th>PID</th><th>Standard?</th></tr>\n"
    for p in listening:
        port = p["local_port"]
        is_std = port in STANDARD_LISTEN_PORTS or port >= 49152
        std_label = STANDARD_LISTEN_PORTS.get(port, "RPC Dynamic" if port >= 49152 else "NO")
        row_class = "" if is_std else ' class="anomaly"'
        ports_html += (
            f'<tr{row_class}>'
            f'<td>{port}</td><td>{h(p["proto"])}</td>'
            f'<td>{h(p["local_addr"])}</td><td>{h(p["pid"])}</td>'
            f'<td>{h(std_label)}</td>'
            f'</tr>\n'
        )
    ports_html += "</table>"

    established = [p for p in ports if p["state"] == "ESTABLISHED"]
    if established:
        est_html = "<table><tr><th>Local</th><th>Remote</th><th>PID</th></tr>\n"
        for p in established:
            est_html += (
                f'<tr><td>{h(p["local_addr"])}:{p["local_port"]}</td>'
                f'<td>{h(p["remote_addr"])}:{h(p["remote_port"])}</td>'
                f'<td>{h(p["pid"])}</td></tr>\n'
            )
        est_html += "</table>"
    else:
        est_html = "<p>None.</p>"

    procs.sort(key=lambda p: p.get("Image Name", "").lower())
    procs_html = "<table><tr><th>Name</th><th>PID</th><th>User</th><th>Memory</th><th>Standard?</th></tr>\n"
    for p in procs:
        name = p.get("Image Name", "")
        is_std = name.lower() in STANDARD_PROCESSES
        row_class = "" if is_std else ' class="anomaly"'
        procs_html += (
            f'<tr{row_class}>'
            f'<td>{h(name)}</td>'
            f'<td>{h(p.get("PID", ""))}</td>'
            f'<td>{h(p.get("User Name", ""))}</td>'
            f'<td>{h(p.get("Mem Usage", ""))}</td>'
            f'<td>{"yes" if is_std else "<b>NO</b>"}</td>'
            f'</tr>\n'
        )
    procs_html += "</table>"

    running_svcs = [s for s in services if s.get("state") == "RUNNING"]
    running_svcs.sort(key=lambda s: s.get("name", "").lower())
    svcs_html = "<table><tr><th>Name</th><th>Display</th><th>Binary</th><th>RunAs</th><th>Standard?</th></tr>\n"
    for s in running_svcs:
        name = s.get("name", "")
        is_std = name in STANDARD_SERVICES
        row_class = "" if is_std else ' class="anomaly"'
        svcs_html += (
            f'<tr{row_class}>'
            f'<td>{h(name)}</td>'
            f'<td>{h(s.get("display", ""))}</td>'
            f'<td class="detail">{h(s.get("binary", ""))}</td>'
            f'<td>{h(s.get("runas", ""))}</td>'
            f'<td>{"yes" if is_std else "<b>NO</b>"}</td>'
            f'</tr>\n'
        )
    svcs_html += "</table>"

    stopped_svcs = [s for s in services if s.get("state") == "STOPPED"]
    stopped_count = len(stopped_svcs)

    sysinfo_html = ""
    for key in ["OS Name", "OS Version", "System Type", "Total Physical Memory",
                 "Domain", "Hotfix(s)", "Network Card(s)"]:
        val = sysinfo.get(key, "")
        if val:
            sysinfo_html += f"<tr><td><b>{h(key)}</b></td><td>{h(val)}</td></tr>\n"
    sysinfo_html += f"<tr><td><b>Current User</b></td><td>{h(sysinfo.get('whoami', ''))}</td></tr>\n"

    ipconfig_html = h(sysinfo.get("ipconfig", ""))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Host Enumeration - {hostname}</title>
<style>
  :root {{
    --bg: #0f172a; --fg: #e2e8f0; --card: #1e293b;
    --border: #334155; --accent: #38bdf8; --anomaly-bg: #451a03;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: Consolas, "Courier New", monospace; background: var(--bg); color: var(--fg); padding: 1rem; line-height: 1.5; }}
  h1 {{ color: var(--accent); margin-bottom: 0.25rem; font-size: 1.5rem; }}
  h2 {{ color: var(--accent); margin: 1.5rem 0 0.5rem; font-size: 1.1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }}
  .meta {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 1rem; }}
  .summary-bar {{ display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }}
  .badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.85rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; font-size: 0.8rem; }}
  th {{ background: #334155; color: var(--accent); text-align: left; padding: 0.4rem 0.5rem; position: sticky; top: 0; }}
  td {{ padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover {{ background: #1a3a5c; }}
  tr.anomaly {{ background: var(--anomaly-bg); }}
  tr.anomaly:hover {{ background: #5c2d10; }}
  .detail {{ max-width: 600px; word-break: break-all; }}
  .sev {{ padding: 0.15rem 0.5rem; border-radius: 3px; color: #fff; font-weight: bold; font-size: 0.75rem; }}
  .findings {{ margin-bottom: 1.5rem; }}
  .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }}
  pre {{ background: #0d1117; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }}
  .toc {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }}
  .toc a {{ color: var(--accent); text-decoration: none; padding: 0.25rem 0.5rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.8rem; }}
  .toc a:hover {{ background: var(--border); }}
  @media print {{ body {{ background: #fff; color: #000; }} .section {{ border: 1px solid #ccc; }} th {{ background: #ddd; color: #000; }} tr.anomaly {{ background: #fff3cd; }} }}
</style>
</head>
<body>

<h1>Host Enumeration Report</h1>
<div class="meta">{hostname} | {h(sysinfo.get('whoami', ''))} | {now}</div>

<div class="toc">
  <a href="#findings">Findings</a>
  <a href="#sysinfo">System Info</a>
  <a href="#ports">Listening Ports</a>
  <a href="#connections">Connections</a>
  <a href="#processes">Processes</a>
  <a href="#services">Services</a>
  <a href="#firewall">Firewall</a>
  <a href="#shares">Shares</a>
  <a href="#users">Users &amp; Groups</a>
  <a href="#network">Network Config</a>
  <a href="#path">PATH</a>
</div>

<div class="section" id="findings">
<h2>Anomalies and Findings</h2>
{findings_html}
</div>

<div class="section" id="sysinfo">
<h2>System Information</h2>
<table>{sysinfo_html}</table>
</div>

<div class="section" id="ports">
<h2>Listening Ports ({len(listening)} total)</h2>
{ports_html}
</div>

<div class="section" id="connections">
<h2>Established Connections ({len(established)} total)</h2>
{est_html}
</div>

<div class="section" id="processes">
<h2>Running Processes ({len(procs)} total)</h2>
{procs_html}
</div>

<div class="section" id="services">
<h2>Running Services ({len(running_svcs)} running, {stopped_count} stopped)</h2>
{svcs_html}
</div>

<div class="section" id="firewall">
<h2>Firewall Status</h2>
<pre>{h(firewall)}</pre>
</div>

<div class="section" id="shares">
<h2>Network Shares</h2>
<pre>{h(shares)}</pre>
</div>

<div class="section" id="users">
<h2>Users and Groups</h2>
<pre>{h(users)}</pre>
</div>

<div class="section" id="network">
<h2>Network Configuration</h2>
<pre>{ipconfig_html}</pre>
</div>

<div class="section" id="path">
<h2>PATH Environment</h2>
<pre>{h(chr(10).join(env_path.split(os.pathsep)))}</pre>
</div>

</body>
</html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate Windows host and generate anomaly-first HTML report.",
    )
    parser.add_argument(
        "-o", "--output", default="enum_report.html",
        help="Output HTML file (default: enum_report.html)",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Skip slow scans (service configs, scheduled tasks)",
    )
    args = parser.parse_args(argv)

    print("[*] Gathering system information...")
    sysinfo = get_system_info()

    print("[*] Enumerating listening ports...")
    ports = get_listening_ports()

    print("[*] Enumerating processes...")
    procs = get_processes()

    print("[*] Enumerating services...")
    services = get_services()

    if not args.quick:
        print("[*] Querying service configurations (this may take a moment)...")
        services = get_service_configs(services)

    print("[*] Checking firewall status...")
    firewall = get_firewall_status()

    print("[*] Enumerating shares...")
    shares = get_shares()

    print("[*] Enumerating users and groups...")
    users = get_users_and_groups()

    env_path = get_env_path()

    print("[*] Classifying anomalies...")
    findings = classify_anomalies(ports, procs, services, sysinfo)

    print(f"[*] Generating report: {args.output}")
    report = generate_html(
        findings=findings,
        ports=ports,
        procs=procs,
        services=services,
        sysinfo=sysinfo,
        firewall=firewall,
        shares=shares,
        users=users,
        env_path=env_path,
    )

    Path(args.output).write_text(report, encoding="utf-8")

    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med = sum(1 for f in findings if f["severity"] == "MEDIUM")
    info = sum(1 for f in findings if f["severity"] == "INFO")
    print(f"[+] Done. {len(findings)} findings: {crit} critical, {high} high, {med} medium, {info} info")
    print(f"[+] Report: {args.output}")
    print(f"[+] Open in browser: start {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
