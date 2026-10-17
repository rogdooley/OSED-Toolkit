"""Host-side tests for the Windows-only enumeration helpers."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import enum_host  # noqa: E402


def test_parse_whoami_privileges_preserves_enabled_and_disabled_states():
    raw = (
        '"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"\r\n'
        '"SeDebugPrivilege","Debug programs","Disabled"\r\n'
    )

    assert enum_host.parse_whoami_privileges(raw) == [
        {"name": "SeChangeNotifyPrivilege", "state": "Enabled"},
        {"name": "SeDebugPrivilege", "state": "Disabled"},
    ]


def test_summarize_service_access_reports_each_requested_capability():
    rights = {
        "query_config": True,
        "start": False,
        "stop": True,
        "change_config": False,
    }

    assert enum_host.summarize_service_access(rights) == "query configuration, stop"


def test_classify_anomalies_marks_unknown_services_as_review_not_high():
    findings = enum_host.classify_anomalies(
        ports=[],
        procs=[],
        services=[
            {
                "name": "ThirdPartyAgent",
                "display": "Third Party Agent",
                "state": "RUNNING",
                "binary": "C:\\Program Files\\Vendor\\agent.exe",
                "runas": "LocalSystem",
            }
        ],
        sysinfo={},
    )

    service_findings = [f for f in findings if "service" in f["category"].lower()]
    assert service_findings == [
        {
            "severity": "INFO",
            "category": "Non-baseline service (review)",
            "detail": (
                "ThirdPartyAgent (Third Party Agent) "
                "Binary: C:\\Program Files\\Vendor\\agent.exe RunAs: LocalSystem"
            ),
        },
        {
            "severity": "INFO",
            "category": "Service binary outside Windows directory",
            "detail": "ThirdPartyAgent: C:\\Program Files\\Vendor\\agent.exe",
        },
    ]


def test_classify_anomalies_treats_unknown_listening_ports_as_review_leads():
    findings = enum_host.classify_anomalies(
        ports=[
            {
                "state": "LISTENING",
                "local_port": 31337,
                "proto": "TCP",
                "pid": "1234",
                "local_addr": "127.0.0.1",
                "remote_addr": "*",
                "remote_port": "*",
            }
        ],
        procs=[{"PID": "1234", "Image Name": "lab-server.exe"}],
        services=[],
        sysinfo={},
    )

    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["category"] == "Non-baseline listening port (review)"
