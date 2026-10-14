"""Host-side checks for the Windows-only build contract.

These tests inspect project metadata only. A Windows MSVC build remains the
authoritative validation for emitted PE32 binaries and runtime behavior.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree


LAB_ROOT = Path(__file__).resolve().parents[1]


def _project_properties(path: Path) -> dict[str, list[str]]:
    root = ElementTree.parse(path).getroot()
    properties: dict[str, list[str]] = {}
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1]
        if element.text and element.text.strip():
            properties.setdefault(name, []).append(element.text.strip())
    return properties


def test_projects_declare_only_win32_and_required_mitigation_settings() -> None:
    """Changing a project to x64 or dropping a lab mitigation must fail here."""
    for project_name in ("net01", "net02"):
        properties = _project_properties(
            LAB_ROOT / "challenges" / project_name / f"{project_name}.vcxproj"
        )
        assert set(properties["Platform"]) == {"Win32"}
        assert set(properties["Optimization"]) == {"Disabled"}
        assert set(properties["BufferSecurityCheck"]) == {"false"}
        assert set(properties["RandomizedBaseAddress"]) == {"false"}
        assert set(properties["DataExecutionPrevention"]) == {"false"}
        assert "ProgramDatabase" in properties["DebugInformationFormat"]


def test_build_script_declares_supported_configurations_and_uses_win32() -> None:
    """Dropping Debug/Release validation or Win32 selection must fail here."""
    script = (LAB_ROOT / "build" / "build.bat").read_text(encoding="utf-8")
    assert 'if /I "%CONFIGURATION%"=="Debug"' in script
    assert 'if /I "%CONFIGURATION%"=="Release"' in script
    assert "Platform=Win32" in script
    assert "vswhere" in script.lower()
    assert not (LAB_ROOT / "docs").exists()
    assert not (LAB_ROOT / ".superpowers").exists()
