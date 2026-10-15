from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_remaining_challenges_have_independent_sources_projects_and_hints() -> None:
    for name, label in (("net03", "NET03"), ("file01", "FILE01"), ("file02", "FILE02"), ("file03", "FILE03")):
        assert (ROOT / "challenges" / name / f"{name}.c").exists()
        assert (ROOT / "challenges" / name / f"{name}.vcxproj").exists()
        assert (ROOT / "Documentation/student" / f"{label}.md").exists()
        assert (ROOT / "Documentation/instructor" / f"{label}.md").exists()
        assert (ROOT / "Documentation/student" / "hints" / f"{label.replace('NET03', 'NET-03').replace('FILE0', 'FILE-0')}.md").exists()


def test_file_generator_and_net03_harness_support_are_present() -> None:
    assert (ROOT / "tools" / "generate_file.py").exists()
    harness = (ROOT / "tools" / "send_tcp.py").read_text(encoding="utf-8")
    assert '"net03"' in harness
