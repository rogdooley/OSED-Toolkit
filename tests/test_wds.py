import os
import sys

import pytest

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.models import Stage, WDSConfig
from badchars_wds.wds import generate_wds


def _base_config(step_mode="none", custom_step=None, av=True, quit_after_dump=False):
    return WDSConfig(
        stage=Stage(
            breakpoint="0x625011AF",
            dump_expr="poi(@esp+4)+2006",
            dump_size=64,
            step_mode=step_mode,
            custom_step=custom_step,
            temp_dump_path=r"C:\temp\dump.tmp.bin",
            final_dump_path=r"C:\temp\dump.bin",
            quit_after_dump=quit_after_dump,
        ),
        enable_second_chance_av=av,
    )


def test_generate_wds_includes_debugger_policy_and_breakpoint():
    script = generate_wds(_base_config())
    assert "sxd ibp" in script
    assert "sxd ld" in script
    assert "sxn av" in script
    assert 'sxe -c ".echo BADCHAR_CRASH; q" av' in script
    assert 'bp 0x625011AF "' in script


def test_generate_wds_step_mode_none_omits_step_cmd():
    script = generate_wds(_base_config(step_mode="none"))
    assert "; pt;" not in script
    assert "; gu;" not in script


def test_generate_wds_step_mode_pt():
    script = generate_wds(_base_config(step_mode="pt"))
    assert 'bp 0x625011AF "pt; .writemem' in script


def test_generate_wds_step_mode_gu():
    script = generate_wds(_base_config(step_mode="gu"))
    assert 'bp 0x625011AF "gu; .writemem' in script


def test_generate_wds_step_mode_custom():
    script = generate_wds(_base_config(step_mode="custom", custom_step="t"))
    assert 'bp 0x625011AF "t; .writemem' in script


def test_generate_wds_wraps_dump_expression():
    script = generate_wds(_base_config())
    assert ".writemem " in script
    assert "(poi(@esp+4)+2006)" in script
    assert "((poi(@esp+4)+2006)+0x40)" in script


def test_generate_wds_can_disable_second_chance_av():
    script = generate_wds(_base_config(av=False))
    assert 'sxe -c ".echo BADCHAR_CRASH; q" av' not in script


def test_generate_wds_quit_after_dump():
    script = generate_wds(_base_config(quit_after_dump=True))
    assert '; q"' in script
    assert '\nq\n' not in script


def test_generate_wds_escapes_quotes_in_paths():
    cfg = WDSConfig(
        stage=Stage(
            breakpoint="mymod!func",
            dump_expr="(@eax)",
            dump_size=8,
            step_mode="none",
            temp_dump_path='C:\\tmp\\"bad".tmp',
            final_dump_path='C:\\tmp\\"bad".bin',
        )
    )
    script = generate_wds(cfg)
    assert '\\"bad\\"' in script


def test_generate_wds_invalid_step_mode():
    with pytest.raises(ValueError):
        generate_wds(_base_config(step_mode="invalid"))


def test_generate_wds_custom_mode_requires_custom_step():
    with pytest.raises(ValueError):
        generate_wds(_base_config(step_mode="custom", custom_step=""))


def test_generate_wds_invalid_dump_size():
    cfg = _base_config()
    cfg.stage.dump_size = 0
    with pytest.raises(ValueError):
        generate_wds(cfg)
