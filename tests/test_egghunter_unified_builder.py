from Tools.egghunter.unified_builder import EgghunterBuilder, EgghunterConfig


def test_syscall_hunter_uses_conditional_control_flow_and_jmp_edi() -> None:
    cfg = EgghunterConfig(
        tag=b"W00T",
        badchars=b"\x00\x0a\x0d",
    )
    hunter = EgghunterBuilder(cfg).build(strategy="syscall")

    cmp_idx = hunter.find(b"\x3c\x05")
    assert cmp_idx >= 0, "Expected cmp al, 0x05"
    page_check_branch = hunter[cmp_idx + 3 : cmp_idx + 5]
    assert page_check_branch[0] == 0x74, "Expected JE after cmp al, 0x05"

    first_scasd_idx = hunter.find(b"\xaf")
    assert first_scasd_idx >= 0, "Expected first scasd"
    first_scasd_branch = hunter[first_scasd_idx + 1 : first_scasd_idx + 3]
    assert first_scasd_branch[0] == 0x75, "Expected JNZ after first scasd"

    second_scasd_idx = hunter.find(b"\xaf", first_scasd_idx + 1)
    assert second_scasd_idx >= 0, "Expected second scasd"
    second_scasd_branch = hunter[second_scasd_idx + 1 : second_scasd_idx + 3]
    assert second_scasd_branch[0] == 0x75, "Expected JNZ after second scasd"

    assert hunter.endswith(b"\xff\xe7"), "Expected final jmp edi"
