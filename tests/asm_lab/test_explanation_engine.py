from asm_lab.explanation import ExplanationEngine
from asm_lab.models import ExecutionTrace, MemoryRead, MemoryWrite, RegisterChange, StateDiff, StackChange, Width


def test_mov_explanation_from_register_change_and_memory_read() -> None:
    engine = ExplanationEngine()
    trace = ExecutionTrace(
        instruction="mov eax, [esi]",
        operands=["eax", "[esi]"],
        reads=[
            MemoryRead(
                address=0x2000,
                bytes_value=[0x63, 0x61, 0x6C, 0x63],
                width=Width.DWORD,
                pointer_source="esi",
            )
        ],
        register_changes=[
            RegisterChange(register_name="eax", before=0, after=0x636C6163, width_bits=32)
        ],
    )

    explanation = engine.build_explanation(trace, StateDiff())

    assert {entry.key for entry in explanation.what_changed} >= {"register.updated", "memory.read"}
    assert {entry.key for entry in explanation.why} >= {"pointer.followed"}
    assert "ascii.pointer_string" in {entry.key for entry in explanation.interpretation}
    assert any("0x2000" in entry.text for entry in explanation.why)


def test_push_explanation_from_stack_pointer_change_and_memory_write() -> None:
    engine = ExplanationEngine()
    trace = ExecutionTrace(
        instruction="push 0x636c6163",
        writes=[
            MemoryWrite(
                address=0x0012FF40,
                before_bytes=[0x00, 0x00, 0x00, 0x00],
                after_bytes=[0x63, 0x61, 0x6C, 0x63],
                width=Width.DWORD,
            )
        ],
        stack_changes=[
            StackChange(
                before=0x0012FF44,
                after=0x0012FF40,
                pushed_bytes=[0x63, 0x61, 0x6C, 0x63],
            )
        ],
    )

    explanation = engine.build_explanation(trace, StateDiff())

    assert "stack.pointer_moved" in {entry.key for entry in explanation.what_changed}
    assert "stack.memory_written" in {entry.key for entry in explanation.what_changed}
    assert "push.grows_down" in {entry.key for entry in explanation.why}
    assert "stack_string_construction" in {entry.key for entry in explanation.shellcode_relevance}


def test_xor_zeroing_explanation_when_register_clears() -> None:
    engine = ExplanationEngine()
    trace = ExecutionTrace(
        instruction="xor eax, eax",
        register_changes=[
            RegisterChange(register_name="eax", before=0x41414141, after=0, width_bits=32)
        ],
    )

    explanation = engine.build_explanation(trace, StateDiff())

    assert "xor.zeroing" in {entry.key for entry in explanation.why}
    assert "xor_zeroing" in {entry.key for entry in explanation.shellcode_relevance}
    assert any("clears the register to zero" in entry.text for entry in explanation.why)
