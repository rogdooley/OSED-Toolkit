"""Core typed models for ASM-Lab milestone one."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator


class Architecture(StrEnum):
    X86 = "x86"


class Width(StrEnum):
    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    QWORD = "qword"


class ValueFormat(StrEnum):
    HEX = "hex"
    ASCII = "ascii"
    UNSIGNED = "unsigned"
    SIGNED = "signed"
    POINTER = "pointer"


class ExplanationCategory(StrEnum):
    WHAT_CHANGED = "what_changed"
    WHY = "why"
    INTERPRETATION = "interpretation"
    SHELLCODE_RELEVANCE = "shellcode_relevance"


class StackRole(StrEnum):
    LOCAL = "local"
    SAVED_EBP = "saved_ebp"
    RETURN_ADDRESS = "return_address"
    ARGUMENT = "argument"
    UNKNOWN = "unknown"


class ByteSequence(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: bytes = Field(default=b"")

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: object) -> object:
        if isinstance(value, cls):
            return {"data": value.data}
        if isinstance(value, bytes):
            return {"data": value}
        if isinstance(value, bytearray):
            return {"data": bytes(value)}
        if isinstance(value, list):
            normalized = cls._normalize_int_sequence(value)
            return {"data": bytes(normalized)}
        if isinstance(value, dict) and "data" in value:
            normalized = cls.normalize_input(value["data"])
            return normalized
        return value

    @staticmethod
    def _normalize_int_sequence(values: list[object]) -> list[int]:
        normalized: list[int] = []
        for byte_value in values:
            if not isinstance(byte_value, int):
                msg = "Byte sequences must contain integers only."
                raise TypeError(msg)
            if not 0 <= byte_value <= 0xFF:
                msg = "Each byte must be in the range 0x00-0xff."
                raise ValueError(msg)
            normalized.append(byte_value)
        return normalized

    @field_serializer("data", when_used="always")
    def serialize_data(self, value: bytes) -> list[int]:
        return list(value)

    def __len__(self) -> int:
        return len(self.data)

    def to_hex(self, separator: str = " ") -> str:
        return separator.join(f"{byte_value:02x}" for byte_value in self.data)

    def to_ascii(self, replacement: str = ".") -> str:
        if len(replacement) != 1:
            msg = "ASCII replacement must be a single character."
            raise ValueError(msg)
        return "".join(
            chr(byte_value) if 32 <= byte_value <= 126 else replacement
            for byte_value in self.data
        )

    def to_little_endian_int(self, width: int | None = None) -> int:
        effective_width = width if width is not None else len(self.data)
        if effective_width not in {1, 2, 4, 8}:
            msg = "Little-endian interpretation supports widths of 1, 2, 4, or 8 bytes."
            raise ValueError(msg)
        if len(self.data) != effective_width:
            msg = "Byte sequence length must match the requested little-endian width."
            raise ValueError(msg)
        return int.from_bytes(self.data, byteorder="little", signed=False)


class RegisterState(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=2)
    width_bits: int = Field(gt=0)
    value: int = Field(ge=0)


class MemoryRegion(BaseModel):
    model_config = ConfigDict(frozen=True)

    start_address: int = Field(ge=0)
    bytes_value: ByteSequence = Field(default_factory=ByteSequence)
    label: str | None = None
    notes: list[str] = Field(default_factory=list)


class MachineState(BaseModel):
    model_config = ConfigDict(frozen=True)

    architecture: Architecture = Architecture.X86
    registers: list[RegisterState] = Field(default_factory=list)
    memory_regions: list[MemoryRegion] = Field(default_factory=list)
    stack_pointer_register: str = "esp"
    instruction_pointer_register: str = "eip"
    annotations: list[str] = Field(default_factory=list)


class RegisterChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    register_name: str = Field(min_length=2)
    before: int = Field(ge=0)
    after: int = Field(ge=0)
    width_bits: int = Field(gt=0)
    reason: str | None = None


class MemoryRead(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int = Field(ge=0)
    bytes_value: ByteSequence = Field(default_factory=ByteSequence)
    width: Width = Width.DWORD
    pointer_source: str | None = None
    notes: list[str] = Field(default_factory=list)


class MemoryWrite(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int = Field(ge=0)
    before_bytes: ByteSequence = Field(default_factory=ByteSequence)
    after_bytes: ByteSequence = Field(default_factory=ByteSequence)
    width: Width = Width.DWORD
    notes: list[str] = Field(default_factory=list)


class StackChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    stack_pointer_register: str = "esp"
    before: int = Field(ge=0)
    after: int = Field(ge=0)
    pushed_bytes: ByteSequence = Field(default_factory=ByteSequence)
    popped_bytes: ByteSequence = Field(default_factory=ByteSequence)
    notes: list[str] = Field(default_factory=list)

    @property
    def delta(self) -> int:
        return self.after - self.before


class ExplanationEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str = Field(min_length=1)
    label: str = Field(min_length=1)
    text: str = Field(min_length=1)


class Explanation(BaseModel):
    model_config = ConfigDict(frozen=True)

    instruction: str = Field(min_length=1)
    changed_registers: list[RegisterChange] = Field(default_factory=list)
    memory_reads: list[MemoryRead] = Field(default_factory=list)
    memory_writes: list[MemoryWrite] = Field(default_factory=list)
    stack_changes: list[StackChange] = Field(default_factory=list)
    what_changed: list[ExplanationEntry] = Field(default_factory=list)
    why: list[ExplanationEntry] = Field(default_factory=list)
    interpretation: list[ExplanationEntry] = Field(default_factory=list)
    shellcode_relevance: list[ExplanationEntry] = Field(default_factory=list)

    def emitted_categories(self) -> set[ExplanationCategory]:
        emitted: set[ExplanationCategory] = set()
        if self.what_changed:
            emitted.add(ExplanationCategory.WHAT_CHANGED)
        if self.why:
            emitted.add(ExplanationCategory.WHY)
        if self.interpretation:
            emitted.add(ExplanationCategory.INTERPRETATION)
        if self.shellcode_relevance:
            emitted.add(ExplanationCategory.SHELLCODE_RELEVANCE)
        return emitted


class InspectSectionBase(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: str = Field(min_length=1)


class InspectSection(InspectSectionBase):
    model_config = ConfigDict(frozen=True)

    format: ValueFormat
    value: str = Field(min_length=1)
    raw_bytes: ByteSequence | None = None


class StackRangeEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int = Field(ge=0)
    offset_from_ebp: int
    raw_bytes: ByteSequence = Field(default_factory=ByteSequence)
    numeric_value: int | None = Field(default=None, ge=0)
    symbolic_value: str | None = None
    role: StackRole
    label: str | None = None


class StackRangeSection(InspectSectionBase):
    model_config = ConfigDict(frozen=True)

    entries: list[StackRangeEntry] = Field(default_factory=list)
    base_pointer_value: int | None = Field(default=None, ge=0)
    stack_pointer_value: int | None = Field(default=None, ge=0)
    notes: list[str] = Field(default_factory=list)


class InspectViewModel(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    raw_value: int = Field(ge=0)
    sections: list[InspectSection | StackRangeSection] = Field(default_factory=list)
    common_meaning: str | None = None
    shellcode_relevance: list[ExplanationEntry] = Field(default_factory=list)


class InstructionEncoding(BaseModel):
    model_config = ConfigDict(frozen=True)

    bytes_value: ByteSequence = Field(default_factory=ByteSequence)
    notes: list[str] = Field(default_factory=list)


class PredictionPrompt(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1)
    focus: list[str] = Field(default_factory=list)


class StateSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: str = Field(min_length=1)
    machine_state: MachineState
    notes: list[str] = Field(default_factory=list)


class ExpectedRegisterChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    register_name: str = Field(min_length=2)
    before: int | None = Field(default=None, ge=0)
    after: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def require_expectation(self) -> "ExpectedRegisterChange":
        if self.before is None and self.after is None:
            msg = "Expected register changes must assert a before or after value."
            raise ValueError(msg)
        return self


class ExpectedMemoryRead(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int | None = Field(default=None, ge=0)
    bytes_value: ByteSequence | None = None
    width: Width | None = None
    pointer_source: str | None = None

    @model_validator(mode="after")
    def require_expectation(self) -> "ExpectedMemoryRead":
        if self.address is None and self.bytes_value is None and self.width is None:
            msg = "Expected memory reads must assert an address, bytes, or width."
            raise ValueError(msg)
        return self


class ExpectedMemoryWrite(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int | None = Field(default=None, ge=0)
    before_bytes: ByteSequence | None = None
    after_bytes: ByteSequence | None = None
    width: Width | None = None

    @model_validator(mode="after")
    def require_expectation(self) -> "ExpectedMemoryWrite":
        if self.address is None and self.before_bytes is None and self.after_bytes is None:
            msg = "Expected memory writes must assert an address or byte transition."
            raise ValueError(msg)
        return self


class ExpectedStackPointerMovement(BaseModel):
    model_config = ConfigDict(frozen=True)

    register_name: str = "esp"
    before: int | None = Field(default=None, ge=0)
    after: int | None = Field(default=None, ge=0)
    delta: int


class LessonStepAssertions(BaseModel):
    model_config = ConfigDict(frozen=True)

    changed_registers: list[ExpectedRegisterChange] = Field(default_factory=list)
    memory_reads: list[ExpectedMemoryRead] = Field(default_factory=list)
    memory_writes: list[ExpectedMemoryWrite] = Field(default_factory=list)
    stack_pointer_movement: ExpectedStackPointerMovement | None = None
    explanation_categories: list[ExplanationCategory] = Field(default_factory=list)
    required_interpretation_keys: list[str] = Field(default_factory=list)
    required_shellcode_relevance_keys: list[str] = Field(default_factory=list)


class ExpectedExplanationOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    categories: list[ExplanationCategory] = Field(default_factory=list)
    what_changed_keys: list[str] = Field(default_factory=list)
    why_keys: list[str] = Field(default_factory=list)
    interpretation_keys: list[str] = Field(default_factory=list)
    shellcode_relevance_keys: list[str] = Field(default_factory=list)


class LessonStepExpectedOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_trace: "ExecutionTrace"
    state_diff: "StateDiff"
    explanation: ExpectedExplanationOutput
    inspect_views: list[InspectViewModel] = Field(default_factory=list)
    before_state: StateSnapshot | None = None
    after_state: StateSnapshot | None = None
    state_snapshot: StateSnapshot | None = None
    instruction_encoding: InstructionEncoding | None = None


class LessonStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    instruction: str = Field(min_length=1)
    explanation_focus: list[str] = Field(default_factory=list)
    expected_learning_points: list[str] = Field(default_factory=list)
    assertions: LessonStepAssertions | None = None
    prediction_prompt: PredictionPrompt | None = None
    expected_output: LessonStepExpectedOutput | None = None


class LessonMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    pedagogical_objective: str = Field(min_length=1)
    architecture: Architecture = Architecture.X86
    tags: list[str] = Field(default_factory=list)


class Lesson(BaseModel):
    model_config = ConfigDict(frozen=True)

    metadata: LessonMetadata
    initial_state: MachineState
    steps: list[LessonStep] = Field(min_length=1)
    expected_outcomes: list[str] = Field(default_factory=list)


class RegisterDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    register_name: str = Field(min_length=2)
    before: int = Field(ge=0)
    after: int = Field(ge=0)
    width_bits: int = Field(gt=0)


class MemoryDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: int = Field(ge=0)
    before_bytes: ByteSequence = Field(default_factory=ByteSequence)
    after_bytes: ByteSequence = Field(default_factory=ByteSequence)
    width: Width = Width.DWORD


class StackDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    stack_pointer_register: str = "esp"
    before: int = Field(ge=0)
    after: int = Field(ge=0)
    pushed_bytes: ByteSequence = Field(default_factory=ByteSequence)
    popped_bytes: ByteSequence = Field(default_factory=ByteSequence)

    @property
    def delta(self) -> int:
        return self.after - self.before


class StateDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    register_diffs: list[RegisterDiff] = Field(default_factory=list)
    memory_diffs: list[MemoryDiff] = Field(default_factory=list)
    stack_diffs: list[StackDiff] = Field(default_factory=list)


class ExecutionTrace(BaseModel):
    model_config = ConfigDict(frozen=True)

    instruction: str = Field(min_length=1)
    operands: list[str] = Field(default_factory=list)
    reads: list[MemoryRead] = Field(default_factory=list)
    writes: list[MemoryWrite] = Field(default_factory=list)
    register_changes: list[RegisterChange] = Field(default_factory=list)
    stack_changes: list[StackChange] = Field(default_factory=list)
    state_diff: StateDiff | None = None
    notes: list[str] = Field(default_factory=list)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    before_state: MachineState
    after_state: MachineState
    execution_trace: ExecutionTrace
    state_diff: StateDiff


class GoldenLessonFixture(BaseModel):
    model_config = ConfigDict(frozen=True)

    metadata: LessonMetadata
    initial_state: MachineState
    steps: list[LessonStep] = Field(min_length=1)
    final_stack_pointer: int = Field(ge=0)
    final_memory_at_stack_pointer: ByteSequence = Field(default_factory=ByteSequence)
    notes: list[str] = Field(default_factory=list)
