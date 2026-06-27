from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
@dataclass
class Api:
    name: str
    imported: bool
    note: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Api:
        return cls(
            name=d["name"],
            imported=d["imported"],
            note=d["note"],
        )


@dataclass
class CallingConvention:
    type: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CallingConvention:
        return cls(type=d["type"])


@dataclass
class CopySemantics:
    type: str
    note: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CallingConvention:
        return cls(type=d["type"], note=d["note"])


@dataclass
class Argument:
    stack_offset: int
    note: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Argument:
        return cls(
            stack_offset=d["stack_offset"],
            note=d["note"],
        )


@dataclass
class ProfileHeader:
    type: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> ProfileHeader:
        return cls(type=d["type"])


@dataclass
class Target:
    executable: str
    image_base: int

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Target:
        return cls(
            executable=d["executable"],
            image_base=d["image_base"],
        )


@dataclass
class CandidateDumpExpr:
    expr: str
    confidence: float
    rationale: list[str]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CandidateDumpExpr:
        return cls(
            expr=d["expr"],
            confidence=d["confidence"],
            rationale=list(d["rationale"]),
        )


@dataclass
class CandidateBreakpoint:
    expression: str
    note: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CandidateBreakpoint:
        return cls(
            expression=d["expression"],
            note=d["note"],
        )


@dataclass
class CopySiteFacts:
    rva: int
    api: Api
    calling_convention: CallingConvention
    copy_semantics: CopySemantics
    source_argument: Argument
    destination_argument: Argument

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CopySiteFacts:
        return cls(
            rva=d["rva"],
            api=Api.from_dict(d["api"]),
            calling_convention=CallingConvention.from_dict(d["calling_convention"]),
            copy_semantics=CopySemantics.from_dict(d["copy_semantics"]),
            source_argument=Argument.from_dict(d["source_argument"]),
            destination_argument=Argument.from_dict(d["destination_argument"]),
        )


@dataclass
class CopySiteInferences:
    candidate_breakpoint: CandidateBreakpoint
    candidate_dump_exprs: list[CandidateDumpExpr]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CopySiteInferences:
        return cls(
            candidate_breakpoint=CandidateBreakpoint.from_dict(
                d["candidate_breakpoint"]
            ),
            candidate_dump_exprs=[
                CandidateDumpExpr.from_dict(x) for x in d["candidate_dump_exprs"]
            ],
        )


@dataclass
class CopySite:
    id: str
    facts: CopySiteFacts
    inferences: CopySiteInferences

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CopySite:
        return cls(
            id=d["id"],
            facts=CopySiteFacts.from_dict(d["facts"]),
            inferences=CopySiteInferences.from_dict(d["inferences"]),
        )


@dataclass
class Protocol:
    transport: str
    port: int
    prefix: str
    prefix_length: int
    recv_buffer_size: int
    eip_offset: int
    note: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Protocol:
        return cls(
            transport=d["transport"],
            port=d["port"],
            prefix=d["prefix"],
            prefix_length=d["prefix_length"],
            recv_buffer_size=d["recv_buffer_size"],
            eip_offset=d["eip_offset"],
            note=d["note"],
        )


@dataclass
class CandidateProfile:
    schema_version: int
    profile: ProfileHeader
    produced_by: ProducedBy
    produced_from: list[str]
    target: Target
    analysis: Analysis
    copy_sites: list[CopySite]
    transformation_sites: list[TransformationSite]
    protocol: Protocol
    notes: list[str]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CandidateProfile:
        return cls(
            schema_version=d["schema_version"],
            profile=ProfileHeader.from_dict(d["profile"]),
            produced_by=ProducedBy.from_dict(d["produced_by"]),
            produced_from=list(d.get("produced_from", [])),
            target=Target.from_dict(d["target"]),
            analysis=Analysis.from_dict(d["analysis"]),
            copy_sites=[CopySite.from_dict(site) for site in d.get("copy_sites", [])],
            transformation_sites=[
                TransformationSite.from_dict(site)
                for site in d.get("transformation_sites", [])
            ],
            protocol=Protocol.from_dict(d["protocol"]),
            notes=list(d.get("notes", [])),
        )


@dataclass
class ProducedBy:
    stage: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> ProducedBy:
        return cls(stage=d["stage"])


@dataclass
class Analysis:
    generated_by: str
    generated_at: str
    analyst: str | None
    tools: list

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Analysis:
        return cls(
            generated_by=d["generated_by"],
            generated_at=d["generated_at"],
            analyst=d["analyst"],
            tools=d["tools"],
        )


@dataclass
class Transformation:
    type: str
    input_byte: int | None = None
    output_byte: int | None = None
    action: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Transformation:

        return cls(
            type=d["type"],
            input_byte=d.get("input_byte"),
            output_byte=d.get("output_byte"),
            action=d.get("action"),
        )


@dataclass
class TransformationFacts:
    rva: int | None
    note: str | None
    affected_buffer: str
    location: str
    transformation: Transformation

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TransformationFacts:

        return cls(
            rva=d.get("rva"),
            note=d.get("note"),
            affected_buffer=d["affected_buffer"],
            location=d["location"],
            transformation=Transformation.from_dict(d["transformation"]),
        )


@dataclass
class TransformationSite:
    id: str
    facts: TransformationFacts

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TransformationSite:

        return cls(
            id=d["id"],
            facts=TransformationFacts.from_dict(d["facts"]),
        )
