"""
Tools.rop — ROP chain planning, validation, and serialization for x86 Windows.

Typical usage
-------------
::

    from Tools.rop import (
        GadgetDB,
        VirtualProtectChain,
        ChainValidator,
        ChainSerializer,
        DryRunPrinter,
    )

    db = GadgetDB.from_file("gadgets.json")

    vp = VirtualProtectChain(shellcode_size=0x201)
    chain = vp.plan()

    validator = ChainValidator()
    issues = validator.validate(chain, db, bad_chars=b"\\x00\\x0a\\x0d")
    for issue in issues:
        print(issue)

    DryRunPrinter().print_chain(chain, db, bad_chars=b"\\x00\\x0a\\x0d")

    raw = ChainSerializer().serialize(chain, db, shellcode_addr=0x00419000)

For building custom chains use RopChain::

    from Tools.rop import RopChain

    chain = (
        RopChain()
        .push_gadget("pop_eax_ret", "load EAX")
        .push_dword(0x41414141, "placeholder")
        .push_shellcode_ptr("return target")
    )
"""

from Tools.rop.chain import RopChain, VirtualProtectChain, VIRTUALPROTECT_REQUIRED_GADGETS
from Tools.rop.gadget_db import GadgetDB, GadgetDBError
from Tools.rop.models import (
    ChainElement,
    GadgetRef,
    Gadget,
    PaddingBlock,
    RawDword,
    ShellcodePtr,
    ValidationIssue,
    WritablePtr,
)
from Tools.rop.printer import DryRunPrinter
from Tools.rop.serializer import ChainSerializer, SerializationError
from Tools.rop.validator import ChainValidator

__all__ = [
    # Chain builders
    "RopChain",
    "VirtualProtectChain",
    "VIRTUALPROTECT_REQUIRED_GADGETS",
    # Gadget database
    "GadgetDB",
    "GadgetDBError",
    # Element types
    "ChainElement",
    "GadgetRef",
    "Gadget",
    "PaddingBlock",
    "RawDword",
    "ShellcodePtr",
    "WritablePtr",
    # Validation
    "ChainValidator",
    "ValidationIssue",
    # Serialization
    "ChainSerializer",
    "SerializationError",
    # Output
    "DryRunPrinter",
]
