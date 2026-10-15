# FILE-03 — stateful record decoding

`file03.exe` processes a record through a heap decode buffer and then stages a
bounded prefix on the stack. Some observations depend on a byte's neighbour,
so single-byte testing alone is insufficient.

Generate each input with `generate_file.py --challenge file03`. First verify a
known-good record, then compare short individual probes with ordered pairwise
probes. Locate the raw file payload, the decoded heap bytes, and the final
stack staging area before recording any conclusion.

Do not treat a length change as deletion until the record passes parsing and
you have compared the correct processing stage.
