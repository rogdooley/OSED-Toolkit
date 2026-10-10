# Target 02 Instructor Guide

## Architecture

The second loopback TCP service keeps a per-connection `Session` object. Its major paths are `client -> answer` and `client -> amend -> mix`. They share state but interpret request fields differently.

## Analysis notes

The response path serializes a fixed local packet from the session state according to caller-selected output length. It exposes internal session material through an otherwise ordinary response. The update path transforms a supplied body, checks a discriminator, then uses a transformed byte as a copy count into the label member. This produces a separate stack-independent overwrite within the session object. The binary enables both ASLR and DEP; the disclosure is relevant to reasoning about randomized process state but does not by itself establish exploitability.

## Suggested hints

1. Follow both branches from the operation comparison; do not infer behavior from their values.
2. Identify the stack and structure layouts on each send path.
3. In the update path, trace the byte used as a copy count back through the transformation.

## Validation notes

Exercise valid requests first. Instructor-only tests may demonstrate the two paths separately; do not ship an exploit chain, shellcode, or ROP material.
