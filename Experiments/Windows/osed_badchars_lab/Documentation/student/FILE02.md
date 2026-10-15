# FILE-02 — file extraction across heap allocations

`file02.exe` reads a binary file record and moves its candidate from the file
buffer to a second heap allocation. Inspect both locations before comparing
them.

Generate input with `generate_file.py --challenge file02`. Use a known-good
array first, then a complete byte array. The first heap allocation holds the
file contents; the later allocation is the useful comparison destination.

The record must retain its expected version, kind, and declared length. A
rejected file says nothing about candidate-byte behavior.
