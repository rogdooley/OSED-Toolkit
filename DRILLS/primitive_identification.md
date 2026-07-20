# Primitive Identification Worksheet

Purpose: identify the problem you are actually solving before building an exploit.

## Memory Corruption Primitive

```text
[ ] Stack overflow
[ ] Heap overflow
[ ] SEH overwrite
[ ] Format string
[ ] Integer overflow
[ ] Use-after-free
[ ] Arbitrary write
[ ] Arbitrary read
[ ] Other: __________________________________________
```

## Control Primitive

```text
[ ] EIP control
[ ] SEH control
[ ] Arbitrary write
[ ] Arbitrary read
[ ] Partial overwrite
[ ] Pointer control
[ ] Other: __________________________________________
```

## Execution Primitive

```text
[ ] JMP ESP
[ ] CALL ESP
[ ] Stack pivot
[ ] ROP
[ ] RET2LIB / API call
[ ] Egghunter
[ ] Direct return target
[ ] Other: __________________________________________
```

## Mitigation State

```text
[ ] DEP
[ ] ASLR
[ ] CFG
[ ] SafeSEH
[ ] /GS
[ ] CET
[ ] Other: __________________________________________
```

## Notes

```text
____________________________________________________
____________________________________________________
____________________________________________________
```
