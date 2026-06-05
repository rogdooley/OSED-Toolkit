# Module 02 — PEB Walk on x64

## The differences at a glance

| Item | x86 | x64 |
|---|---|---|
| CPU segment for TEB | FS | GS |
| TEB.PEB offset | `+0x30` | `+0x60` |
| Pointer size | 4 bytes | 8 bytes |
| PEB.Ldr offset | `+0x0c` | `+0x18` |
| PEB_LDR_DATA InLoadOrderList.Flink | `+0x0c` | `+0x10` |
| PEB_LDR_DATA InInitOrderList.Flink | `+0x1c` | `+0x30` |
| InLoadOrderLinks to DllBase | `+0x18` | `+0x30` |
| InLoadOrderLinks to BaseDllName.Length | `+0x2c` | `+0x58` |
| InLoadOrderLinks to BaseDllName.Buffer | `+0x30` | `+0x60` |

Everything else — the algorithm, the list structure, the name comparison —
is identical to x86.

---

## Step 1 — Reaching the PEB

```asm
; x64 shellcode:
xor rax, rax
mov rax, gs:[rax + 0x60]   ; RAX = PEB (GS:0x60)
```

In WinDbg on a 64-bit process:

```
0:000> dq gs:[60] L1        ; PEB address
; or:
0:000> r $peb
```

---

## Step 2 — PEB fields (x64)

```
PEB + 0x02   BeingDebugged (1 byte)
PEB + 0x10   ImageBaseAddress (8 bytes)
PEB + 0x18   Ldr → PEB_LDR_DATA (8 bytes)
```

Read them:

```
0:000> dq @$peb+0x18 L1    ; Ldr pointer (8 bytes)
; call this LDR_ADDR

0:000> dq @$peb+0x10 L1    ; ImageBaseAddress
```

Compare with `lm` for the process. Confirm the image base matches.

---

## Step 3 — PEB_LDR_DATA (x64 offsets)

```
PEB_LDR_DATA:
  +0x00   Length (4 bytes)
  +0x04   Initialized (1 byte)
  +0x08   SsHandle (8 bytes)
  +0x10   InLoadOrderModuleList.Flink (8 bytes)
  +0x18   InLoadOrderModuleList.Blink (8 bytes)
  +0x20   InMemoryOrderModuleList.Flink (8 bytes)
  +0x28   InMemoryOrderModuleList.Blink (8 bytes)
  +0x30   InInitializationOrderModuleList.Flink (8 bytes)
  +0x38   InInitializationOrderModuleList.Blink (8 bytes)
```

Read the load-order list head Flink:

```
0:000> dq LDR_ADDR+0x10 L1   ; InLoadOrderModuleList.Flink → first entry
; call this FIRST_ENTRY
```

---

## Step 4 — LDR_DATA_TABLE_ENTRY (x64 from InLoadOrderLinks)

All fields are wider (8-byte pointers):

```
InLoadOrderLinks (LIST_ENTRY, 16 bytes at offset 0x00)
InMemoryOrderLinks (LIST_ENTRY, 16 bytes at offset 0x10)
InInitializationOrderLinks (LIST_ENTRY, 16 bytes at offset 0x20)

From InLoadOrderLinks (offset 0x00):
  +0x30   DllBase (8 bytes)
  +0x38   EntryPoint (8 bytes)
  +0x40   SizeOfImage (4 bytes)
  +0x48   FullDllName.Length (USHORT)
  +0x4a   FullDllName.MaximumLength (USHORT)
  +0x50   FullDllName.Buffer (8 bytes, PWSTR)
  +0x58   BaseDllName.Length (USHORT)
  +0x5a   BaseDllName.MaximumLength (USHORT)
  +0x60   BaseDllName.Buffer (8 bytes, PWSTR)
```

Read the first entry:

```
0:000> dq FIRST_ENTRY+0x30 L1   ; DllBase
0:000> dw FIRST_ENTRY+0x58 L1   ; BaseDllName.Length (USHORT)
0:000> dq FIRST_ENTRY+0x60 L1   ; BaseDllName.Buffer
0:000> du poi(FIRST_ENTRY+0x60)  ; the name string
```

---

## Step 5 — Walk the list

Follow Flink (8 bytes in x64):

```
0:000> dq FIRST_ENTRY L1         ; Flink → next entry
; call this SECOND_ENTRY
0:000> du poi(SECOND_ENTRY+0x60)
```

Termination: when `Flink == LDR_ADDR + 0x10` (address of
InLoadOrderModuleList, not its value).

---

## Step 6 — Verify with osed-windbg (x64 process)

Attach to a native 64-bit process. The osed-windbg toolkit detects pointer
size automatically:

```
0:000> dx @$osed().sc.peb()
0:000> dx @$osed().sc.modules()
0:000> dx @$osed().sc.base("kernel32")
```

Output format is the same as x86, but addresses are 64-bit values.

---

## x64 assembly: find kernel32

```asm
find_kernel32_x64:
    xor     rax, rax
    mov     rax, gs:[rax + 0x60]    ; RAX = PEB (GS:0x60)
    mov     rax, [rax + 0x18]       ; RAX = Ldr (PEB + 0x18)
    lea     rbx, [rax + 0x10]       ; RBX = list head address (for termination)
    mov     rsi, [rax + 0x10]       ; RSI = InLoadOrderModuleList.Flink

.next_module:
    cmp     rsi, rbx                ; looped back to head?
    je      .not_found

    movzx   ecx, word [rsi + 0x58]  ; BaseDllName.Length
    cmp     ecx, 0x18               ; 24 bytes = "KERNEL32.DLL"
    jne     .advance

    mov     rdi, [rsi + 0x60]       ; BaseDllName.Buffer

    mov     eax, [rdi + 0x00]
    cmp     eax, 0x0045004B         ; "KE" (same as x86)
    jne     .advance

    mov     eax, [rdi + 0x04]
    cmp     eax, 0x004E0052         ; "RN"
    jne     .advance

    ; ... remaining chars same as x86 ...

    mov     rax, [rsi + 0x30]       ; DllBase (8 bytes in x64)
    ret

.advance:
    mov     rsi, [rsi]              ; Flink (8 bytes)
    jmp     .next_module

.not_found:
    xor     rax, rax
    ret
```

The name comparison is identical to x86 — the characters are the same
Unicode values. Only the pointer dereferences use 8 bytes instead of 4.

---

## Checkpoint (no reference)

1. Which CPU segment register holds the TEB on x64?
2. TEB.PEB offset on x64: `+0x30` or `+0x60`?
3. PEB.Ldr offset on x64: `+0x0c` or `+0x18`?
4. `InLoadOrderModuleList.Flink` in `PEB_LDR_DATA` at what x64 offset?
5. `DllBase` from `InLoadOrderLinks` on x64 is at what offset?
6. Why is the `BaseDllName` comparison code identical between x86 and x64?
