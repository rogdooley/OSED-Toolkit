# Exercise 02 — The PEB (Process Environment Block)

## The question

The PEB is a per-process structure. Given its address, what are the three
fields that matter for shellcode, and how do you read them?

---

## Setup

Continue from Exercise 01. You have `PEB_ADDR` from `dd fs:[30] L1`.

If starting fresh:

```
windbgx -o stack_lab_x86.exe HelloWorld
```

Break anywhere after main starts, then:

```
0:000> dd fs:[30] L1
```

Write down the value as `PEB_ADDR`.

---

## Step 1 — Dump the PEB with `dt`

```
0:000> dt ntdll!_PEB PEB_ADDR
```

Look for three fields in the output:

- `BeingDebugged` — 1 byte at offset `0x02`. If non-zero, the process knows
  it is being debugged. Anti-debug checks read this field.
- `ImageBaseAddress` — 4 bytes at offset `0x08`. The base address of the
  process's main executable image.
- `Ldr` — 4 bytes at offset `0x0c`. Pointer to `PEB_LDR_DATA`.

Note the values. Keep `dt` open while you do the manual reads below.

---

## Step 2 — Read the PEB manually (offset by offset)

**BeingDebugged (PEB+0x02):**

```
0:000> db PEB_ADDR+2 L1
```

If you're debugging the process right now, this byte should be `01`. That is
why antivirus and malware both check it. Shellcode that checks `[peb+2]` and
exits if it's set is implementing a basic anti-debugging check.

**ImageBaseAddress (PEB+0x08):**

```
0:000> dd PEB_ADDR+8 L1
```

Compare to `lm m stack_lab_x86`. The base address should match.

**Ldr (PEB+0x0c):**

```
0:000> dd PEB_ADDR+0xc L1
```

Call this value `LDR_ADDR`. This is your entry point to the module list. Every
module the process has loaded is reachable from here.

---

## Step 3 — The PEB layout (abbreviated x86)

```
Offset  Size  Field
0x00    1     InheritedAddressSpace
0x01    1     ReadImageFileExecOptions
0x02    1     BeingDebugged             <-- anti-debug flag
0x03    1     BitField
0x04    4     Mutant
0x08    4     ImageBaseAddress          <-- executable's base
0x0c    4     Ldr                       <-- PEB_LDR_DATA* (module list)
0x10    4     ProcessParameters         <-- RTL_USER_PROCESS_PARAMETERS*
0x14    4     SubSystemData
0x18    4     ProcessHeap               <-- default heap handle
...
```

The relevant fields for shellcode development:

| Offset | What it gives you |
|---|---|
| `+0x02` | Anti-debug detection (BeingDebugged byte) |
| `+0x08` | Main image base |
| `+0x0c` | Module list (Ldr → DLL bases and names) |

---

## Step 4 — Verify with osed-windbg

The osed-windbg toolkit's `sc.peb()` command reads these exact fields:

```
0:000> dx @$osed().sc.peb()
```

Expected output (fields may vary by Windows version):

```
[0]  : PEB              = 0x00X...
[1]  : Ldr              = 0x00Y...
[2]  : ProcessParameters= 0x00Z...
[3]  : BeingDebugged    = true
[4]  : ImageBase        = 0x00400000
```

Cross-check each value against your manual reads. They should match exactly.

---

## Step 5 — The ProcessParameters field

While not needed for module walking, `ProcessParameters` at `PEB+0x10` points
to `RTL_USER_PROCESS_PARAMETERS`, which contains the command-line string and
the working directory. Shellcode that needs to know the process path reads
this field.

Peek at it:

```
0:000> dd PEB_ADDR+0x10 L1           ; ProcessParameters pointer
0:000> dt ntdll!_RTL_USER_PROCESS_PARAMETERS poi(PEB_ADDR+0x10)
```

Find the `CommandLine` field (a `UNICODE_STRING`). It contains the full command
line. You've now traced the entire process context from a single CPU instruction
(`mov eax, fs:[0x30]`).

---

## Checkpoint

Answer in your notes (no debugger):

1. What does a non-zero `BeingDebugged` byte mean, and why would shellcode
   check it?
2. At what offset in the PEB is the Ldr pointer?
3. What does the Ldr pointer lead to?
4. How do you read `PEB.BeingDebugged` in one WinDbg command (starting from
   the FS register)?
5. What field contains the command-line string of the process?

---

## Offset cheat sheet (x86 PEB)

```
PEB + 0x02   BeingDebugged (1 byte)
PEB + 0x08   ImageBaseAddress (4 bytes)
PEB + 0x0c   Ldr → PEB_LDR_DATA (4 bytes)
PEB + 0x10   ProcessParameters (4 bytes)
PEB + 0x18   ProcessHeap (4 bytes)
```

Access pattern from scratch:

```asm
mov eax, fs:[0x30]    ; EAX = PEB
mov eax, [eax+0x0c]   ; EAX = Ldr (PEB_LDR_DATA*)
```

You will type this from memory before this series is over.
