# 24. WinDbg Reading Guide

## Register Commands

```
r                    ; display all registers
r eax                ; display EAX only
r eax=41414141       ; set EAX to 0x41414141
```

## Disassembly

```
u eip                ; disassemble 8 instructions at EIP
u eip L20            ; disassemble 32 instructions at EIP
ub eip               ; disassemble backward from EIP
uf <address>         ; disassemble entire function
u <addr1> <addr2>    ; disassemble range
```

## Memory Display

```
dd <addr>            ; display DWORDs (4-byte values)
dd <addr> L8         ; display 8 DWORDs
db <addr>            ; display bytes
db <addr> L40        ; display 64 bytes
dc <addr>            ; display bytes with ASCII
da <addr>            ; display ASCII string
du <addr>            ; display Unicode string
dps <addr>           ; display pointers with symbols
dds <addr>           ; display DWORDs with symbols
```

`dd` shows values as the CPU interprets them (little-endian reconstructed).
`db` shows raw byte order in memory.

## Stack Commands

```
k                    ; call stack (return addresses)
kb                   ; call stack with first 3 args
kv                   ; call stack with calling convention info
kn                   ; call stack with frame numbers
```

## Module Commands

```
lm                   ; list all loaded modules
lm m kernel32        ; show kernel32 module info
lm m <pattern>       ; wildcard search for modules
```

## Memory Protection

```
!address <addr>      ; full details of memory region
!vprot <addr>        ; page protection of specific address
!address -summary    ; memory usage summary
```

## Structure Display

```
dt ntdll!_PEB @$peb                        ; display PEB structure
dt ntdll!_TEB @$teb                        ; display TEB structure
dt ntdll!_PEB_LDR_DATA poi(@$peb+0xc)     ; display loader data
dt ntdll!_LDR_DATA_TABLE_ENTRY <addr>      ; display module entry
```

## Exception State

```
.exr -1              ; display most recent exception record
.ecxr                ; switch to exception context (registers at fault)
!analyze -v          ; verbose crash analysis
```

## First-Chance vs. Second-Chance Exceptions

A **first-chance exception** is the debugger's first notification. The
application has not yet had a chance to handle it. If the debugger passes it
(`g`), the application's exception handlers run. If no handler handles it, the
debugger gets a **second-chance exception** -- this is the unhandled crash.

For SEH exploitation: break on first-chance (`sxe av`) to inspect the corrupted
SEH chain before dispatch. If you wait for second-chance, you've missed the
window.

## Context Distinction

- **Current context:** the thread/frame the debugger is focused on (set by `.frame`, `.thread`)
- **Exception context:** the register state at the time of the fault (switch with `.ecxr`)
- **Current EIP:** where the debugger is stopped (may differ from the faulting instruction after an exception)

After a crash, EIP shown by `r` may not be the faulting instruction. Use
`.ecxr` to see the actual state at the fault, then `u @eip` to see the
faulting instruction.

## Breakpoints

```
bp <addr>            ; set breakpoint
bl                   ; list breakpoints
bc *                 ; clear all breakpoints
bp <addr> ".if @eax==0x40 {} .else {gc}"   ; conditional breakpoint
ba r4 <addr>         ; hardware breakpoint (read, 4 bytes)
ba w4 <addr>         ; hardware breakpoint (write, 4 bytes)
ba e1 <addr>         ; hardware breakpoint (execute, 1 byte)
```

## Exception Handling Configuration

```
sxe av               ; break on first-chance access violation
sxd av               ; pass first-chance AV to application
sxe ld <module>      ; break when module is loaded
```

## Useful Expressions

```
? 0x40 + 4           ; evaluate arithmetic
? 0 - 0x1c           ; compute negative (two's complement)
? poi(esp)            ; dereference ESP
? @eax + @ecx        ; register arithmetic
```
