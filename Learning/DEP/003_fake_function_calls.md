# Lesson Capture 003 — Building a Fake Function Call

## Objective

Understand why a ROP chain can enter `VirtualProtect` or `VirtualAlloc` without using a normal `CALL` instruction.

## Ordinary C model

Use a fully specified conceptual example:

```c
void foo(void *shellcode)
{
    DWORD oldProtect;

    VirtualProtect(
        shellcode,
        0x400,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
}
```

The original discussion used `shellcode` before declaring it. That was correctly identified as an imprecise teaching example. In this corrected model it is a parameter, so the compiler has a definite pointer value to pass.

## Prototype and value meanings

```c
BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);
```

| Parameter | Value in the example | Meaning |
|---|---:|---|
| `lpAddress` | `shellcode` | first byte of the region whose protection changes |
| `dwSize` | `0x400` | region length to cover the payload |
| `flNewProtect` | `0x40` | `PAGE_EXECUTE_READWRITE` |
| `lpflOldProtect` | `&oldProtect` | writable location where Windows stores the prior protection |

The fourth argument is a pointer to storage, not the old protection value itself.

## Compiler-generated pushes

x86 `stdcall` pushes arguments right-to-left:

```asm
push &oldProtect
push 0x40
push 0x400
push shellcode
call VirtualProtect
```

Immediately before `CALL`:

```text
Higher addresses

ESP ---> shellcode address       ; lpAddress
         0x400                   ; dwSize
         0x40                    ; flNewProtect
         &oldProtect             ; lpflOldProtect

Lower addresses
```

## What `CALL` adds

When `CALL VirtualProtect` executes, it pushes the address of the next instruction in `foo`.

After `CALL` and at the first instruction of `VirtualProtect`:

```text
ESP ---> ReturnToFoo
         shellcode address
         0x400
         0x40
         &oldProtect
```

`CALL` changes `EIP` to the target and leaves this stack frame. It does not push `EBP`.

## Callee prologue

The callee may execute:

```asm
push ebp
mov  ebp, esp
```

Then its conventional frame is:

```text
EBP+00  saved caller EBP
EBP+04  ReturnToFoo
EBP+08  lpAddress
EBP+0C  dwSize
EBP+10  flNewProtect
EBP+14  lpflOldProtect
```

The code is elsewhere in the process, but the stack is the same thread-owned stack. The callee reads offsets from the current frame; it does not need the arguments to be near its code.

## Fake call with `RET`

Before a ROP `RET`, arrange:

```text
ESP ---> VirtualProtect
         ReturnToShellcode
         shellcode address
         0x400
         0x40
         WritableAddress
```

Execute:

```asm
ret
```

CPU effect:

```asm
EIP = [ESP]       ; EIP = VirtualProtect
ESP = ESP + 4     ; ESP -> ReturnToShellcode
```

At API entry:

```text
EIP = VirtualProtect
ESP -> ReturnToShellcode
       shellcode address
       0x400
       0x40
       WritableAddress
```

This is bit-for-bit the same stack layout as a normal call, except the return address now points to shellcode.

## Why `lpAddress` is not execution

`lpAddress` is an argument consumed by `VirtualProtect` or `VirtualAlloc`. It identifies memory. It is not the next instruction.

The return address is the first DWORD at `[ESP]` when the API starts. Its value may happen to equal the shellcode address. The API returns by loading that value into `EIP`.

## API return

After changing protection, the API executes its normal return sequence. The return address is popped into `EIP` and execution continues at the shellcode address placed in the frame.

```text
VirtualProtect
       |
       +-- RET -> shellcode
```

The ROP chain's job is not to execute shellcode directly. It constructs a legitimate call frame and lets the API's ordinary return mechanism transfer control.

## Stack as a program

Once ROP begins, each `RET` consumes the next code address. Values after that address may be:

- a constant for `POP`;
- a pointer for a memory operation;
- a future gadget address;
- an API return address;
- an API argument.

The stack is therefore both a control-flow graph and a data source.

## Exercises preserved

1. Draw the stack immediately before four argument pushes.
2. Draw the stack immediately after the four pushes.
3. Add the return address pushed by `CALL`.
4. Replace `CALL` with `RET` and show why the callee sees the same layout.
5. Label the difference between `[ESP]` and `[ESP+4]` at API entry.

## Durable rules

- A callee cares about calling-convention locations, not the history of control transfer.
- `CALL` supplies a return address; a ROP `RET` can supply the same observable state.
- The return address precedes the first argument.
- `lpAddress` identifies memory; it does not direct execution.
