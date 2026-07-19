# 28. Worked State-Transition Exercises

Work through each exercise by tracking register and memory state
instruction by instruction. Answers follow each problem.

---

## Exercise 1: POP and XCHG

**Initial state:**

```
EAX = 0x12345678
ECX = 0xAAAAAAAA

ESP -> 0x11111111
       0x22222222
       0x33333333
```

**Instructions:**

```asm
pop ecx
xchg eax, ecx
ret
```

**Question:** What are EAX, ECX, EIP, and ESP after execution?

**Answer:**

```
After pop ecx:
  ECX = 0x11111111
  ESP -> 0x22222222
         0x33333333

After xchg eax, ecx:
  EAX = 0x11111111
  ECX = 0x12345678
  ESP -> 0x22222222
         0x33333333

After ret:
  EIP = 0x22222222
  ESP -> 0x33333333
  EAX = 0x11111111
  ECX = 0x12345678
```

---

## Exercise 2: CALL and RET

**Initial state:**

```
EIP = 0x00401000  (address of the CALL instruction)
ESP = 0x0012FF80

Instruction at 0x00401000:  call 0x00402000  (5 bytes long)
Instruction at 0x00402000:  ret
```

**Question:** What are EIP and ESP after the CALL executes? After the RET?

**Answer:**

```
After call 0x00402000:
  EIP = 0x00402000
  ESP = 0x0012FF7C
  [0x0012FF7C] = 0x00401005  (return address = next instruction after CALL)

After ret:
  EIP = 0x00401005
  ESP = 0x0012FF80
```

---

## Exercise 3: RET N

**Initial state:**

```
ESP = 0x0012FF80
[0x0012FF80] = 0x00401000   (return address)
[0x0012FF84] = 0x00000001   (arg1)
[0x0012FF88] = 0x00000002   (arg2)
[0x0012FF8C] = 0x00000003   (arg3)
[0x0012FF90] = 0xDEADBEEF   (caller's data)
```

**Instruction:** `ret 0x0C`

**Question:** What are EIP and ESP after execution?

**Answer:**

```
EIP = 0x00401000  (popped from [0x0012FF80])
ESP = 0x0012FF80 + 4 + 0x0C = 0x0012FF90
                  ^ret   ^cleanup 3 args
Next value at [ESP] = 0xDEADBEEF
```

---

## Exercise 4: PUSH and POP Sequence

**Initial state:**

```
EAX = 0xAAAAAAAA
EBX = 0xBBBBBBBB
ESP = 0x0012FF80
```

**Instructions:**

```asm
push eax
push ebx
pop eax
pop ebx
```

**Question:** What are EAX, EBX, and ESP after execution?

**Answer:**

```
After push eax:  ESP=0x0012FF7C  [0x0012FF7C]=0xAAAAAAAA
After push ebx:  ESP=0x0012FF78  [0x0012FF78]=0xBBBBBBBB
After pop eax:   ESP=0x0012FF7C  EAX=0xBBBBBBBB  (was EBX's value)
After pop ebx:   ESP=0x0012FF80  EBX=0xAAAAAAAA  (was EAX's value)

Final: EAX=0xBBBBBBBB, EBX=0xAAAAAAAA (swapped), ESP=0x0012FF80
```

---

## Exercise 5: LEAVE

**Initial state:**

```
EBP = 0x0012FF80
ESP = 0x0012FF40
[0x0012FF80] = 0x0012FFA0  (saved EBP from caller)
[0x0012FF84] = 0x00401000  (return address)
```

**Instructions:**

```asm
leave
ret
```

**Question:** What are EBP, ESP, and EIP after execution?

**Answer:**

```
leave = mov esp, ebp; pop ebp:
  mov esp, ebp:  ESP = 0x0012FF80
  pop ebp:       EBP = [0x0012FF80] = 0x0012FFA0
                 ESP = 0x0012FF84

ret:
  EIP = [0x0012FF84] = 0x00401000
  ESP = 0x0012FF88

Final: EBP=0x0012FFA0, ESP=0x0012FF88, EIP=0x00401000
```

---

## Exercise 6: Pointer Dereference Chain

**Initial state:**

```
EAX = 0x00300000

Memory:
[0x00300000] = 0x00400000
[0x00400000] = 0x00500000
[0x00500000] = 0x41414141
```

**Instructions:**

```asm
mov eax, [eax]
mov eax, [eax]
mov eax, [eax]
```

**Question:** What is EAX after each instruction?

**Answer:**

```
After 1st mov eax, [eax]:  EAX = [0x00300000] = 0x00400000
After 2nd mov eax, [eax]:  EAX = [0x00400000] = 0x00500000
After 3rd mov eax, [eax]:  EAX = [0x00500000] = 0x41414141
```

Three-level pointer chain. This is how PEB walking works (follow pointer,
follow pointer, read value).

---

## Exercise 7: LEA vs. MOV

**Initial state:**

```
EBX = 0x0012FF80
ECX = 0x00000003

Memory:
[0x0012FF8C] = 0xDEADBEEF
```

**Instructions (independent, not sequential):**

```asm
; A:
mov eax, [ebx+ecx*4]

; B:
lea eax, [ebx+ecx*4]
```

**Question:** What is EAX after instruction A? After instruction B?

**Answer:**

```
Effective address = 0x0012FF80 + 3*4 = 0x0012FF80 + 0x0C = 0x0012FF8C

A (mov): EAX = [0x0012FF8C] = 0xDEADBEEF  (reads memory)
B (lea): EAX = 0x0012FF8C                  (computes address only)
```

---

## Exercise 8: Stack Pivot

**Initial state:**

```
EAX = 0x0C0C0C0C
ESP = 0x0012FF80

Memory (the fake ROP chain at 0x0C0C0C0C):
[0x0C0C0C0C] = 0x10015442   (pop ecx; ret)
[0x0C0C0C10] = 0x00000040   (value for ECX)
[0x0C0C0C14] = 0x10019876   (next gadget address)
```

**Instructions:**

```asm
xchg eax, esp
ret
```

**Question:** Trace the state through the pivot and the first gadget.

**Answer:**

```
xchg eax, esp:
  EAX = 0x0012FF80  (old ESP)
  ESP = 0x0C0C0C0C  (old EAX = pivot target)

ret:
  EIP = [0x0C0C0C0C] = 0x10015442
  ESP = 0x0C0C0C10

Now executing "pop ecx; ret" at 0x10015442:
  pop ecx:
    ECX = [0x0C0C0C10] = 0x00000040
    ESP = 0x0C0C0C14
  ret:
    EIP = [0x0C0C0C14] = 0x10019876
    ESP = 0x0C0C0C18

Execution continues at the next gadget with ECX = 0x40.
```

---

## Exercise 9: VirtualProtect ROP Frame

**Initial state (after ROP chain arranges the stack):**

```
ESP -> 0x7C801234    (VirtualProtect address)
+04    0x0C0C0C40    (return address = shellcode)
+08    0x0C0C0C40    (arg1: lpAddress = shellcode)
+0C    0x00000400    (arg2: dwSize = 1024)
+10    0x00000040    (arg3: flNewProtect = PAGE_EXECUTE_READWRITE)
+14    0x10004000    (arg4: lpflOldProtect = writable .data address)
```

**Instruction:** `ret` (from the preceding gadget)

**Question:** What does VirtualProtect see? Where does execution go after
VirtualProtect returns?

**Answer:**

```
ret:
  EIP = 0x7C801234  (VirtualProtect)
  ESP = old_ESP + 4  (now points at 0x0C0C0C40)

VirtualProtect sees (stdcall frame):
  [ESP+0x00] = 0x0C0C0C40  (return address)
  [ESP+0x04] = 0x0C0C0C40  (lpAddress)
  [ESP+0x08] = 0x00000400  (dwSize)
  [ESP+0x0C] = 0x00000040  (flNewProtect)
  [ESP+0x10] = 0x10004000  (lpflOldProtect)

VirtualProtect executes:
  - Changes page containing 0x0C0C0C40 to RWX
  - Writes old protection to [0x10004000]
  - Executes ret 0x10:
    EIP = 0x0C0C0C40  (shellcode)
    ESP = ESP + 4 + 0x10  (cleaned 4 args)

Execution begins at shellcode. The page is now executable.
```

---

## Exercise 10: PUSHAD

**Initial state:**

```
EAX = 0x11111111    EDI = 0x7C801234
ECX = 0x22222222    ESI = 0x0C0C0C40
EDX = 0x33333333    EBP = 0x0C0C0C40
EBX = 0x00000040    ESP = 0x0012FF80
```

**Instructions:**

```asm
pushad
ret
```

**Question:** What does the stack look like after PUSHAD? Where does RET go?

**Answer:**

```
PUSHAD pushes in order: EAX, ECX, EDX, EBX, ESP(orig), EBP, ESI, EDI
ESP decreases by 32: 0x0012FF80 - 0x20 = 0x0012FF60

Stack after PUSHAD:
[0x0012FF60] = 0x7C801234  (EDI)  <-- ESP points here
[0x0012FF64] = 0x0C0C0C40  (ESI)
[0x0012FF68] = 0x0C0C0C40  (EBP)
[0x0012FF6C] = 0x0012FF80  (original ESP)
[0x0012FF70] = 0x00000040  (EBX)
[0x0012FF74] = 0x33333333  (EDX)
[0x0012FF78] = 0x22222222  (ECX)
[0x0012FF7C] = 0x11111111  (EAX)

ret:
  EIP = [0x0012FF60] = 0x7C801234  (= EDI = VirtualProtect)
  ESP = 0x0012FF64

VirtualProtect now sees:
  [ESP+0x00] = 0x0C0C0C40  (ESI = return addr / shellcode)
  [ESP+0x04] = 0x0C0C0C40  (EBP = lpAddress)
  [ESP+0x08] = 0x0012FF80  (orig ESP = dwSize -- large enough)
  [ESP+0x0C] = 0x00000040  (EBX = flNewProtect = PAGE_EXECUTE_READWRITE)
  [ESP+0x10] = 0x33333333  (EDX = lpflOldProtect -- must be writable!)
```

Note: EDX (0x33333333) must point to writable memory or the call fails.

---

## Exercise 11: PEB Walking

**Initial state:**

```
FS:[0x30] = 0x7FFD3000  (PEB)

Memory:
[0x7FFD3000 + 0x0C] = 0x77F40000  (Ldr)
[0x77F40000 + 0x14] = 0x77F40120  (InMemoryOrderModuleList.Flink)

At the first entry (ESI = 0x77F40120):
[0x77F40120 + 0x00] = 0x77F40130  (Flink to next)
[0x77F40120 + 0x10] = 0x00400000  (DllBase of exe)

At the second entry (ESI = 0x77F40130):
[0x77F40130 + 0x00] = 0x77F40140  (Flink to next)
[0x77F40130 + 0x10] = 0x7C900000  (DllBase of ntdll.dll)

At the third entry (ESI = 0x77F40140):
[0x77F40140 + 0x00] = 0x77F40014  (Flink = list head)
[0x77F40140 + 0x10] = 0x7C800000  (DllBase of kernel32.dll)
```

**Instructions:**

```asm
xor ecx, ecx
mov eax, fs:[ecx+0x30]     ; EAX = PEB
mov eax, [eax+0x0C]         ; EAX = Ldr
mov esi, [eax+0x14]         ; ESI = first Flink
lodsd                       ; EAX = [ESI], ESI += 4  (follow Flink once)
                            ; -- but this reads the Flink, moving to entry 2
```

**Question:** After `lodsd`, what is EAX? How do you reach kernel32.dll's base?

**Answer:**

```
After lodsd:
  EAX = [0x77F40120] = 0x77F40130  (Flink to second entry)
  ESI = 0x77F40124

To reach kernel32 (third entry), follow Flink again:
  mov esi, eax           ; ESI = 0x77F40130 (second entry)
  lodsd                  ; EAX = [0x77F40130] = 0x77F40140 (third entry)

Now read DllBase:
  mov ebx, [eax+0x10]   ; EBX = [0x77F40140+0x10] = 0x7C800000 = kernel32 base
```

The InMemoryOrderLinks field is at offset +0x08 in the entry structure. Since
we entered the list through Ldr+0x14 (which points to the Links field), the
DllBase (at entry+0x18) is at [Flink+0x10] (0x18 - 0x08 = 0x10).
