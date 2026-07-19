# How VirtualProtect() Is Normally Called

#### Learning Objective

By the end of this worksheet you should be able to answer:

“If I were the compiler, what would the stack look like immediately before and immediately after calling VirtualProtect()?”

Once you can answer that, ROP becomes:

“How do I recreate that same stack without executing the compiler’s code?”

## Part 1 C Code

Assume this:

```c
void foo()
{
    DWORD oldProtect;

    VirtualProtect(
        shellcode,
        0x400,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    shellcode();
}
```

## Part 2 Compiler Thinking

Question 1:

What four values must be passed to VirtualProtect?

```text

Argument 1 (lpAddress)

Value: that doesn't make any sense here because shellcode isn't declared and isn't an argument of foo. You don't even know what shellcode is at this point and the compiler certainly doesn't.

Reason: 


----------------------------------------

Argument 2 (dwSize)

Value: 0x400

Reason: If shellcode was actually something (an address/pointer), which it's not because I don't see a declaration nor do I see it as an argument of foo(), this would be the amount of bytes in the page where shellcode occupies that we will change it's protection attributes.


----------------------------------------

Argument 3 (flNewProtect)

Value: PAGE_EXECUTE_READWRITE

Reason: Memory protection options we want to invoke for that section of memory containing our shellcode in order for the shellcode to execute


----------------------------------------

Argument 4 (lpflOldProtect)

Value: &oldProtect

Reason: Windows writes the previous protection to this location.

```

## Part 3 The Pushes

```asm
push &oldProtect
push flNewProtect
push 0x400
push shellcode
call VirtualProtect
```

Immediately before the CALL executes

```txt

        Higher Addresses
        +----------------------+
        |                      |
        |                      |
        +----------------------+

ESP --> |   shellcode address  |
        +----------------------+
        |   0x400              |
        +----------------------+
        |   0x40               |  (PAGE_EXECUTE_READWRITE)
        +----------------------+
        |   &oldProtect        |
        +----------------------+

        Lower Addresses

```

## Now execute `call VirtualProtect`

As long as the stack contains the correct values in the locations defined by the calling convention, the function executes normally.



“How do I build a ROP chain?”

I want you to replace that question forever with:

“What machine state must exist when execution reaches this function?”

That’s what exploit developers actually ask.


## What does RET actually Do?

```asm
foo:
ret
```

```text
Before RET

EIP = foo
ESP -> return address

----------------------------

After RET

EIP = DWORD PTR [old esp] ...[ESP]
ESP -> old esp + 4 ... ESP+4
```

### The Thought Experiment

```text
ESP ---> VirtualProtect
         ReturnToShellcode
         ShellcodeAddress
         0x400
         0x40
         WritableAddress
```
Now execute `ret`

What happens to 
    - EIP
    - ESP

`ret` pops the next dword from the stack into EIP
    - moment ret is called
        - EIP -> VirtualProtect
        - ESP -> ReturnToShellcode

```text
EIP ---> VirtualProtect

ESP ---> ReturnToShellcode
         ShellcodeAddress
         0x400
         0x40
         WritableAddress
```

A RET instruction is effectively a programmable indirect jump:
```asm
jmp [esp]
```
with one extra side effect:
```asm
esp += 4
```

A gadget is nothing more than a state transformer.

You start with one machine state:

```
EAX = ?
ESP -> 0x12345678
       VirtualProtect
       ...
```

You end with another:

```
EAX = 0x12345678
EIP = VirtualProtect
ESP -> ReturnToShellcode
       ...
```

ROP is simply composing these little state transformations.

⸻

Here’s where real ROP differs

In practice, you usually don’t want to jump directly to VirtualProtect after the first gadget.

Instead, you might need to initialize several registers first.

Suppose your chain is:

POP EAX
RET
POP ECX
RET
POP EDX
RET
VirtualProtect

Your stack might look like:

ESP ---> ValueForEAX
         AddressOf(POP ECX; RET)
         ValueForECX
         AddressOf(POP EDX; RET)
         ValueForEDX
         AddressOf(VirtualProtect)
         ReturnToShellcode
         ShellcodeAddress
         0x400
         0x40
         WritableAddress

Now watch the execution:

1. POP EAX; RET
    * EAX = ValueForEAX
    * RET jumps to POP ECX; RET
2. POP ECX; RET
    * ECX = ValueForECX
    * RET jumps to POP EDX; RET
3. POP EDX; RET
    * EDX = ValueForEDX
    * RET jumps to VirtualProtect

Every gadget advances ESP and leaves the machine in a new state.

⸻

The key insight

Earlier you said something that I think is now even clearer:

“As long as the stack has the correct values at the addresses it will use as its arguments, then the function will execute.”

Extend that one step:

As long as every RET finds the address of the next gadget on the stack, the entire chain executes.

The stack has become both:

* the control-flow graph (where execution goes next), and
* the data source (arguments, register values, return addresses).

That’s why exploit developers spend so much time drawing the stack. It isn’t just where arguments live anymore—it’s effectively your “program.”

One small exercise

Let’s add one more gadget:

POP EAX
RET
POP ECX
RET

Suppose the stack starts as:

ESP ---> 0x11111111
         POP ECX; RET
         0x22222222
         VirtualProtect
         ReturnToShellcode
         ShellcodeAddress
         0x400
         0x40
         WritableAddress

Without skipping steps, tell me the values of EAX, ECX, EIP, and ESP after both gadgets have executed, just before VirtualProtect begins. This is the point where ROP execution usually “clicks.”

```text
POP EAX: EAX -> 0x11111111
POP ECX; RET -> EIP

POP ECX; RET: ECX -> 0x22222222 
VirtualProtect -> EIP

(EAX ->  0x11111111, ECX -> 0x22222222, EIP-> VirtualProect, ESP->ReturnToShellcode )

```

## PUSHAD

```asm
PUSHAD
```

pushes:

```asm
EAX
ECX
EDX
EBX
(original ESP)
EBP
ESI
EDI
```

Example Machine state:

```text
EAX = 0x11111111
ECX = 0x22222222
EDX = 0x33333333
EBX = 0x44444444

ESP = 0x0012FF00

EBP = 0x55555555
ESI = 0x66666666
EDI = 0x77777777
```

After `PUSHAD` what does the stack look like:

```text
ESP ----> 0x77777777
0x66666666
0x55555555
0x0012FF00
0x44444444
0x33333333
0x22222222
0x11111111

```

Suppose immediately after PUSHAD we execute:

ret

Where does execution go?

Remember:

ret
EIP = [ESP]
ESP += 4

What is [ESP] right now?

Your answer should be immediate.

⸻

This is where exploit writers get clever

Look at the stack again.

ESP ---> EDI
        ESI
        EBP
        Original ESP
        EBX
        EDX
        ECX
        EAX

Does that layout remind you of anything?

Not yet?

Let’s compare it with something you already know.

⸻

A normal function call

After:

push arg4
push arg3
push arg2
push arg1
call VirtualProtect

VirtualProtect sees:

ESP ---> Return Address
        lpAddress
        dwSize
        flNewProtect
        lpflOldProtect

Now imagine we could arrange the registers like this:

Register	Value
EDI	Address of RET gadget
ESI	Address of VirtualProtect
EBP	Return-to-shellcode helper
EBX	0x400
EDX	0x40
ECX	Writable pointer
EAX	Scratch or NOP value

Then execute:

pushad
ret

Now ask yourself:

What is the very first thing RET pops?

It pops EDI.

That means EDI isn’t just a register anymore.

It becomes the next instruction pointer.

This is why many exploit chains end by loading registers and then executing PUSHAD.

They are converting register state into a carefully crafted stack frame.

⸻

This is the conceptual leap

Stack  → Function

With PUSHAD, you’re doing:

Registers
      │
      ▼
PUSHAD
      │
      ▼
Stack
      │
      ▼
RET
      │
      ▼
Function

You’re synthesizing the stack frame from register values.

⸻

Mini exercise

Let’s use the same register values.

EDI = 0x77777777
ESI = 0x66666666
...

After:

pushad
ret

Tell me:

* What is EIP?
* What does ESP point to?


## To Construct

```txt
Address       Meaning
-----------   ---------------------------------
SKELETON+00   VirtualAlloc address
SKELETON+04   Return address → shellcode
SKELETON+08   lpAddress      → shellcode
SKELETON+0C   dwSize         → 0x00000001
SKELETON+10   flAllocationType → 0x00001000
SKELETON+14   flProtect      → 0x00000040
```

```txt
ESP ---> VirtualAlloc
         ShellcodeAddress       ; return address
         ShellcodeAddress       ; lpAddress
         0x00000001             ; dwSize
         0x00001000             ; MEM_COMMIT
         0x00000040             ; PAGE_EXECUTE_READWRITE
```


#### Phases of the chain:

```txt
Phase 1: Acquire a stack reference
         ESI = original ESP

Phase 2: Find skeleton[0]
         ESI = address of VirtualAlloc placeholder

Phase 3: Patch six fields
         [ESI+00] = VirtualAlloc
         [ESI+04] = shellcode
         [ESI+08] = shellcode
         [ESI+0C] = 1
         [ESI+10] = 0x1000
         [ESI+14] = 0x40

Phase 4: Calculate address before skeleton
         EBP = skeleton - 4

Phase 5: Pivot
         ESP = EBP
         POP EBP
         RET → VirtualAlloc
```



### push eax; ret

```asm
push eax
ret
```

Execution jumps to whatever address is in EAX