# ROP Worksheet #1
## VirtualProtect

## Section 1 — Goal

Objective:

> Call VirtualProtect() so the page containing my shellcode becomes executable,
> then return into my shellcode.

### Q1
What problem is DEP creating?

Answer:

The CPU has reached an instruction pointer that points into attacker-controlled data on the stack (or heap), but the page containing that data is marked non-executable. When the CPU attempts to fetch the next instruction, the processor raises an access violation instead of executing the shellcode.



### Q2
Why are we calling VirtualProtect?

Answer:

We want to change the memory region containing our shellcode to allow execution (mark that page as executable). Once marked, we can jump to the shellcode and it will execute in memory.

We use VirtualProtect because it allows our own process to change the protection attributes of one of its virtual memory pages.


### Q3
Where should execution continue after VirtualProtect returns?

Answer:

VirtualProtect returns directly into the first instruction of the shellcode.





---

## Section 2 — API

Prototype

```c
BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);
```

### Argument 1

Name: lpAddress (address)

Meaning: Address of the first byte in the memory region whose protection we want to change.

Desired Value: Address of my shellcode or ESP

Why? Because my shellcode lives there, and I need that memory region to become executable.

---

### Argument 2

Name: dwSize  (int) 

Meaning: Size of the region we want to change the attributes

Desired Value: Large enough to include my shellcode.

Why? Because Windows changes protection on that entire region.

---

### Argument 3

Name: flNewProtect (int)

Meaning: memory protection constants

Desired Value: PAGE_EXECUTE_READWRITE (0x40)

PAGE_EXECUTE 0x10, PAGE_EXECUTE_READ 0x20, PAGE_EXECUTE_READWRITE 0x40, PAGE_EXECUTE_WRITECOPY 0x80

Why?

---

### Argument 4

Name: lpflOldProtect (address)

Meaning: Pointer to writable memory where Windows can store the previous protection.

Desired Value: Address of writable memory.

Why? Windows writes the previous protection to this location.