# ROP Worksheet #1
## VirtualProtect

## Section 1 — Goal

Objective:

> Call VirtualProtect() so the page containing my shellcode becomes executable,
> then return into my shellcode.

### Q1
What problem is DEP creating?

Answer:






### Q2
Why are we calling VirtualProtect?

Answer:






### Q3
Where should execution continue after VirtualProtect returns?

Answer:






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

Name:

Meaning:

Desired Value:

Why?

---

### Argument 2

Name:

Meaning:

Desired Value:

Why?

---

### Argument 3

Name:

Meaning:

Desired Value:

Why?

---

### Argument 4

Name:

Meaning:

Desired Value:

Why?