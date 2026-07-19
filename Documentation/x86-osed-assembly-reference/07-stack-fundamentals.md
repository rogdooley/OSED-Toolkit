# 7. Stack Fundamentals

## Growth Direction

The x86 stack grows toward **lower** addresses. `push` decrements ESP; `pop`
increments ESP. "Top of stack" means the lowest address currently in use.

## Stack Reserve vs. Stack Commit

When a thread is created, Windows **reserves** a large contiguous virtual
address range for its stack (default 1 MB) but only **commits** a small portion
(typically one or a few pages). As the stack grows, guard pages trigger
automatic commit of additional pages. The full reserved range is NOT physically
backed at creation time.

Active stack frames are created dynamically as functions are called and
destroyed as they return. The total number of functions in the executable does
not determine stack size -- only the depth of the call chain at any moment.

## State Transitions

### PUSH

```
Before:                After push 0x41414141:

ESP = 0x1000           ESP = 0x0FFC
                       [0x0FFC] = 0x41414141
[0x1000] = ????        [0x1000] = ????

Rule: ESP = ESP - 4; [ESP] = operand
```

### POP

```
Before:                After pop eax:

ESP = 0x0FFC           ESP = 0x1000
[0x0FFC] = 0x41414141  EAX = 0x41414141

Rule: dst = [ESP]; ESP = ESP + 4
```

### CALL

```
Before:                After call 0x00401000:

EIP = 0x004010A0       EIP = 0x00401000
ESP = 0x1000           ESP = 0x0FFC
                       [0x0FFC] = 0x004010A5  (address after CALL)

Rule: ESP -= 4; [ESP] = EIP_next; EIP = target
```

### RET

```
Before:                After ret:

EIP = (address of ret) EIP = 0x004010A5  (= value popped from stack)
ESP = 0x0FFC           ESP = 0x1000
[0x0FFC] = 0x004010A5

Rule: EIP = [ESP]; ESP = ESP + 4
```

### RET N (e.g., ret 0x10)

```
Before:                After ret 0x10:

ESP = 0x0FFC           EIP = [0x0FFC]  (return address)
[0x0FFC] = retaddr     ESP = 0x0FFC + 4 + 0x10 = 0x1010

Rule: EIP = [ESP]; ESP = ESP + 4 + N
```

The N bytes cleaned are the callee's arguments (stdcall convention).

### SUB ESP, N

```
Before:                After sub esp, 0x40:

ESP = 0x1000           ESP = 0x0FC0

Rule: ESP = ESP - N  (allocate N bytes of local space)
```

### ADD ESP, N

```
Before:                After add esp, 0x40:

ESP = 0x0FC0           ESP = 0x1000

Rule: ESP = ESP + N  (deallocate/clean up stack space)
```

## Guard Pages

The page immediately below the committed portion of the stack is a guard page.
Writing to it triggers a `STATUS_GUARD_PAGE_VIOLATION` exception, which the
kernel handles by committing that page and placing a new guard below it.
Functions with large local allocations (> 4096 bytes) call `__chkstk` to
probe each page in order, ensuring guard pages are triggered sequentially.
