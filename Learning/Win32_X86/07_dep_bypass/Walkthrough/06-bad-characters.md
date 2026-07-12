## 6. Bad characters

The overflow flows through `sscanf("... %s", value)`. `%s` terminates on
whitespace or NUL, so those bytes cannot appear anywhere in your payload —
including inside gadget addresses.

Derive the set from the conversion, not by rote:

```
0x00  NUL          terminates the C string / %s
0x09  \t  tab      whitespace → ends the %s token
0x0a  \n  LF        whitespace
0x0b  \v  VT        whitespace
0x0c  \f  FF        whitespace
0x0d  \r  CR        whitespace
0x20  ' ' space     whitespace → ends the %s token
```

Bad-char set: **`00 09 0a 0b 0c 0d 20`**.

Confirm empirically: send `set name ` + a byte array `\x01\x02...\xff` (omitting
`0x00`), then inspect the landed bytes in memory (`db`) and see where the string
got truncated or mangled. Every byte that fails to appear intact is bad.

> **Design decision.** Bad chars constrain *two* things: the shellcode (handle
> with `msfvenom -b`) **and every gadget address**. When you picked
> `compression.dll` in Chapter 3, "addresses free of `00/0a/0d/20`" was one of
> the scoring criteria — this is why. A gadget at `0x6150200a` is unusable
> (`0x0a`); you would pick a different gadget for that primitive.

---

---

[← Previous](05-controlling-eip.md) · [Index](00-index.md) · [Next →](07-proving-dep.md)
