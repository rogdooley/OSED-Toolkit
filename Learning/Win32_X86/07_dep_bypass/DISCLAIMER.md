# Disclaimer & Safe-Use Notice

**Independent educational material.** VulnSvc is an original, self-contained lab
written to teach classic 32-bit Windows stack-overflow and DEP-bypass techniques.
It is not affiliated with, derived from, or endorsed by any commercial training
course, certification, or vendor. All source code, the vulnerable service, the
companion DLLs, the walkthrough, and the exploit scaffold are original works
released under the MIT License (see `LICENSE`).

**The techniques are public knowledge.** Return-oriented programming, DEP
bypass, and IAT-based API resolution are widely documented, decades-old methods.
This lab teaches them with a purpose-built target and its own addresses; it
reproduces no third party's proprietary case study, exploit code, or text.

**Intentionally vulnerable — lab use only.**

- `service.exe` contains a deliberate, unauthenticated-reachable memory-safety
  bug. **Never run it on a production system or any network you do not fully
  control.** Use a disposable, isolated virtual machine.
- The exploit code is provided solely for learning exploit development against
  *this* target. Do not use these techniques against systems you do not own or
  lack explicit written authorization to test. Unauthorized access to computer
  systems is illegal in most jurisdictions.

**No warranty.** Provided "as is" without warranty of any kind. The authors
accept no liability for any use or misuse of this material.

By building, running, or distributing this project you agree to use it only for
lawful, authorized, educational purposes.
