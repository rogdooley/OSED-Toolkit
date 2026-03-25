// Mitigation observation target (Win32/x86).
// Build this file with different compiler/linker flags as described in:
//   lessons/win32_x86/05_mitigations/README.md
//
// This is intentionally unsafe and designed only for an authorized lab VM.

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

__declspec(noinline) void vuln_copy(const char *user)
{
    // Keep this stable; your observations come from changing build flags, not source.
    char buf[160];

    // Deliberately unsafe (classic stack overflow primitive).
    strcpy(buf, user);

    // Touch the buffer to reduce optimization variance.
    if (buf[0] == 'Q') {
        puts("unlikely");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    vuln_copy(argv[1]);
    puts("done");
    return 0;
}

