// Win32/x86 training binary: deterministic crash via unsafe stack copy.
// Build (x86):
//   cl /nologo /W3 /Od /Zi /MT vuln_strcpy.c /link /OUT:vuln_strcpy_x86.exe
//
// Notes:
// - This is intentionally unsafe. Use only in your authorized lab VM.
// - The goal is crash analysis and debugger workflow, not weaponization.

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

__declspec(noinline) void vuln_copy(const char *user)
{
    // Keep the buffer size stable across builds.
    char buf[128];

    // Deliberately unsafe.
    strcpy(buf, user);

    // Prevent optimizing away the buffer.
    if (buf[0] == 'Z') {
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

