// Win32/x86 training binary: crash via unsafe stack copy from file contents.
//
// Why this exists:
// - argv-based inputs are annoying for certain bytes and very long payloads.
// - file-driven targets are closer to common parsing bugs you'll see later.
//
// Build (x86):
//   cl /nologo /W3 /Od /Zi /MT vuln_file_read.c /link /OUT:vuln_file_read_x86.exe
//
// Run:
//   vuln_file_read_x86.exe payload.bin
//
// This is intentionally unsafe. Use only in your authorized lab VM.

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_all(const char *path, unsigned char **out_buf, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return 0;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }

    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 0;
    }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (n != (size_t)sz) {
        free(buf);
        return 0;
    }

    *out_buf = buf;
    *out_len = n;
    return 1;
}

__declspec(noinline) void vuln_copy_bytes(const unsigned char *data, size_t len)
{
    // Stack buffer. We'll overflow it by copying len bytes unconditionally.
    unsigned char buf[128];

    // Deliberately unsafe: no bounds checking.
    memcpy(buf, data, len);

    // Keep stable.
    if (buf[0] == 0x7f) {
        puts("unlikely");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <payload_file>\n", argv[0]);
        return 1;
    }

    unsigned char *data = NULL;
    size_t len = 0;
    if (!read_all(argv[1], &data, &len)) {
        puts("failed to read input file");
        return 1;
    }

    vuln_copy_bytes(data, len);
    free(data);
    puts("done");
    return 0;
}

