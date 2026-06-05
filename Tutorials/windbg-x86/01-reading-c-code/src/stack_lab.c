// Win32/x86 stack-layout lab target.
// Nothing dangerous — designed to produce predictable, readable stack frames.
//
// Build (x86, Developer Command Prompt):
//   cl /nologo /Od /Zi /MT /W3 stack_lab.c /link /OUT:stack_lab_x86.exe
//
// Pass any string argument.  Example:
//   stack_lab_x86.exe HelloWorld

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

// Returned by process_buffer; contains a summary of what was found.
typedef struct {
    int  length;
    char first_char;
    char last_char;
    int  checksum;
} BufferStats;

// Compute a simple byte-sum checksum.
__declspec(noinline) int compute_checksum(const char *buf, int len)
{
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += (unsigned char)buf[i];
    }
    return sum;
}

// Fill a local buffer with a transformed copy of the input,
// then return stats about the result.
__declspec(noinline) BufferStats process_buffer(const char *input)
{
    char local_copy[128];
    int  len;
    BufferStats stats;

    // Safe bounded copy.
    strncpy(local_copy, input, sizeof(local_copy) - 1);
    local_copy[sizeof(local_copy) - 1] = '\0';

    len = (int)strlen(local_copy);

    // XOR each byte with 0x20 (toggles ASCII letter case).
    for (int i = 0; i < len; i++) {
        local_copy[i] ^= 0x20;
    }

    stats.length     = len;
    stats.first_char = (len > 0) ? local_copy[0]       : '\0';
    stats.last_char  = (len > 0) ? local_copy[len - 1] : '\0';
    stats.checksum   = compute_checksum(local_copy, len);

    return stats;
}

// Wrapper that allocates a pointer-sized slot on the stack, passes it down,
// then prints the result.  Demonstrates pointer arguments.
__declspec(noinline) void run_and_print(const char *input)
{
    BufferStats result;
    result = process_buffer(input);

    printf("length    = %d\n", result.length);
    printf("first     = 0x%02x ('%c')\n", (unsigned char)result.first_char, result.first_char);
    printf("last      = 0x%02x ('%c')\n", (unsigned char)result.last_char,  result.last_char);
    printf("checksum  = 0x%x\n", result.checksum);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return 1;
    }

    run_and_print(argv[1]);
    return 0;
}
