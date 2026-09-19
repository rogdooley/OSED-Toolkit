#include "lab_io.h"

#include <stdio.h>

static unsigned int authorization_gate = 0;

__declspec(noinline) static void vulnerable_print(const char *format)
{
    printf(format,
        0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
        0x55555555u, &authorization_gate, 0x77777777u, 0x88888888u);
    putchar('\n');
}

int main(int argc, char **argv)
{
    char format[256];

    puts("FMT-03: controlled write");
    _set_printf_count_output(1);
    if (!read_format_string(argc, argv, format, sizeof(format))) {
        return 1;
    }
    vulnerable_print(format);

    printf("[state] authorization_gate = 0x%08X\n", authorization_gate);
    if (authorization_gate == 0x00000040u) {
        puts("[success] Gate value accepted.");
        return 0;
    }
    puts("[retry] Required value: 0x00000040");
    return 2;
}
