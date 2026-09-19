#include "lab_io.h"

#include <stdio.h>

typedef void (__cdecl *action_fn)(void);

static void normal_action(void)
{
    puts("[state] Normal action executed.");
}

static void proof_action(void)
{
    puts("[success] Controlled function pointer reached the benign proof action.");
}

static action_fn selected_action = normal_action;

__declspec(noinline) static void vulnerable_print(const char *format)
{
    printf(format,
        0x11111111u, 0x22222222u, 0x33333333u, &selected_action,
        0x55555555u, 0x66666666u, 0x77777777u, 0x88888888u);
    putchar('\n');
}

int main(int argc, char **argv)
{
    char format[256];

    puts("FMT-04: function-pointer overwrite");
    _set_printf_count_output(1);
    if (!read_format_string(argc, argv, format, sizeof(format))) {
        return 1;
    }
    vulnerable_print(format);
    selected_action();
    return 0;
}
