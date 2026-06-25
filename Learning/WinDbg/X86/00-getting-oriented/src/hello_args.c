// Win32/x86 orientation target.
// Does nothing dangerous — just prints args and returns.
//
// Build (x86, Developer Command Prompt):
//   cl /nologo /Od /Zi /MT /W3 hello_args.c /link /OUT:hello_args_x86.exe
//
// Usage:
//   hello_args_x86.exe foo bar baz

#include <stdio.h>

__declspec(noinline) int add_numbers(int a, int b)
{
    int result = a + b;
    return result;
}

__declspec(noinline) void print_arg(int index, const char *arg)
{
    char local_buf[64];
    int sum = add_numbers(index, (int)arg[0]);

    // _snprintf_s is safe; this is just a debug helper.
    _snprintf_s(local_buf, sizeof(local_buf), _TRUNCATE, "  arg[%d] = \"%s\" (sum=%d)", index, arg, sum);
    puts(local_buf);
}

int main(int argc, char **argv)
{
    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        print_arg(i, argv[i]);
    }
    puts("done");
    return 0;
}
