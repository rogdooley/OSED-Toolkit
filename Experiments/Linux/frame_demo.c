// frame_demo.c
#include <stdio.h>

// compile: gcc -g -O0 -fno-omit-frame-pointer -no-pie frame_demo.c -o frame_demo
// use with gdb to walk through the stack/registers


__attribute__((noinline))
int add1(int x) {
    int local = x + 1;
    return local;
}

int main(void) {
    int a = 41;
    int b = add1(a);
    printf("%d\n", b);
    return 0;
}