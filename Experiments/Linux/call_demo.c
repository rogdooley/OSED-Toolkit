// call_demo.c
#include <stdio.h>

__attribute__((noinline))
int add1(int x) {
    return x + 1;
}

int main(void) {
    int a = 41;
    int b = add1(a);
    printf("%d\n", b);
    return 0;
}