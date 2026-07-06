// frame_demo.c  —  Windows x86 stack-frame walkthrough target
//
// Build (x86 Developer Command Prompt, no optimisations, debug info):
//   cl /nologo /Od /Zi /MT /Gs frame_demo.c /link /OUT:frame_demo.exe
//
// Load in WinDbg:  .sympath+ <pdb dir>  then  bu frame_demo!add1
// Load in IDA:     open frame_demo.exe, press F5 on add1 for pseudocode

#include <stdio.h>

__declspec(noinline)
int add1(int x)
{
    int local = x + 1;
    return local;
}

__declspec(noinline)
int double_add(int x)
{
    int a = add1(x);
    int b = add1(a);
    return b;
}

int main(void)
{
    int val  = 41;
    int result = double_add(val);
    printf("%d\n", result);
    return 0;
}
