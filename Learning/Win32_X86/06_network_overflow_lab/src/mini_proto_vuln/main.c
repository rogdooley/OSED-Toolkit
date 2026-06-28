#include "mini_proto_vuln.h"

#include <stdio.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    return start_server();
}
