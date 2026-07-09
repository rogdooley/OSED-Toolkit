#include "service.h"

#include <stdio.h>
#include <string.h>

#include "gadgetlib.h"
#include "osedtp_helper.h"

int main(void)
{
    OSEDTP_SERVICE_CONFIG cfg;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (service_config_load(&cfg) != 0) {
        return 1;
    }

    printf("[boot] helper=%p gadgetlib=%p checksum=%08x probe=%d\n",
           helper_get_anchor(),
           gadgetlib_get_anchor(),
           (unsigned)helper_checksum32((const unsigned char *)cfg.service_name, strlen(cfg.service_name)),
           helper_probe(7));

    return service_run(&cfg) == 0 ? 0 : 1;
}
