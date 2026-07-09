#include "service.h"

#include <string.h>

int service_config_load(OSEDTP_SERVICE_CONFIG *cfg)
{
    if (!cfg) {
        return -1;
    }

    cfg->bind_ip = OSEDTP_DEFAULT_BIND_IP;
    cfg->bind_port = OSEDTP_DEFAULT_BIND_PORT;
    cfg->service_name = "osedtp_service";
    cfg->auth_token = 0xC0FFEE11u;
    return 0;
}
