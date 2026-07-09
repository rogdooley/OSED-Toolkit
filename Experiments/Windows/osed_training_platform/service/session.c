#include "service.h"

#include <string.h>

#include "osedtp_helper.h"

void service_session_init(OSEDTP_SESSION *session)
{
    if (!session) {
        return;
    }

    memset(session, 0, sizeof(*session));
}

int service_session_authenticate(OSEDTP_SESSION *session, uint32_t token, const char *client_name)
{
    char normalized[OSEDTP_SESSION_NAME_MAX];

    if (!session) {
        return -1;
    }

    if (!helper_token_accept(token)) {
        return -1;
    }

    if (client_name && helper_normalize_name(client_name, normalized, sizeof(normalized)) == 0) {
        strncpy(session->client_name, normalized, sizeof(session->client_name) - 1U);
        session->client_name[sizeof(session->client_name) - 1U] = '\0';
    } else {
        strncpy(session->client_name, "anonymous", sizeof(session->client_name) - 1U);
        session->client_name[sizeof(session->client_name) - 1U] = '\0';
    }

    session->authenticated = 1;
    session->auth_token = token;
    return 0;
}
