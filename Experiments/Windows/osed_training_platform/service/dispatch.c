#include "service.h"

#include <stdio.h>
#include <string.h>

extern int service_handle_hello(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);
extern int service_handle_auth(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);
extern int service_handle_status(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);
extern int service_handle_config(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);
extern int service_handle_diag(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);
extern int service_handle_analyze(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);

static int send_text(SOCKET client, const char *text)
{
    size_t len = strlen(text);
    return send(client, text, (int)len, 0) == SOCKET_ERROR ? -1 : 0;
}

int service_dispatch_frame(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    service_log_info("dispatch", "opcode=%s records=%u session=%u",
                     osedtp_opcode_name(frame->header.opcode),
                     (unsigned)frame->record_count,
                     (unsigned)frame->header.session_id);

    switch (frame->header.opcode) {
    case OSEDTP_OP_HELLO:
        return service_handle_hello(client, session, frame);
    case OSEDTP_OP_AUTH:
        return service_handle_auth(client, session, frame);
    case OSEDTP_OP_STATUS:
        return service_handle_status(client, session, frame);
    case OSEDTP_OP_CONFIG:
        return service_handle_config(client, session, frame);
    case OSEDTP_OP_DIAG:
        return service_handle_diag(client, session, frame);
    case OSEDTP_OP_ANALYZE:
        return service_handle_analyze(client, session, frame);
    default:
        service_log_warn("dispatch", "unsupported opcode=0x%04x", (unsigned)frame->header.opcode);
        return send_text(client, "ERR unsupported opcode\r\n");
    }
}
