#include "service.h"

#include <stdio.h>
#include <string.h>

#include "gadgetlib.h"
#include "osedtp_helper.h"

static int send_text(SOCKET client, const char *text)
{
    size_t len = strlen(text);
    return send(client, text, (int)len, 0) == SOCKET_ERROR ? -1 : 0;
}

static int require_auth(SOCKET client, const OSEDTP_SESSION *session)
{
    if (!session || !session->authenticated) {
        send_text(client, "ERR auth required\r\n");
        return -1;
    }

    return 0;
}

static const OSEDTP_RECORD_VIEW *find_record(const OSEDTP_PARSED_FRAME *frame, uint16_t type)
{
    return osedtp_find_record(frame, type);
}

int service_handle_hello(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    const OSEDTP_RECORD_VIEW *client_rec = find_record(frame, OSEDTP_RECORD_CLIENT);
    char client_name[OSEDTP_SESSION_NAME_MAX];
    char reply[160];

    (void)session;

    if (!client_rec) {
        return send_text(client, "ERR missing client record\r\n");
    }

    if (osedtp_copy_text(client_rec->body,
                         client_rec->header.length,
                         client_name,
                         sizeof(client_name)) != 0) {
        return send_text(client, "ERR bad client record\r\n");
    }

    snprintf(reply, sizeof(reply), "HELLO %s\r\n", client_name);
    return send_text(client, reply);
}

int service_handle_auth(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    const OSEDTP_RECORD_VIEW *client_rec = find_record(frame, OSEDTP_RECORD_CLIENT);
    const OSEDTP_RECORD_VIEW *auth_rec = find_record(frame, OSEDTP_RECORD_AUTH);
    char client_name[OSEDTP_SESSION_NAME_MAX];
    uint32_t token;

    if (!client_rec || !auth_rec || auth_rec->header.length < sizeof(uint32_t)) {
        return send_text(client, "ERR malformed auth packet\r\n");
    }

    if (osedtp_copy_text(client_rec->body,
                         client_rec->header.length,
                         client_name,
                         sizeof(client_name)) != 0) {
        return send_text(client, "ERR bad client record\r\n");
    }

    memcpy(&token, auth_rec->body, sizeof(token));
    if (service_session_authenticate(session, token, client_name) != 0) {
        service_log_warn("auth", "rejected client='%s' token=0x%08x", client_name, (unsigned)token);
        return send_text(client, "ERR auth failed\r\n");
    }

    service_log_info("auth", "accepted client='%s'", session->client_name);
    return send_text(client, "AUTH OK\r\n");
}

int service_handle_status(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    char response[160];
    const OSEDTP_RECORD_VIEW *cmd_rec = find_record(frame, OSEDTP_RECORD_COMMAND);
    char command[64];

    if (require_auth(client, session) != 0) {
        return -1;
    }

    if (cmd_rec && osedtp_copy_text(cmd_rec->body,
                                    cmd_rec->header.length,
                                    command,
                                    sizeof(command)) == 0) {
        service_log_info("status", "command='%s'", command);
    }

    snprintf(response, sizeof(response),
             "STATUS OK client=%s requests=%u\r\n",
             session->client_name,
             (unsigned)session->request_count);
    return send_text(client, response);
}

int service_handle_config(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    const OSEDTP_RECORD_VIEW *cfg_rec = find_record(frame, OSEDTP_RECORD_CONFIG);
    char config_note[96];
    char response[192];

    if (require_auth(client, session) != 0) {
        return -1;
    }

    if (!cfg_rec || osedtp_copy_text(cfg_rec->body,
                                     cfg_rec->header.length,
                                     config_note,
                                     sizeof(config_note)) != 0) {
        return send_text(client, "ERR malformed config packet\r\n");
    }

    snprintf(response, sizeof(response),
             "CONFIG OK note=%s helper=%p\r\n",
             config_note,
             helper_get_anchor());
    return send_text(client, response);
}

int service_handle_diag(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    const OSEDTP_RECORD_VIEW *diag_rec = find_record(frame, OSEDTP_RECORD_DIAG);
    const OSEDTP_RECORD_VIEW *cmd_rec = find_record(frame, OSEDTP_RECORD_COMMAND);
    char diag_text[160];
    char cmd_text[64];
    uint32_t score;
    char response[192];

    if (require_auth(client, session) != 0) {
        return -1;
    }

    if (!diag_rec || osedtp_copy_text(diag_rec->body,
                                      diag_rec->header.length,
                                      diag_text,
                                      sizeof(diag_text)) != 0) {
        return send_text(client, "ERR malformed diag packet\r\n");
    }

    if (cmd_rec) {
        if (osedtp_copy_text(cmd_rec->body,
                             cmd_rec->header.length,
                             cmd_text,
                             sizeof(cmd_text)) == 0) {
            service_log_info("diag", "command='%s'", cmd_text);
        }
    }

    score = gadgetlib_score_buffer((const unsigned char *)diag_text, strlen(diag_text));
    snprintf(response, sizeof(response),
             "DIAG OK score=%08x fold=%d\r\n",
             (unsigned)score,
             gadgetlib_fold_flags(frame->header.flags));
    return send_text(client, response);
}

int service_handle_analyze(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame)
{
    const OSEDTP_RECORD_VIEW *client_rec = find_record(frame, OSEDTP_RECORD_CLIENT);
    const OSEDTP_RECORD_VIEW *cmd_rec = find_record(frame, OSEDTP_RECORD_COMMAND);
    char client_name[OSEDTP_SESSION_NAME_MAX];
    char command[96];
    int layout_score;

    if (require_auth(client, session) != 0) {
        return -1;
    }

    if (!client_rec || !cmd_rec) {
        return send_text(client, "ERR analyze requires client and command records\r\n");
    }

    if (osedtp_copy_text(client_rec->body,
                         client_rec->header.length,
                         client_name,
                         sizeof(client_name)) != 0) {
        return send_text(client, "ERR bad client record\r\n");
    }

    if (osedtp_copy_text(cmd_rec->body,
                         cmd_rec->header.length,
                         command,
                         sizeof(command)) != 0) {
        return send_text(client, "ERR bad command record\r\n");
    }

    layout_score = gadgetlib_probe_layout((uint32_t)frame->header.opcode, frame->header.total_length);
    service_log_info("analyze", "client='%s' command='%s' layout=%d", client_name, command, layout_score);
    return send_text(client, "ANALYZE OK\r\n");
}
