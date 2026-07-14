/*
 * net.c - framing helpers: read a header, validate it, read a body, send
 * responses. Nothing attacker-controlled is copied unsafely here; this layer
 * only bounds body_len against VULNSVC_MAX_BODY. The unsafe copy happens later
 * in a parser, which is exactly the point: recv is not the bug.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "service.h"
#include "protocol.h"

int net_recv_all(SOCKET s, void *buf, int len)
{
    int got = 0;
    char *p = (char *)buf;
    while (got < len) {
        int n = recv(s, p + got, len - got, 0);
        if (n <= 0)
            return -1;
        got += n;
    }
    return got;
}

int net_send_all(SOCKET s, const void *buf, int len)
{
    int sent = 0;
    const char *p = (const char *)buf;
    while (sent < len) {
        int n = send(s, p + sent, len - sent, 0);
        if (n == SOCKET_ERROR)
            return -1;
        sent += n;
    }
    return sent;
}

int net_read_header(Client *c, PACKET_HEADER *hdr)
{
    if (net_recv_all(c->sock, hdr, VULNSVC_HEADER_SIZE) != VULNSVC_HEADER_SIZE)
        return -1;

    if (hdr->magic != VULNSVC_MAGIC) {
        log_msg("WARN", "bad magic %08lx", (unsigned long)hdr->magic);
        return -1;
    }
    if (hdr->body_len > VULNSVC_MAX_BODY) {
        /* Note: this bounds the *transport*, not the parser. body_len can be
         * up to 8 KiB, far larger than any single stack buffer downstream. */
        log_msg("WARN", "oversized body_len %lu", (unsigned long)hdr->body_len);
        send_status(c, ST_TOO_LARGE, "body too large");
        return -1;
    }
    c->bytes_in += VULNSVC_HEADER_SIZE;
    return 0;
}

int net_read_body(Client *c, const PACKET_HEADER *hdr, uint8_t *body)
{
    if (hdr->body_len == 0) {
        body[0] = '\0';
        return 0;
    }
    if (net_recv_all(c->sock, body, (int)hdr->body_len) != (int)hdr->body_len)
        return -1;

    /* Ensure C-string safety at the framing layer. The parser will still treat
     * the body as a NUL-terminated string; embedded NULs therefore truncate,
     * which is why 0x00 is a bad character for the eventual exploit. */
    body[hdr->body_len] = '\0';
    c->bytes_in += hdr->body_len;
    return 0;
}

int send_status(Client *c, uint16_t status, const char *msg)
{
    /* Response frame: [status u16][len u16][msg]. */
    uint8_t out[512];
    uint16_t mlen = msg ? (uint16_t)strlen(msg) : 0;
    if (mlen > sizeof(out) - 4)
        mlen = sizeof(out) - 4;

    memcpy(out + 0, &status, 2);
    memcpy(out + 2, &mlen, 2);
    if (mlen)
        memcpy(out + 4, msg, mlen);

    c->bytes_out += (uint32_t)(4 + mlen);
    return net_send_all(c->sock, out, 4 + mlen);
}

int send_error(Client *c, const char *msg)
{
    return send_status(c, ST_BAD_REQUEST, msg);
}
