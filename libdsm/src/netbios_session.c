/*****************************************************************************
 *  __________________    _________  _____            _____  .__         ._.
 *  \______   \______ \  /   _____/ /     \          /  _  \ |__| ____   | |
 *   |    |  _/|    |  \ \_____  \ /  \ /  \        /  /_\  \|  _/ __ \  | |
 *   |    |   \|    `   \/        /    Y    \      /    |    |  \  ___/   \|
 *   |______  /_______  /_______  \____|__  / /\   \____|__  |__|\___ |   __
 *          \/        \/        \/        \/  )/           \/        \/   \/
 *
 * This file is part of liBDSM. Copyright © 2014-2015 VideoLabs SAS
 *
 * Author: Julien 'Lta' BALLET <contact@lta.io>
 *
 * liBDSM is released under LGPLv2.1 (or later) and is also available
 * under a commercial license.
 *****************************************************************************
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <fcntl.h>
#include <errno.h>

#include "smb_defs.h"
#include "bdsm_debug.h"
#include "netbios_session.h"
#include "netbios_utils.h"

#if !defined(MSG_NOSIGNAL)
# define MSG_NOSIGNAL 0
#endif

/*
 * smbftp port, v0.6 (see libdsm-v0.6-fixes.diff):
 *   - send and receive give up after SMB_IO_TIMEOUT_SEC seconds without progress
 *     (they used to wait for ever on a stalled or half-dead server); the connect
 *     wait is unchanged. Override with -DSMB_IO_TIMEOUT_SEC=n.
 *   - a partial send() is continued instead of being treated as a failure
 *   - the receive buffer bookkeeping counted the 4-byte NetBIOS header twice, so
 *     netbios_session_packet_append() could write 4 bytes past the buffer; a failed
 *     realloc no longer frees the buffer and leaves a NULL pointer behind
 *   - a packet longer than the 17-bit NetBIOS length field is refused, not truncated
 */
#ifndef SMB_IO_TIMEOUT_SEC
# define SMB_IO_TIMEOUT_SEC 60
#endif

static int open_socket_and_connect(netbios_session *s)
{
    int pf = AF_INET;
    int type = SOCK_STREAM;
#ifdef _WIN32
    int wsa_err = 0;        /* Winsock error to report (errno is not set by Winsock) */
#endif

#ifndef _WIN32
#ifdef SOCK_NONBLOCK
    /* Linux specific */
    type |= SOCK_NONBLOCK;
#endif
    if ((s->socket = socket(pf, type, 0)) < 0)
        goto error;

#ifndef SOCK_NONBLOCK
    /* Posix */
    fcntl(s->socket, F_SETFL, fcntl(s->socket, F_GETFL, 0) | O_NONBLOCK);
#endif

#else
    /* Windows */
    if ((s->socket = socket(pf, type, 0)) < 0)
        goto error;

    ioctlsocket(s->socket, FIONBIO, &(unsigned long){ 1 });
#endif

#ifdef SO_NOSIGPIPE
    //Never generate SIGPIPE on broken write
    if (setsockopt(s->socket, SOL_SOCKET, SO_NOSIGPIPE, &(int){ 1 }, sizeof(int)))
        goto error;
#endif
    if (connect(s->socket, (struct sockaddr *)&s->remote_addr, sizeof(s->remote_addr)) <0)
    {
#ifdef _WIN32
        /* TCC port: Winsock does not set errno. A non-blocking connect that
         * is still in progress reports WSAEWOULDBLOCK through
         * WSAGetLastError(); testing errno here made every connect fail. */
        wsa_err = WSAGetLastError();
        if (wsa_err != WSAEWOULDBLOCK && wsa_err != WSAEINPROGRESS)
            goto error;
        wsa_err = 0;
#else
        if (errno != EINPROGRESS && errno != EINTR)
            goto error;
#endif

        /* Wait for connection, cf. EINPROGRESS in man connect(2) */
        while (true)
        {
            fd_set read_fds, write_fds;
#ifdef _WIN32
            fd_set except_fds;
#endif
            int nfds, ret;

            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            FD_SET(s->socket, &write_fds);
#ifdef _WIN32
            /* Winsock reports a FAILED non-blocking connect in exceptfds, not
             * writefds; without this a refused connection waited forever. */
            FD_ZERO(&except_fds);
            FD_SET(s->socket, &except_fds);
#endif
#ifdef NS_ABORT_USE_PIPE
            FD_SET(s->abort_ctx.pipe[0], &read_fds);
            nfds = (s->socket > s->abort_ctx.pipe[0] ? s->socket : s->abort_ctx.pipe[0]) + 1;
#else
            nfds = s->socket + 1;
#endif

#ifdef _WIN32
            ret = select(nfds, &read_fds, &write_fds, &except_fds, NULL);
#else
            ret = select(nfds, &read_fds, &write_fds, NULL, NULL);
#endif
            if (ret < 0)
                goto error;

#ifdef NS_ABORT_USE_PIPE
            if (FD_ISSET(s->abort_ctx.pipe[0], &read_fds))
                return DSM_ERROR_GENERIC;
#else
            if (netbios_abort_ctx_is_aborted(&s->abort_ctx))
                return DSM_ERROR_GENERIC;
#endif

#ifdef _WIN32
            if (FD_ISSET(s->socket, &write_fds) || FD_ISSET(s->socket, &except_fds))
#else
            if (FD_ISSET(s->socket, &write_fds))
#endif
            {
                if (getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &ret,
                               &(socklen_t){ sizeof (ret) }) || ret)
                {
#ifdef _WIN32
                    wsa_err = ret;
#else
                    errno = ret;
#endif
                    goto error;
                }
                break; /* Success */
            }
        }
    }
    return DSM_SUCCESS;

error:
#ifdef _WIN32
    /* Winsock errors are not in errno, so perror() would print "Success" */
    if (wsa_err == 0)
        wsa_err = WSAGetLastError();
    fprintf(stderr, "netbios_session_new, open_socket: Winsock error %d%s\n", wsa_err,
            wsa_err == 10061 ? " (connection refused)" :
            wsa_err == 10060 ? " (timed out)" :
            wsa_err == 10051 ? " (network unreachable)" :
            wsa_err == 10065 ? " (host unreachable)" : "");
#else
    BDSM_perror("netbios_session_new, open_socket: ");
#endif
    return DSM_ERROR_NETWORK;
}

/*
 * session_buffer_realloc - grow the packet buffer
 * Inputs : s = session, new_payload_size = wanted payload capacity in bytes
 *          (the 4-byte NetBIOS header is added here)
 * Outputs: 1 on success, 0 on failure (the old buffer is kept and still valid)
 * Clobbers: s->packet, s->packet_payload_size
 */
static int        session_buffer_realloc(netbios_session *s, size_t new_payload_size)
{
    void        *new_ptr;

    assert(s != NULL);

    new_ptr  = realloc(s->packet, sizeof(netbios_session_packet) + new_payload_size);
    if (new_ptr == NULL)
        return 0;
    s->packet_payload_size = new_payload_size;
    s->packet = new_ptr;
    return 1;
}

netbios_session *netbios_session_new(size_t buf_size)
{
    netbios_session   *session;
    size_t            packet_size;

    session = (netbios_session *)calloc(1, sizeof(netbios_session));
    if (!session)
        return NULL;

    if (netbios_abort_ctx_init(&session->abort_ctx) != 0)
    {
        free(session);
        return NULL;
    }

    session->packet_payload_size = buf_size;
    packet_size = sizeof(netbios_session_packet) + session->packet_payload_size;
    session->packet = (netbios_session_packet *)malloc(packet_size);
    if (!session->packet) {
        netbios_abort_ctx_destroy(&session->abort_ctx);
        free(session);
        return NULL;
    }
    session->socket = -1;

    return session;
}

void              netbios_session_disconnect(netbios_session *s)
{
    if (!s)
        return;

    if (s->socket != -1)
    {
        closesocket(s->socket);
        s->socket = -1;
    }
}

void              netbios_session_destroy(netbios_session *s)
{
    if (!s)
        return;

    free(s->packet);
    netbios_abort_ctx_destroy(&s->abort_ctx);
    free(s);
}

void              netbios_session_abort(netbios_session *s)
{
    netbios_abort_ctx_abort(&s->abort_ctx);
}

int netbios_session_connect(uint32_t ip, netbios_session *s,
                            const char *name, int direct_tcp)
{
    ssize_t                   recv_size;
    char                      *encoded_name = NULL;
    uint16_t                  ports[2];
    unsigned int              nb_ports;
    bool                      opened = false;

    assert(s != NULL && s->packet != NULL);

    if (direct_tcp)
    {
        ports[0] = htons(NETBIOS_PORT_DIRECT);
        ports[1] = htons(NETBIOS_PORT_DIRECT_SECONDARY);
        nb_ports = 2;
    }
    else
    {
        ports[0] = htons(NETBIOS_PORT_SESSION);
        nb_ports = 1;
    }
    for (unsigned int i = 0; i < nb_ports && !opened; ++i)
    {
        s->remote_addr.sin_port         = ports[i];
        s->remote_addr.sin_family       = AF_INET;
        s->remote_addr.sin_addr.s_addr  = ip;
        opened = open_socket_and_connect(s) == DSM_SUCCESS;
    }
    if (!opened)
        goto error;

    if (!direct_tcp)
    {
        // Send the Session Request message
        netbios_session_packet_init(s);
        s->packet->opcode = NETBIOS_OP_SESSION_REQ;
        encoded_name = netbios_name_encode(name, 0, NETBIOS_FILESERVER);
        if (!netbios_session_packet_append(s, encoded_name, strlen(encoded_name) + 1))
            goto error;
        free(encoded_name);
        encoded_name = netbios_name_encode("LIBDSM", 0, NETBIOS_WORKSTATION);
        if (!netbios_session_packet_append(s, encoded_name, strlen(encoded_name) + 1))
            goto error;
        free(encoded_name);
        encoded_name = NULL;

        s->state = NETBIOS_SESSION_CONNECTING;
        if (!netbios_session_packet_send(s))
            goto error;

        // Now receiving the reply from the server.
        recv_size = netbios_session_packet_recv(s, NULL);
        if (recv_size < 0)
            goto error;

        // Reply was negative, we are not connected :(
        if (s->packet->opcode != NETBIOS_OP_SESSION_REQ_OK)
        {
            s->state = NETBIOS_SESSION_REFUSED;
            return 0;
        }
    }

    // Reply was OK or DirectTCP, a session has been established
    s->state = NETBIOS_SESSION_CONNECTED;
    return 1;

error:
    free(encoded_name);
    s->state = NETBIOS_SESSION_ERROR;
    return 0;
}

void              netbios_session_packet_init(netbios_session *s)
{
    assert(s != NULL);

    s->packet_cursor  = 0;
    s->packet->flags  = 0;
    s->packet->opcode = NETBIOS_OP_SESSION_MSG;
}

int               netbios_session_packet_append(netbios_session *s,
        const char *data, size_t size)
{
    char  *start;

    assert(s && s->packet);

    if (s->packet_payload_size - s->packet_cursor < size)
        if (!session_buffer_realloc(s, size + s->packet_cursor))
            return 0;

    start = ((char *)&s->packet->payload) + s->packet_cursor;
    memcpy(start, data, size);
    s->packet_cursor += size;

    return 1;
}

/*
 * netbios_session_packet_send - send the packet being built
 * Inputs : s = connected session whose packet buffer holds a message of
 *          s->packet_cursor payload bytes
 * Outputs: number of bytes sent (header included) on success; 0 on failure,
 *          abort, timeout (SMB_IO_TIMEOUT_SEC without the socket becoming
 *          writable) or a message longer than the 17-bit length field allows
 * Clobbers: s->packet->length and ->flags
 */
int               netbios_session_packet_send(netbios_session *s)
{
    size_t          to_send, off = 0;

    assert(s && s->packet && s->socket >= 0 && s->state > 0);

    if (s->packet_cursor > 0x1FFFF)
    {
        BDSM_dbg("netbios_session_packet_send: message too long (%lu)\n",
                 (unsigned long)s->packet_cursor);
        return 0;
    }
    s->packet->length = htons(s->packet_cursor & 0xFFFF);
    s->packet->flags  = (s->packet_cursor >> 16) & 0x01;
    to_send           = sizeof(netbios_session_packet) + s->packet_cursor;

    while (off < to_send)
    {
        fd_set read_fds, write_fds;
        struct timeval tv;
        int nfds, ret;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(s->socket, &write_fds);
#ifdef NS_ABORT_USE_PIPE
        FD_SET(s->abort_ctx.pipe[0], &read_fds);
        nfds = (s->socket > s->abort_ctx.pipe[0] ? s->socket : s->abort_ctx.pipe[0]) + 1;
#else
        nfds = s->socket + 1;
#endif
        tv.tv_sec  = SMB_IO_TIMEOUT_SEC;
        tv.tv_usec = 0;

        ret = select(nfds, &read_fds, &write_fds, NULL, &tv);
        if (ret < 0)
        {
            BDSM_perror("netbios_session_packet_send: select: ");
            return 0;
        }
        if (ret == 0)
        {
            BDSM_dbg("netbios_session_packet_send: timed out\n");
            return 0;
        }

#ifdef NS_ABORT_USE_PIPE
        if (FD_ISSET(s->abort_ctx.pipe[0], &read_fds))
            return 0;
#else
        if (netbios_abort_ctx_is_aborted(&s->abort_ctx))
            return 0;
#endif

        if (FD_ISSET(s->socket, &write_fds))
        {
            ssize_t sent = send(s->socket, (char *)s->packet + off, to_send - off,
                                MSG_NOSIGNAL);

            if (sent < 0)
            {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEWOULDBLOCK)
                    continue;
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;
#endif
                BDSM_perror("netbios_session_packet_send: Unable to send packet");
                return 0;
            }
            off += (size_t)sent;        // a partial send is continued
        }
    }

    return (int)to_send;
}

/*
 * netbios_session_recv - read some bytes from the socket
 * Inputs : s = connected session, buf/len = destination
 * Outputs: bytes read (> 0); <= 0 on close, error, abort or timeout
 *          (SMB_IO_TIMEOUT_SEC without data)
 * Clobbers: *buf
 */
static ssize_t netbios_session_recv(netbios_session *s, void *buf, size_t len)
{
    while (true)
    {
        fd_set read_fds;
        struct timeval tv;
        int nfds, ret;

        FD_ZERO(&read_fds);
        FD_SET(s->socket, &read_fds);
#ifdef NS_ABORT_USE_PIPE
        FD_SET(s->abort_ctx.pipe[0], &read_fds);
        nfds = (s->socket > s->abort_ctx.pipe[0] ? s->socket : s->abort_ctx.pipe[0]) + 1;
#else
        nfds = s->socket + 1;
#endif

        tv.tv_sec  = SMB_IO_TIMEOUT_SEC;
        tv.tv_usec = 0;

        ret = select(nfds, &read_fds, NULL, NULL, &tv);
        if (ret < 0)
        {
            BDSM_perror("netbios_session_recv: select: ");
            return -1;
        }
        if (ret == 0)
        {
            BDSM_dbg("netbios_session_recv: timed out\n");
            return -1;
        }

#ifdef NS_ABORT_USE_PIPE
        if (FD_ISSET(s->abort_ctx.pipe[0], &read_fds))
            return -1;
#else
        if (netbios_abort_ctx_is_aborted(&s->abort_ctx))
            return -1;
#endif

        if (FD_ISSET(s->socket, &read_fds))
        {
            ssize_t res = recv(s->socket, buf, len, 0);

            if (res <= 0)
                BDSM_perror("netbios_session_recv: recv: ");
            return res;
        }
    }

    return -1;
}

static ssize_t    netbios_session_get_next_packet(netbios_session *s)
{
    ssize_t         res;
    size_t          total, sofar;

    assert(s != NULL && s->packet != NULL && s->socket >= 0 && s->state > 0);

    // Only get packet header and analyze it to get only needed number of bytes
    // needed for the packet. This will prevent losing a part of next packet
    total = sizeof(netbios_session_packet);
    sofar = 0;
    while (sofar < total)
    {
        res = netbios_session_recv(s, (uint8_t *)(s->packet) + sofar, total - sofar);
        if (res <= 0)
            return -1;
        sofar += res;
    }

    total  = ntohs(s->packet->length);
    total |= (s->packet->flags & 0x01) << 16;
    sofar  = 0;

    if (total > s->packet_payload_size
     && !session_buffer_realloc(s, total))
        return -1;

    //BDSM_dbg("Total = %ld, sofar = %ld\n", total, sofar);

    while (sofar < total)
    {
        res = netbios_session_recv(s, (uint8_t *)(s->packet) + sizeof(netbios_session_packet)
                                   + sofar, total - sofar);
        //BDSM_dbg("Total = %ld, sofar = %ld, res = %ld\n", total, sofar, res);

        if (res <= 0)
            return -1;
        sofar += res;
    }

    if (sofar > total)
    {
        BDSM_dbg("netbios_session_packet_recv: Packet size mismatch (%ld/%ld)\n",
                 sofar, total);
        return -1;
    }

    return sofar;
}

ssize_t           netbios_session_packet_recv(netbios_session *s, void **data)
{
    ssize_t         size;

    // ignore keepalive messages if needed
    do
    {
        size = netbios_session_get_next_packet(s);
    } while (size >= 0 && s->packet->opcode == NETBIOS_OP_SESSION_KEEPALIVE);

    if ((size >= 0) && (data != NULL))
        *data = (void *) s->packet->payload;

    return size;
}
