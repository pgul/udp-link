#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include "udp-link.h"

int send_msg(int msgtype, ...)
{
    va_list ap;
    char sendbuf[MTU];
    int datalen=0;
    uint32_t magic = htonl(key + msgtype);
    uint32_t nonce = 0; // todo: generate unique nonce
    uint16_t seq;
    int len;
    unsigned char reason;

    if (remote_addr.sin_addr.s_addr == 0)
    {
        syslog(LOG_ERR, "Remote address is not set");
        return -1;
    }
    // todo: encrypt magic with nonce
    memcpy(sendbuf, &magic, sizeof(magic));
    datalen += sizeof(magic);
    memcpy(sendbuf + datalen, &nonce, sizeof(nonce));
    datalen += sizeof(nonce);
    va_start(ap, msgtype);
    switch (msgtype) {
        case MSGTYPE_INIT:
            break;
        case MSGTYPE_INIT2:
            break;
        case MSGTYPE_DATA:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            len = va_arg(ap, unsigned);
            if (datalen + len > MTU) {
                syslog(LOG_ERR, "Message too long: %d\n", datalen + len);
                return -1;
            }
            memcpy(sendbuf + datalen, va_arg(ap, char *), len);
            datalen += len;
            break;
        case MSGTYPE_KEEPALIVE:
            break;
        case MSGTYPE_SHUTDOWN:
            reason = (unsigned char)va_arg(ap, int);
            memcpy(sendbuf + datalen, &reason, 1);
            datalen += 1;
            break;
        case MSGTYPE_YAK:
            // ...
            break;
        case MSGTYPE_NAK:
            // ...
            break;
        default:
            syslog(LOG_INFO, "Unknown message type: %d\n", msgtype);
            break;
    }
    va_end(ap);
    return sendto(socket_fd, sendbuf, datalen, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
}

int open_socket(short local_port)
{
    int fd;
    struct sockaddr_in addr;
    int optval = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bind() failed: %s", strerror(errno));
        return -1;
    }
    return fd;
}

int write_buf(int fd, buffer_t *buffer)
{
    int n = 0;

    if (buffer->tail > buffer->head)
    {
        n = write(fd, buffer->buf + buffer->tail, buffer->head - buffer->tail);
        if (n <= 0)
            return n;
        if (n < buffer->size - buffer->tail) {
            buffer->tail += n;
            return n;
        }
        buffer->tail = 0;
    }
    if (buffer->head > buffer->tail)
    {
        int n2 = write(fd, buffer->buf + buffer->tail, buffer->head - buffer->tail);
        if (n2 > 0)
        {
            buffer->tail += n2;
            n += n2;
        }
        else if (n2 < 0)
            return n2;
    }
    return n;
}

int send_data(char *data, int len)
{
    static uint16_t seq = 0;
    // todo: store data in buf_sent for possible resent in case of NAK
    return send_msg(MSGTYPE_DATA, seq++, len, data);
}

int receive_data(uint16_t seq, unsigned char *data, int len)
{
    if (len > mtu)
    {
        syslog(LOG_ERR, "Received packet too long: %d\n", len);
        return -1;
    }
    if (buf_recv.head + len >= buf_recv.size)
    {
        memcpy(buf_recv.buf + buf_recv.head, data, buf_recv.size - buf_recv.head);
        data += buf_recv.size - buf_recv.head;
        len -= buf_recv.size - buf_recv.head;
        buf_recv.head = 0;
    }
    if (len > 0)
    {
        memcpy(buf_recv.buf + buf_recv.head, data, len);
        buf_recv.head += len;
    }
    // todo: send ack
    return 1;
}

int read_msg(int *msgtype_p)
{
    unsigned char databuf[MTU];
	struct sockaddr_in remote;
    uint32_t magic;
    uint32_t nonce;
    uint16_t seq;
    int len, n, rc, msgtype;
    unsigned char reason;
    unsigned int sl;

    memset(&remote, 0, sizeof(remote)),
    sl = sizeof(remote);
    n = recvfrom(socket_fd, databuf, sizeof(databuf), 0, (struct sockaddr *)&remote, &sl);
    if (n == -1)
        return -1;
    magic = ntohl(*(uint32_t *)databuf);
    nonce = ntohl(*(uint32_t *)(databuf + sizeof(magic)));
    // todo: decrypt magic with nonce
    // todo: check if nonce is unique to prevent replay attacks (but allow reordered packets)
    memcpy(&remote_addr, &remote, sizeof(remote_addr));
    msgtype = magic - key;
    rc = 1;
    switch (msgtype) {
        case MSGTYPE_INIT:
            send_msg(MSGTYPE_INIT2);
            break;
        case MSGTYPE_INIT2:
            break;
        case MSGTYPE_DATA:
            seq = ntohs(*(uint16_t *)(databuf + sizeof(magic) + sizeof(nonce)));
            len = n - sizeof(magic) - sizeof(nonce) - sizeof(seq);
            n = receive_data(seq, databuf + sizeof(magic) + sizeof(nonce) + sizeof(seq), len);
            if (n < 0)
                return -1;
            break;
        case MSGTYPE_KEEPALIVE:
            break;
        case MSGTYPE_SHUTDOWN:
            reason = *(databuf + sizeof(magic) + sizeof(nonce));
            syslog(LOG_INFO, "Shutdown message received: %u\n", reason);
            return -1;
        case MSGTYPE_YAK:
            // ...
            break;
        case MSGTYPE_NAK:
            // ...
            break;
        default:
            syslog(LOG_INFO, "Unknown message type ignored: %u\n", msgtype);
            rc = 0;
            break;
    }
    if (rc > 0 && msgtype_p != NULL)
        *msgtype_p = msgtype;
    return rc;
}

int init_connection(void)
{
    /* send MSGTIME_INIT each RESEND_INIT time until receive MSGTYPE_INIT2 or any other message (in case if INIT2 lost) */
    /* Answer MSGTYPE_INIT2 on all MSGTYPE_INIT during init stage */
    time_t start = time(NULL);

    if (remote_addr.sin_addr.s_addr) {
        if (send_msg(MSGTYPE_INIT) < 0)
            return -1;
    }
    while (1)
    {
        fd_set fd_in, fd_out;
        struct timeval tm;
        int r, maxfd;
        time_t curtime;

        FD_ZERO(&fd_in);
        FD_ZERO(&fd_out);
        maxfd = socket_fd+1;
        FD_SET(socket_fd, &fd_in);
        tm.tv_sec = 0;
        tm.tv_usec = RESEND_INIT * 1000;
        r = select(maxfd, &fd_in, &fd_out, NULL, &tm);
        if (r < 0)
        {
            syslog(LOG_ERR, "select() failed: %s", strerror(errno));
            return -1;
        }
        if (r == 0)
        {
            curtime = time(NULL);
            if (curtime - start > TIMEOUT_INIT)
            {
                syslog(LOG_ERR, "Timeout waiting for connection\n");
                return -1;
            }
            if (remote_addr.sin_addr.s_addr)
            {
                if (send_msg(MSGTYPE_INIT) < 0)
                    return -1;
            }
            continue;
        }
        if (FD_ISSET(socket_fd, &fd_in))
        {
            int msgtype;
            int n = read_msg(&msgtype);
            if (n < 0)
                return -1;
            if (n == 0)
                continue;
            if (msgtype == MSGTYPE_INIT)
                send_msg(MSGTYPE_INIT2);
            else
                break;
        }
    }
    syslog(LOG_INFO, "Connection established");
    return 0;
}
