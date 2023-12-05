#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include "udp-link.h"

int send_msg(int msgtype, ...)
{
    va_list ap;
    char sendbuf[MTU];
    int datalen=0;
    uint32_t magic;
    uint16_t seq;
    int len;
    unsigned char reason;

    if (remote_addr.sin_addr.s_addr == 0)
    {
        syslog(LOG_ERR, "Remote address is not set");
        return -1;
    }
    magic = htonl(key + msgtype);
    memcpy(sendbuf, &magic, sizeof(magic));
    datalen += sizeof(magic);
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
                syslog(LOG_ERR, "Message too long: %d", datalen + len);
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
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            break;
        case MSGTYPE_NAK:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            break;
        default:
            syslog(LOG_INFO, "Unknown message type: %d", msgtype);
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
    if (fd < 0)
    {
        syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
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
        n = write(fd, buffer->data + buffer->tail, buffer->size - buffer->tail);
        if (n <= 0)
            return n;
        if (n < buffer->size - buffer->tail)
        {
            buffer->tail += n;
            return n;
        }
        buffer->tail = 0;
    }
    if (buffer->head > buffer->tail)
    {
        int n2 = write(fd, buffer->data + buffer->tail, buffer->head - buffer->tail);
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
    memcpy(buf_sent.msgs[buf_sent.head].data, data, len);
    buf_sent.msgs[buf_sent.head].seq = seq;
    buf_sent.msgs[buf_sent.head].len = len;
    buf_sent.msgs[buf_sent.head].yak = 0;
    gettimeofday(&buf_sent.msgs[buf_sent.head].timestamp, NULL);
    buf_sent.head++;
    return send_msg(MSGTYPE_DATA, seq++, len, data);
}

/* seq is resetting after 65546, so we need be careful on comparation */
int cmp_seq(unsigned short seq1, unsigned short seq2)
{
    if (seq1>seq2)
        return seq1-seq2<0x8000u ? 1 : -1;
    if (seq2>seq1)
        return seq2-seq1<0x8000u ? -1 : 1;
    return 0;
}

int receive_data(uint16_t seq, unsigned char *data, int len)
{
    static uint16_t recv_seq = 0;
    if (len > mtu)
    {
        syslog(LOG_ERR, "Received packet too long: %d", len);
        return -1;
    }
    if (seq != recv_seq) {
        if (cmp_seq(seq, recv_seq) > 0)
        {
            syslog(LOG_INFO, "Received data packet with seq %u, expected %u, send NAK", seq, recv_seq);
            send_msg(MSGTYPE_NAK, seq);
        }
        else
            syslog(LOG_INFO, "Received data packet with seq %u, expected %u, ignored", seq, recv_seq);
        return 1;
    }
    if (buf_out.head+len >= buf_out.size)
    {
        memcpy(buf_out.data + buf_out.head, data, buf_out.size - buf_out.head);
        data += buf_out.size - buf_out.head;
        len  -= buf_out.size - buf_out.head;
        buf_out.head = 0;
    }
    if (len > 0)
    {
        memcpy(buf_out.data+buf_out.head, data, len);
        buf_out.head += len;
    }
    send_msg(MSGTYPE_YAK, recv_seq++);
    return 1;
}

int process_yak(unsigned short seq)
{
    unsigned short tail_seq;
    if (buf_sent.head==buf_sent.tail)
    {
        syslog(LOG_INFO, "Incorrect YAK (buffer is empty), ignored");
        return 0;
    }
    tail_seq = buf_sent.msgs[buf_sent.tail].seq;
    if (tail_seq == seq)
    {
        buf_sent.tail++;
        return 0;
    }
    if (cmp_seq(tail_seq, seq) > 0)
        /* it's old (obsoleted) yak */
        return 0;
    if (cmp_seq(buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq, seq) < 0)
    {
        /* yak from the future (was it rollback?) */
        syslog(LOG_INFO, "Incorrect YAK, ignored");
        return 0;
    }
    /* all packets from tail to seq are confirmed */
    buf_sent.tail += seq>tail_seq ? seq-tail_seq+1 : seq+0x10000u-tail_seq+1;
    buf_sent.tail %= buf_sent.size;
}

int process_nak(unsigned short seq)
{
    unsigned short tail_seq;
    int ndx;

    if (buf_sent.head==buf_sent.tail)
    {
        syslog(LOG_INFO, "Incorrect NAK (buffer is empty), ignored");
        return 0;
    }
    tail_seq = buf_sent.msgs[buf_sent.tail].seq;
    if (cmp_seq(tail_seq, seq) > 0)
    {
        /* it's old (obsoleted) nak */
        syslog(LOG_INFO, "Incorrect (obsoleted) NAK, ignored");
        return 0;
    }
    if (cmp_seq(buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq, seq) < 0)
    {
        /* nak from the future (was it rollback?) */
        syslog(LOG_INFO, "Incorrect (future) NAK, ignored");
        return 0;
    }
    /* resend all packets from the seq to the head */
    syslog(LOG_INFO, "Received NAK, resend packets from %u to %u", seq, buf_sent.msgs[(buf_sent.head-1)%buf_sent.size].seq);
    ndx = (buf_sent.tail + (seq>tail_seq ? seq-tail_seq : seq+0x10000u-tail_seq)) % buf_sent.size;
    do
    {
        send_msg(MSGTYPE_DATA, buf_sent.msgs[ndx].seq, buf_sent.msgs[ndx].len, buf_sent.msgs[ndx].data);
        ndx = (ndx+1)%buf_sent.size;
    }
    while (ndx != buf_sent.head);
    return 0;
}

int read_msg(int *msgtype_p)
{
    unsigned char databuf[MTU];
    unsigned char *pdata;
	struct sockaddr_in remote;
    uint32_t magic;
    uint16_t seq;
    int len, n, rc, msgtype;
    unsigned char reason;
    unsigned int sl;

    memset(&remote, 0, sizeof(remote)),
    sl = sizeof(remote);
    n = recvfrom(socket_fd, databuf, sizeof(databuf), 0, (struct sockaddr *)&remote, &sl);
    if (n == -1)
        return -1;
    if (n < sizeof(magic))
    {
        syslog(LOG_INFO, "Bad packet, length %u, ignore", n);
        return 0;
    }
    magic = ntohl(*(uint32_t *)databuf);
    memcpy(&remote_addr, &remote, sizeof(remote_addr));
    n -= sizeof(magic);
    pdata = databuf+sizeof(magic);
    msgtype = magic-key;
    rc = 1;
    switch (msgtype) {
        case MSGTYPE_INIT:
            if (n != 0)
            {
                syslog(LOG_ERR, "Incorrect init packet");
                return -1;
            }
            send_msg(MSGTYPE_INIT2);
            break;
        case MSGTYPE_INIT2:
            if (n != 0)
            {
                syslog(LOG_ERR, "Incorrect init2 packet");
                return -1;
            }
            break;
        case MSGTYPE_DATA:
            if (n <= sizeof(seq))
            {
                syslog(LOG_ERR, "Incorrect data packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            n -= sizeof(seq);
            pdata += sizeof(seq);
            if (receive_data(seq, pdata, n) < 0)
                return -1;
            break;
        case MSGTYPE_KEEPALIVE:
            if (n != 0)
            {
                syslog(LOG_ERR, "Incorrect keepalive packet");
                return -1;
            }
            break;
        case MSGTYPE_SHUTDOWN:
            if (n != 1)
            {
                syslog(LOG_ERR, "Incorrect shutdown packet");
                return -1;
            }
            reason = *pdata;
            syslog(LOG_INFO, "Shutdown message received: %u", reason);
            break;
        case MSGTYPE_YAK:
            if (n != sizeof(seq))
            {
                syslog(LOG_ERR, "Incorrect yak packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            process_yak(seq);
            break;
        case MSGTYPE_NAK:
            if (n != sizeof(seq))
            {
                syslog(LOG_ERR, "Incorrect nak packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            process_nak(seq);
            break;
        default:
            syslog(LOG_INFO, "Unknown message type ignored: %u", msgtype);
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

    if (remote_addr.sin_addr.s_addr)
    {
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
            fprintf(stderr, "select() failed: %s", strerror(errno));
            return -1;
        }
        if (r == 0)
        {
            curtime = time(NULL);
            if (curtime - start > TIMEOUT_INIT)
            {
                fprintf(stderr, "Timeout waiting for connection\n");
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
