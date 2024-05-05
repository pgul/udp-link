#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include "udp-link.h"

static uint16_t remote_version = 0;
static uint16_t local_version;

int send_msg(int sockfd, int msgtype, ...)
{
    va_list ap;
    char sendbuf[MTU];
    int datalen=0;
    uint32_t magic;
    uint16_t seq, seq2;
    char *data;
    int len;
    unsigned char reason;

    if (remote_addr.sin_addr.s_addr == 0)
    {
        write_log(LOG_ERR, "Remote address is not set");
        return -1;
    }
    magic = htonl(key + msgtype);
    memcpy(sendbuf, &magic, sizeof(magic));
    datalen += sizeof(magic);
    va_start(ap, msgtype);
    switch (msgtype) {
        case MSGTYPE_INIT:
            if (debug) write_log(LOG_DEBUG, "Sending init");
            memcpy(sendbuf + datalen, &local_version, sizeof(local_version));
            datalen += sizeof(local_version);
            break;
        case MSGTYPE_INIT2:
            if (debug) write_log(LOG_DEBUG, "Sending init2");
            break;
        case MSGTYPE_DATA:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            len = va_arg(ap, unsigned);
            if (datalen + len > MTU) {
                write_log(LOG_ERR, "Message too long: %d", datalen + len);
                return -1;
            }
            data = va_arg(ap, char *);
            memcpy(sendbuf + datalen, data, len);
            if (dump)
                write_log(LOG_DEBUG, "Sending data packet, seq %u, len %u, data %s", ntohs(seq), len, dump_data(data, len));
            else if (debug)
                write_log(LOG_DEBUG, "Sending data packet, seq %u, len %u", ntohs(seq), len);
            datalen += len;
            break;
        case MSGTYPE_KEEPALIVE:
            if (debug) write_log(LOG_DEBUG, "Sending keepalive");
            break;
        case MSGTYPE_SHUTDOWN:
            reason = (unsigned char)va_arg(ap, int);
            memcpy(sendbuf + datalen, &reason, 1);
            datalen += 1;
            if (debug) write_log(LOG_DEBUG, "Sending shutdown reason %u", reason);
            break;
        case MSGTYPE_YAK:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            if (debug) write_log(LOG_DEBUG, "Sending yak seq %u", ntohs(seq));
            break;
        case MSGTYPE_NAK:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            if (debug) write_log(LOG_DEBUG, "Sending nak seq %u", ntohs(seq));
            break;
        case MSGTYPE_NAK2:
            seq = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            seq2 = htons(va_arg(ap, unsigned));
            memcpy(sendbuf + datalen, &seq, sizeof(seq));
            datalen += sizeof(seq);
            if (debug) write_log(LOG_DEBUG, "Sending nak2 seq %u-%u", ntohs(seq), ntohs(seq2));
            break;
        case MSGTYPE_PING:
            if (debug) write_log(LOG_DEBUG, "Sending ping");
            break;
        case MSGTYPE_PONG:
            if (debug) write_log(LOG_DEBUG, "Sending pong");
            break;
        default:
            write_log(LOG_INFO, "Unknown message type: %d", msgtype);
            break;
    }
    va_end(ap);
    if (sockfd == socket_fd)
        return sendto(sockfd, sendbuf, datalen, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
    else
        return send(sockfd, sendbuf, datalen, 0);
}

int open_socket(short local_port)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        write_log(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
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
            if (dump)
                write_log(LOG_DEBUG, "Write %u bytes to target, new tail %u: %s", n, buffer->tail+n, dump_data(buffer->data + buffer->tail, n));
            buffer->tail += n;
            return n;
        }
        if (dump)
            write_log(LOG_DEBUG, "Write %u bytes to target, new tail %u: %s", n, 0, dump_data(buffer->data + buffer->tail, n));
        buffer->tail = 0;

    }
    if (buffer->head > buffer->tail)
    {
        int n2 = write(fd, buffer->data + buffer->tail, buffer->head - buffer->tail);
        if (n2 > 0)
        {
            if (dump)
                write_log(LOG_DEBUG, "Write %u bytes to target, new tail %u: %s", n2, buffer->tail+n2, dump_data(buffer->data + buffer->tail, n2));
            buffer->tail += n2;
            n += n2;
        }
        else if (n2 < 0)
            return n2;
    }
    if (debug && !dump)
        write_log(LOG_DEBUG, "Write %u bytes from buffer to target, new tail %u", n, buffer->tail);
    return n;
}

int send_data(char *data, int len)
{
    static uint16_t seq = 0;
    int rc;
    memcpy(buf_sent.msgs[buf_sent.head].data, data, len);
    buf_sent.msgs[buf_sent.head].seq = seq;
    buf_sent.msgs[buf_sent.head].len = len;
    buf_sent.msgs[buf_sent.head].yak = 0;
    buf_sent.msgs[buf_sent.head].timestamp = time_ms();
    buf_sent.head = (buf_sent.head+1)%buf_sent.size;
    rc = send_msg(socket_fd, MSGTYPE_DATA, seq, len, data);
    if (rc > 0)
        seq++;
    return rc;
}

/* seq is resetting after 65546, so we need be careful on comparation */
int cmp_seq(uint16_t seq1, uint16_t seq2)
{
    if (seq1>seq2)
        return seq1-seq2<0x8000u ? 1 : -1;
    if (seq2>seq1)
        return seq2-seq1<0x8000u ? -1 : 1;
    return 0;
}

int receive_data(uint16_t seq, char *data, int len)
{
    static uint16_t recv_seq = 0;
    static int last_nak_seq = -1;

    if (len > mtu)
    {
        write_log(LOG_ERR, "Received packet too long: %d", len);
        return -1;
    }
    if (seq != recv_seq) {
        if (cmp_seq(seq, recv_seq) > 0)
        {
            if (remote_version >= 1)
            {
                if (buf_recv.head != buf_recv.tail && cmp_seq(seq, buf_recv.msgs[buf_recv.tail].seq) < 0)
                    buf_recv.head = buf_recv.tail;
                if ((buf_recv.head+1)%buf_recv.size != buf_recv.tail &&
                    (buf_recv.head == buf_recv.tail || seq == buf_recv.msgs[(buf_recv.head+buf_recv.size-1)%buf_recv.size].seq+1))
                {
                    if (last_nak_seq != (int)recv_seq || buf_recv.head == buf_recv.tail)
                    {
                        write_log(LOG_INFO, "Received data packet with seq %u, expected %u, send NAK2", seq, recv_seq);
                        send_msg(socket_fd, MSGTYPE_NAK2, recv_seq, seq-1);
                        last_nak_seq = recv_seq;
                    }
                    else
                        write_log(LOG_DEBUG, "Received data packet with seq %u, save to ahead buffer", seq);
                    memcpy(buf_recv.msgs[buf_recv.head].data, data, len);
                    buf_recv.msgs[buf_recv.head].seq = seq;
                    buf_recv.msgs[buf_recv.head].len = len;
                    buf_recv.head = (buf_recv.head+1)%buf_recv.size;
                }
                else
                    write_log(LOG_INFO, "Received data packet with seq %u, expected %u, ignored", seq, recv_seq);
            }
            else
            {   /* NAK2 not supported by remote */
                if (last_nak_seq != (int)recv_seq)
                {
                    write_log(LOG_INFO, "Received data packet with seq %u, expected %u, send NAK", seq, recv_seq);
                    send_msg(socket_fd, MSGTYPE_NAK, recv_seq);
                    last_nak_seq = recv_seq;
                }
            }
        }
        else
        {
            write_log(LOG_INFO, "Received data packet with seq %u, expected %u, ignored", seq, recv_seq);
            if (seq+1 == recv_seq)
                send_msg(socket_fd, MSGTYPE_YAK, seq);
        }
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
    if (debug)
        write_log(LOG_DEBUG, "Data saved to buffer, new head %u", buf_out.head);
    /* process ahead buffer */
    if (buf_recv.head != buf_recv.tail && buf_recv.msgs[buf_recv.tail].seq == recv_seq+1)
    {
        do
        {
            if (buf_out.head+buf_recv.msgs[buf_recv.tail].len >= buf_out.size)
            {
                int n = buf_out.size - buf_out.head;
                memcpy(buf_out.data+buf_out.head, buf_recv.msgs[buf_recv.tail].data, n);
                if (dump)
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u: %s", buf_recv.tail, 0, dump_data(buf_out.data+buf_out.head, n));
                else
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u", buf_recv.tail, 0);
                buf_out.head = 0;
                memcpy(buf_out.data, buf_recv.msgs[buf_recv.tail].data+n, buf_recv.msgs[buf_recv.tail].len-n);
                if (dump)
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u: %s", buf_recv.tail, buf_out.head+buf_recv.msgs[buf_recv.tail].len-n, dump_data(buf_out.data, buf_recv.msgs[buf_recv.tail].len-n));
                else
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u", buf_recv.tail, buf_out.head+buf_recv.msgs[buf_recv.tail].len-n);
                buf_out.head += buf_recv.msgs[buf_recv.tail].len-n;
            }
            else
            {
                memcpy(buf_out.data+buf_out.head, buf_recv.msgs[buf_recv.tail].data, buf_recv.msgs[buf_recv.tail].len);
                if (dump)
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u: %s", buf_recv.tail, buf_out.head+buf_recv.msgs[buf_recv.tail].len, dump_data(buf_out.data+buf_out.head, buf_recv.msgs[buf_recv.tail].len));
                else
                    write_log(LOG_DEBUG, "Data from ahead pkt %u saved to buffer, new head %u", buf_recv.tail, buf_out.head+buf_recv.msgs[buf_recv.tail].len);
                buf_out.head += buf_recv.msgs[buf_recv.tail].len;
            }
            buf_recv.tail = (buf_recv.tail+1)%buf_recv.size;
            recv_seq++;
        }
        while (buf_recv.head != buf_recv.tail);
    }
    send_msg(socket_fd, MSGTYPE_YAK, recv_seq++);
    last_nak_seq = -1;
    return 1;
}

int process_yak(uint16_t seq)
{
    uint16_t tail_seq;
    if (buf_sent.head==buf_sent.tail)
    {
        write_log(LOG_INFO, "Incorrect YAK (buffer is empty), ignored");
        return 0;
    }
    tail_seq = buf_sent.msgs[buf_sent.tail].seq;
    if (tail_seq == seq)
    {
        buf_sent.tail = (buf_sent.tail+1)%buf_sent.size;
        return 0;
    }
    if (cmp_seq(tail_seq, seq) > 0)
        /* it's old (obsoleted) yak */
        return 0;
    if (cmp_seq(buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq, seq) < 0)
    {
        /* yak from the future (was it rollback?) */
        write_log(LOG_INFO, "Incorrect YAK, ignored");
        return 0;
    }
    /* all packets from tail to seq are confirmed */
    buf_sent.tail += seq-tail_seq+1;
    buf_sent.tail %= buf_sent.size;
    return 0;
}

int process_nak(uint16_t seq)
{
    uint16_t tail_seq;
    int ndx;

    if (buf_sent.head==buf_sent.tail)
    {
        write_log(LOG_INFO, "Incorrect NAK (buffer is empty) seq %u, ignored", seq);
        return 0;
    }
    tail_seq = buf_sent.msgs[buf_sent.tail].seq;
    if (cmp_seq(tail_seq, seq) > 0)
    {
        /* it's old (obsoleted) nak */
        write_log(LOG_INFO, "Incorrect (obsoleted) NAK seq %u, ignored", seq);
        return 0;
    }
    if (cmp_seq(buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq, seq) < 0)
    {
        /* nak from the future (was it rollback?) */
        write_log(LOG_INFO, "Incorrect (future) NAK seq %u, ignored", seq);
        return 0;
    }
    /* all packets from tail to seq-1 are confirmed */
    if (seq != tail_seq)
    {
        buf_sent.tail += seq-tail_seq;
        buf_sent.tail %= buf_sent.size;
    }
    /* resend all packets from the seq to the head */
    if (debug)
        write_log(LOG_DEBUG, "Received NAK, resend packets from %u to %u", seq,
            buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq);
    ndx = buf_sent.tail;
    do
    {
        send_msg(socket_fd, MSGTYPE_DATA, buf_sent.msgs[ndx].seq, buf_sent.msgs[ndx].len, buf_sent.msgs[ndx].data);
        ndx = (ndx+1)%buf_sent.size;
    }
    while (ndx != buf_sent.head);
    return 0;
}

int process_nak2(uint16_t seq1, uint16_t seq2)
{
    uint16_t tail_seq;
    int ndx;

    if (buf_sent.head==buf_sent.tail)
    {
        write_log(LOG_INFO, "Incorrect NAK (buffer is empty) seq %u-%u, ignored", seq1, seq2);
        return 0;
    }
    tail_seq = buf_sent.msgs[buf_sent.tail].seq;
    if (cmp_seq(tail_seq, seq1) > 0)
    {
        /* it's old (obsoleted) nak */
        write_log(LOG_INFO, "Incorrect (obsoleted) NAK seq %u-%u, ignored", seq1, seq2);
        return 0;
    }
    if (cmp_seq(buf_sent.msgs[(buf_sent.head+buf_sent.size-1)%buf_sent.size].seq, seq2) < 0)
    {
        /* nak from the future (was it rollback?) */
        write_log(LOG_INFO, "Incorrect (future) NAK seq %u-%u, ignored", seq1, seq2);
        return 0;
    }
    /* all packets from tail to seq1-1 are confirmed */
    if (seq1 != tail_seq)
    {
        buf_sent.tail += seq1-tail_seq;
        buf_sent.tail %= buf_sent.size;
    }
    /* resend all packets from the seq1 to the seq2 */
    if (debug)
        write_log(LOG_DEBUG, "Received NAK2, resend packets from %u to %u", seq1, seq2);
    ndx = buf_sent.tail;
    while (1)
    {
        send_msg(socket_fd, MSGTYPE_DATA, buf_sent.msgs[ndx].seq, buf_sent.msgs[ndx].len, buf_sent.msgs[ndx].data);
        if (buf_sent.msgs[ndx].seq == seq2)
            break;
        ndx = (ndx+1)%buf_sent.size;
    }
    return 0;
}

int read_msg(int *msgtype_p)
{
    char databuf[MTU];
    char *pdata;
	struct sockaddr_in remote;
    uint32_t magic;
    uint16_t seq;
    int n, rc, msgtype;
    unsigned char reason;
    unsigned int sl;

    memset(&remote, 0, sizeof(remote)),
    sl = sizeof(remote);
    n = recvfrom(socket_fd, databuf, sizeof(databuf), 0, (struct sockaddr *)&remote, &sl);
    if (n == -1)
    {
        write_log(LOG_ERR, "recvfrom() failed: %s", strerror(errno));
        return -1;
    }
    if (n < sizeof(magic))
    {
        write_log(LOG_INFO, "Bad packet, length %u, ignore", n);
        return 0;
    }
    magic = ntohl(*(uint32_t *)databuf);
    n -= sizeof(magic);
    pdata = databuf+sizeof(magic);
    msgtype = magic-key;
    if (msgtype > MSGTYPE_MAX || msgtype < 0)
    {
        write_log(LOG_INFO, "Unknown message type %u (incorrect connection key?), ignore", msgtype);
        return 0;
    }
    memcpy(&remote_addr, &remote, sizeof(remote_addr));
    rc = 1;
    switch (msgtype) {
        case MSGTYPE_INIT:
            if (n == 2)
            {
                remote_version = ntohs(*(uint16_t *)pdata);
                n -= sizeof(remote_version);
            }
            else if (n != 0)
            {
                write_log(LOG_ERR, "Incorrect init packet");
                return -1;
            }
            if (debug) write_log(LOG_DEBUG, "Received init");
            send_msg(socket_fd, MSGTYPE_INIT2);
            break;
        case MSGTYPE_INIT2:
            if (n != 0)
            {
                write_log(LOG_ERR, "Incorrect init2 packet");
                return -1;
            }
            if (debug) write_log(LOG_DEBUG, "Received init2");
            break;
        case MSGTYPE_DATA:
            if (n <= sizeof(seq))
            {
                write_log(LOG_ERR, "Incorrect data packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            n -= sizeof(seq);
            pdata += sizeof(seq);
            if (dump)
                write_log(LOG_DEBUG, "Received data packet, seq %u, len %u, data %s", seq, n, dump_data(pdata, n));
            else if (debug)
                write_log(LOG_DEBUG, "Received data packet, seq %u, len %u", seq, n);
            if (receive_data(seq, pdata, n) < 0)
                return -1;
            break;
        case MSGTYPE_KEEPALIVE:
            if (n != 0)
            {
                write_log(LOG_ERR, "Incorrect keepalive packet");
                return -1;
            }
            if (debug) write_log(LOG_DEBUG, "Received keepalive");
            break;
        case MSGTYPE_SHUTDOWN:
            if (n != 1)
            {
                write_log(LOG_ERR, "Incorrect shutdown packet");
                return -1;
            }
            reason = *pdata;
            write_log(LOG_INFO, "Shutdown message received: %u", reason);
            break;
        case MSGTYPE_YAK:
            if (n != sizeof(seq))
            {
                write_log(LOG_ERR, "Incorrect yak packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            if (debug) write_log(LOG_DEBUG, "Received yak seq %u", seq);
            process_yak(seq);
            break;
        case MSGTYPE_NAK:
            if (n != sizeof(seq))
            {
                write_log(LOG_ERR, "Incorrect nak packet");
                return -1;
            }
            seq = ntohs(*(uint16_t *)pdata);
            process_nak(seq);
            break;
        case MSGTYPE_NAK2:
            if (n != 2*sizeof(seq))
            {
                write_log(LOG_ERR, "Incorrect nak2 packet");
                return -1;
            }
            process_nak2(ntohs(((uint16_t *)pdata)[0]), ntohs(((uint16_t *)pdata)[1]));
            break;
        default:
            write_log(LOG_INFO, "Unknown message type ignored: %u", msgtype);
            rc = 0;
            break;
    }
    if (rc > 0 && msgtype_p != NULL)
        *msgtype_p = msgtype;
    return rc;
}

/* return 0 if timeout, 1 if response received, -1 if send error, -2 if port unreachable */
int udp_ping(void)
{
    /* for catch icmp port unreachable we have to create connected socket */
    /* bind it to another local port - this affects stored our port on remote, but it's not a problem, it will return later */
    /* we cannot bind to the same local port, because it will be in use by main socket */
    /* we can close main socket for the check time, but it's not good idea, because we will lost all data in buffer */
    int sockfd, rc, n, saved_errno;
    char *buf[MTU];
    struct pollfd fds[1];

    if (remote_addr.sin_addr.s_addr == 0)
    {
        write_log(LOG_ERR, "Remote address is not set");
        return -1;
    }
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        write_log(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    if (connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
    {
        write_log(LOG_ERR, "connect() failed: %s", strerror(errno));
        return -1;
    }
    if (send_msg(sockfd, MSGTYPE_PING) < 0)
    {
        write_log(LOG_ERR, "send() failed: %s", strerror(errno));
        return -1;
    }
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    rc = poll(fds, 1, PING_TIMEOUT);
    if (rc < 0)
    {
        write_log(LOG_ERR, "poll() failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    if (rc == 0)
    {
        write_log(LOG_INFO, "Ping timeout");
        close(sockfd);
        return 0;
    }
    n = recv(sockfd, buf, sizeof(buf), 0);
    saved_errno = errno;
    close(sockfd);
    if (n < 0)
    {
        if (saved_errno == ECONNREFUSED)
        {
            write_log(LOG_INFO, "Ping: port unreachable");
            return -2;
        }
        write_log(LOG_ERR, "Ping recv() failed: %s", strerror(saved_errno));
        return -1;
    }
    if (n == 0)
    {
        write_log(LOG_INFO, "Ping: connection closed");
        return 0;
    }
    write_log(LOG_INFO, "Ping: response received");
    return 1;
}

int init_connection(void)
{
    /* send MSGTYPE_INIT each RESEND_INIT time until receive MSGTYPE_INIT2 or any other message (in case if INIT2 lost) */
    /* Answer MSGTYPE_INIT2 on all MSGTYPE_INIT during init stage */

    local_version = htons(VERSION);
    if (remote_addr.sin_addr.s_addr)
    {
        if (send_msg(socket_fd, MSGTYPE_INIT) < 0)
            return -1;
    }
    while (1)
    {
        struct pollfd fds[1];
        int r;
        unsigned int curtime;

        fds[0].fd = socket_fd;
        fds[0].events = POLLIN;
        r = poll(fds, 1, RESEND_INIT);
        if (r < 0)
        {
            fprintf(stderr, "select() failed: %s", strerror(errno));
            return -1;
        }
        if (r == 0)
        {
            curtime = time_ms();
            if (curtime > TIMEOUT_INIT)
            {
                fprintf(stderr, "Timeout waiting for connection\n");
                return -1;
            }
            if (remote_addr.sin_addr.s_addr)
            {
                if (send_msg(socket_fd, MSGTYPE_INIT) < 0)
                    return -1;
            }
            continue;
        }
        if (fds[0].revents & POLLIN)
        {
            int msgtype;
            int n = read_msg(&msgtype);
            if (n < 0)
                return -1;
            if (n == 0)
                continue;
            if (msgtype != MSGTYPE_INIT)
                break;
        }
    }
    write_log(LOG_INFO, "Connection established");
    return 0;
}
