#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp-link.h"

u_long key;
int socket_fd;
unsigned int mtu = MTU;
buffer_t buf_recv, buf_sent;
struct sockaddr_in remote_addr;

void sigpipe(int signo)
{
    syslog(LOG_ERR, "SIGPIPE received");
}

int main(int argc, char *argv[])
{
    time_t last_sent, last_received;
    int stdin_fileno = fileno(stdin);
    int stdout_fileno = fileno(stdout);
    int packet_to_send = 0;
    char *packet_data;
    unsigned int window_pkts;
    unsigned int keepalive_interval = KEEPALIVE_INTERVAL;
    unsigned int timeout = TIMEOUT;
    short local_port;

    openlog("udp-link", LOG_PID, LOG_DAEMON);
    /* params */
    // ...
    if (argv[1] && argv[2]) {
        key=atoi(argv[1]);
        local_port = atoi(argv[2]);
    }
    else {
        printf("Usage: udp-link key local_port [remote_ip remote_port]\n");
        return 1;
    }
    memset(&remote_addr, 0, sizeof(remote_addr));
    if (argv[3] && argv[4]) {
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(argv[3]);
        remote_addr.sin_port = htons(atoi(argv[4]));
    }

    buf_recv.size = BUFSIZE;
    buf_recv.buf=malloc(buf_recv.size);
    window_pkts = BUFSIZE / mtu;
    buf_sent.size = window_pkts * mtu;
    buf_sent.buf=malloc(buf_sent.size);
    packet_data = malloc(mtu);
    if (buf_recv.buf==NULL || buf_sent.buf==NULL || packet_data==NULL)
    {   syslog(LOG_ERR, "Can't malloc()");
        return 1;
    }
    buf_sent.head = buf_sent.tail = 0;
    buf_recv.head = buf_recv.tail = 0;

    sigset(SIGPIPE, sigpipe);

    socket_fd = open_socket(local_port);
    if (socket_fd < 0)
        return 1;

    if (init_connection() != 0)
        return 3;

    last_sent = last_received = time(NULL);

    while (1) {
        fd_set fd_in, fd_out;
        struct timeval tm;
        int r, maxfd;
        time_t curtime;

        FD_ZERO(&fd_in);
        FD_ZERO(&fd_out);
        maxfd = 0;
        if (packet_to_send == 0 && (buf_sent.head+1)%buf_sent.size != buf_sent.tail)
        {
            FD_SET(stdin_fileno, &fd_in);
            if (stdin_fileno > maxfd)
                maxfd = stdin_fileno;
        }
        if (buf_recv.head != buf_recv.tail)
        {
            FD_SET(stdout_fileno, &fd_out);
            if (stdout_fileno > maxfd)
                maxfd = stdout_fileno;
        }
        if ((buf_recv.head+buf_recv.size-buf_recv.tail) % buf_recv.size < buf_recv.size-mtu)
        {
            // we have space for at least one packet
            FD_SET(socket_fd, &fd_in);
            if (socket_fd > maxfd)
                maxfd = socket_fd;
        }
        /* Assume we always can write to socket */
        curtime=time(NULL);
        if (packet_to_send) {
            tm.tv_sec=0;
            tm.tv_usec=RESEND_INTERVAL*1000;
        }
        else {
            /* keepalive is mandatory */
            tm.tv_sec=keepalive_interval-(curtime-last_sent);
            if (timeout && tm.tv_sec>timeout-(curtime-last_received))
                tm.tv_sec=timeout-(curtime-last_received);
            tm.tv_usec=0;
        }
        r = select(maxfd+1, &fd_in, &fd_out, NULL, &tm);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "Can't select: %s", strerror(errno));
            send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
            close(socket_fd);
            return 1;
        }
        if (curtime-last_received > timeout)
        {
            syslog(LOG_ERR, "Timeout");
            send_msg(MSGTYPE_SHUTDOWN, REASON_TIMEOUT);
            return 1;
        }
        if (curtime-last_sent > keepalive_interval && !packet_to_send)
            send_msg(MSGTYPE_KEEPALIVE);
        if (FD_ISSET(stdout_fileno, &fd_out))
        {
            int n = write_buf(stdout_fileno, &buf_recv);
            if (n < 0)
            {
                syslog(LOG_ERR, "Can't write to stdout: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n == 0)
            {
                syslog(LOG_ERR, "stdout closed");
                send_msg(MSGTYPE_SHUTDOWN, REASON_NORMAL);
                return 1;
            }
        }
        if (FD_ISSET(socket_fd, &fd_in))
        {
            int n = read_msg(NULL);
            if (n < 0)
            {
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n > 0)
                last_received = curtime;
        }
        if (FD_ISSET(stdin_fileno, &fd_in))
        {
            // read from stdin
            int n = read(stdin_fileno, packet_data, mtu);
            if (n > 0)
                packet_to_send = n;
            else if (n < 0)
            {
                syslog(LOG_ERR, "Can't read from stdin: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            else
            {
                syslog(LOG_INFO, "stdin closed");
                send_msg(MSGTYPE_SHUTDOWN, REASON_NORMAL);
                return 0;
            }
        }
        if (packet_to_send > 0)
        {
            int n = send_data(packet_data, packet_to_send);
            if (n < 0)
                // try later
                syslog(LOG_INFO, "Can't send_data: %s", strerror(errno));
            else
            {
                last_sent = curtime;
                packet_to_send = 0;
            }
        }
    }
}
