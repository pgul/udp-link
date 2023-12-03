#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp-link.h"

u_long key;
int socket_fd;
unsigned int mtu = MTU-DATA_HEADER_SIZE;
buf_pkt_t buf_recv; /* currently unused */
buf_pkt_t buf_sent;
buffer_t buf_out;
struct sockaddr_in remote_addr;
int shutdown_local = 0, shutdown_remote = 0;

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

    buf_recv.size = buf_sent.size = BUFSIZE;
    buf_recv.msgs = malloc(buf_recv.size*sizeof(buf_recv.msgs[0]));
    buf_sent.msgs = malloc(buf_sent.size*sizeof(buf_sent.msgs[0]));
    buf_out.size = BUF2SIZE;
    buf_out.data = malloc(buf_out.size);
    packet_data = malloc(mtu);
    if (buf_recv.msgs==NULL || buf_sent.msgs==NULL || buf_out.data==NULL || packet_data==NULL)
    {   syslog(LOG_ERR, "Can't malloc()");
        return 1;
    }
    buf_sent.head = buf_sent.tail = 0;
    buf_recv.head = buf_recv.tail = 0;
    buf_out.head  = buf_out.tail  = 0;

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
        if (packet_to_send == 0 && (buf_sent.head+1)%buf_sent.size != buf_sent.tail && !shutdown_remote && !shutdown_local)
        {
            FD_SET(stdin_fileno, &fd_in);
            if (stdin_fileno > maxfd)
                maxfd = stdin_fileno;
        }
        if (buf_out.head != buf_out.tail && !shutdown_local)
        {
            FD_SET(stdout_fileno, &fd_out);
            if (stdout_fileno > maxfd)
                maxfd = stdout_fileno;
        }
        if ((buf_out.head+buf_out.size-buf_out.tail)%buf_out.size < buf_out.size-mtu && !shutdown_remote)
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
        if (FD_ISSET(socket_fd, &fd_in))
        {
            int msgtype;
            int n = read_msg(&msgtype);
            if (n < 0)
            {
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n > 0)
            {
                last_received = curtime;
                if (msgtype == MSGTYPE_SHUTDOWN) {
                    shutdown_remote = 1;
                    buf_sent.head = buf_sent.tail = 0;
                }
                else if (msgtype == MSGTYPE_DATA && shutdown_local)
                    /* ignore (purge) received data packets after shutdown */
                    buf_out.head = buf_out.tail = 0;
            }
        }
        if (FD_ISSET(stdout_fileno, &fd_out))
        {
            int n = write_buf(stdout_fileno, &buf_out);
            if (n < 0)
            {
                syslog(LOG_ERR, "Can't write to stdout: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n == 0)
            {
                syslog(LOG_ERR, "stdout closed");
                buf_out.head = buf_out.tail = 0;
                shutdown_local = 1;
            }
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
                buf_out.head = buf_out.tail = 0;
                shutdown_local = 1;
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
        if (shutdown_local && buf_sent.head == buf_sent.tail && packet_to_send == 0)
        {
            send_msg(MSGTYPE_SHUTDOWN, REASON_NORMAL);
            syslog(LOG_INFO, "Normal shutdown");
            return 0;
        }
        if (shutdown_remote && buf_out.head == buf_out.tail)
        {
            syslog(LOG_INFO, "Remote shutdown");
            return 0;
        }
    }
}
