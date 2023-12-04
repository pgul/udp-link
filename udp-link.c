#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include "udp-link.h"

u_long key;
int socket_fd;
unsigned int mtu = MTU-DATA_HEADER_SIZE;
buf_pkt_t buf_recv; /* currently unused */
buf_pkt_t buf_sent;
buffer_t buf_out;
struct sockaddr_in remote_addr;
static int shutdown_local = 0, shutdown_remote = 0;
static int target_in_fd, target_out_fd;
static short local_port;

void usage(void)
{
    printf("Usage: udp-link [options] key\n");
    printf("Options:\n");
    printf("  -r, --remote=IP[:PORT]  remote IP address and port, default port %u\n", DEFAULT_PORT);
    printf("  -t, --target=IP[:PORT]  target IP address and port, default port 22\n");
    printf("  -b, --bind=PORT         bind to local port PORT, default %u\n", DEFAULT_PORT);
    printf("  -h, --help              display this help and exit\n");
}

void sigpipe(int signo)
{
    syslog(LOG_ERR, "SIGPIPE received");
}

int parse_args(int argc, char *argv[])
{
    int c;
    char target[256], remote[256];
    struct option long_options[] = {
        {"target", required_argument, NULL, 't'},
        {"remote", required_argument, NULL, 'r'},
        {"bind",   required_argument, NULL, 'b'},
        {"help",   no_argument,       NULL, 'h'},
        {0, 0, 0, 0 }
    };
    while ((c = getopt_long(argc, argv, "t:r:b:h", long_options, NULL)) != EOF)
    {
        switch (c)
        {
            case 't':   strncpy(target, optarg, sizeof(target)-1);
                        target[sizeof(target)-1] = '\0';
                        break;
            case 'r':   strncpy(remote, optarg, sizeof(remote)-1);
                        remote[sizeof(remote)-1] = '\0';
                        break;
            case 'b':   local_port = atoi(optarg);
                        break;
            case 'h':   usage();
                        return 0;
        }
    }
    argc -= optind;
    argv += optind;

    if (argv[0] && !argv[1]) {
        key = atoi(argv[0]);
    }
    else {
        usage();
        return 1;
    }
    if (target[0]) {
        struct sockaddr_in target_addr;
        struct hostent *target_host;
        int target_sockfd;
        char *p;

        memset(&target_addr, 0, sizeof(target_addr));
        p = strchr(target, ':');
        if (p)
        {   *p = '\0';
            target_addr.sin_port = htons(atoi(p+1));
        }
        else
            target_addr.sin_port = htons(22);
        target_host = gethostbyname(target);
        if (target_host == NULL)
        {   fprintf(stderr, "Can't resolve target host %s\n", target);
            return 1;
        }
        memcpy(&target_addr.sin_addr, target_host->h_addr_list[0], target_host->h_length);
        target_addr.sin_family = AF_INET;
        target_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (target_sockfd < 0)
        {   fprintf(stderr, "Can't create socket: %s\n", strerror(errno));
            return 1;
        }
        if (connect(target_sockfd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0)
        {
            fprintf(stderr, "Can't connect to %s: %s\n", target, strerror(errno));
            return 1;
        }
        target_out_fd = target_in_fd = target_sockfd;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    if (remote[0]) {
        struct hostent *remote_host;
        char *p = strchr(remote, ':');
        if (p)
        {   *p = '\0';
            remote_addr.sin_port = htons(atoi(p+1));
        }
        else
            remote_addr.sin_port = htons(DEFAULT_PORT);
        remote_host = gethostbyname(remote);
        if (remote_host == NULL)
        {   fprintf(stderr, "Can't resolve remote host %s\n", remote);
            return 1;
        }
        memcpy(&remote_addr.sin_addr, remote_host->h_addr_list[0], remote_host->h_length);
        remote_addr.sin_family = AF_INET;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    time_t last_sent, last_received;
    int packet_to_send = 0;
    char *packet_data;
    unsigned int keepalive_interval = KEEPALIVE_INTERVAL;
    unsigned int timeout = TIMEOUT;

    if (parse_args(argc, argv) != 0)
        return 1;

    openlog("udp-link", LOG_PID, LOG_DAEMON);

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
            FD_SET(target_in_fd, &fd_in);
            if (target_in_fd > maxfd)
                maxfd = target_in_fd;
        }
        if (buf_out.head != buf_out.tail && !shutdown_local)
        {
            FD_SET(target_out_fd, &fd_out);
            if (target_out_fd > maxfd)
                maxfd = target_out_fd;
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
        if (FD_ISSET(target_out_fd, &fd_out))
        {
            int n = write_buf(target_out_fd, &buf_out);
            if (n < 0)
            {
                syslog(LOG_ERR, "Can't write to target: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n == 0)
            {
                syslog(LOG_ERR, "target closed");
                buf_out.head = buf_out.tail = 0;
                shutdown_local = 1;
            }
        }
        if (FD_ISSET(target_in_fd, &fd_in))
        {
            int n = read(target_in_fd, packet_data, mtu);
            if (n > 0)
                packet_to_send = n;
            else if (n < 0)
            {
                syslog(LOG_ERR, "Can't read from target: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            else
            {
                syslog(LOG_INFO, "target closed");
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
