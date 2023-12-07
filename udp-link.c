#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <poll.h>
#include <sys/wait.h>
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
static int shutdown_local = 0, shutdown_remote = 0, killed = 0;
static int target_in_fd, target_out_fd;
static short local_port;
static struct timeval tv_start;
int debug = 0, dump = 0;
char *logfile = "syslog";

void usage(void)
{
    printf("Usage: udp-link [options] host [port]\n");
    printf("Options:\n");
    printf("  -t, --target=IP[:PORT]  target IP address and port, default 127.0.0.1:22\n");
    printf("  -b, --bind=PORT         bind to local port PORT, default %u-%u\n", LOCAL_PORT_MIN, LOCAL_PORT_MAX);
    printf("  -l, --log=FILE          log to FILE, default write_log\n");
    printf("  -h, --help              display this help and exit\n");
}

void sigpipe(int signo)
{
    write_log(LOG_ERR, "SIGPIPE received");
}

void sighup_handler(int signo)
{
    write_log(LOG_INFO, "SIGHUP received");
    shutdown_local = 1;
}

void signal_handler(int signo)
{
    static char signame[32] = "SIG";
    char *p;
    strncpy(signame+3, strsignal(signo), sizeof(signame)-4);
    for (p=signame+3; *p; p++)
        *p = toupper(*p);
    write_log(LOG_INFO, "%s received", signame);
    shutdown_local = 1;
    killed = signo;
    /* purge output buffer by signal */
    buf_sent.head = buf_sent.tail = 0;
}

char **split(char *str)
{
    static char *words[256];
    int i;

    for (i=0; i<sizeof(words)/sizeof(words[0])-1; i++)
    {
        while (str[0] && isspace(str[0]))
            *str++ = '\0';
        if (str[0] == '\0')
            break;
        words[i] = str;
        while (str[0] && !isspace(str[0]))
            str++;
    }
    words[i] = NULL;
    return words;
}

int parse_args(int argc, char *argv[])
{
    int c;
    char target[256]="", remote[256]="", rport[8];
    char *p;
    unsigned short local_port_min = LOCAL_PORT_MIN, local_port_max = LOCAL_PORT_MAX;
    struct option long_options[] = {
        {"target", required_argument, NULL, 't'},
        {"remote", required_argument, NULL, 'r'},
        {"bind",   required_argument, NULL, 'b'},
        {"debug",  no_argument,       NULL, 'd'},
        {"dump",   no_argument,       NULL, 'D'},
        {"log",    required_argument, NULL, 'l'},
        {"help",   no_argument,       NULL, 'h'},
        {0, 0, 0, 0 }
    };
    while ((c = getopt_long(argc, argv, "t:r:b:l:dDh", long_options, NULL)) != EOF)
    {
        switch (c)
        {
            case 't':   strncpy(target, optarg, sizeof(target)-1);
                        target[sizeof(target)-1] = '\0';
                        break;
            case 'r':   strncpy(remote, optarg, sizeof(remote)-1);
                        remote[sizeof(remote)-1] = '\0';
                        break;
            case 'b':   local_port_min = atoi(optarg);
                        if ((p=strchr(optarg, '-')) != 0)
                            local_port_max = atoi(p+1);
                        else
                            local_port_max = local_port_min;
                        break;
            case 'l':   logfile = optarg;
                        break;
            case 'D':   dump = 1;
            case 'd':   debug = 1;
                        break;
            case 'h':   usage();
                        return 1;
        }
    }
    argc -= optind;
    argv += optind;

    if (!argv[0])
    {
        usage();
        return 1;
    }
    if (local_port_max < local_port_min)
    {
        fprintf(stderr, "Invalid port range %u-%u\n", local_port_min, local_port_max);
        return 1;
    }
    srand(time(NULL) ^ getpid()); rand();
    if (strcmp(argv[0], "server") == 0)
    {
        unsigned short start_port;

        if (!argv[1])
        {   fprintf(stderr, "second parameter (key) required for server mode\n");
            return 1;
        }
        /* bind to free port and output it */
        start_port = rand()%(local_port_max-local_port_min+1) + local_port_min;
        for (local_port = start_port+1;; local_port++)
        {
            if (local_port > local_port_max)
                local_port = local_port_min;
            socket_fd = open_socket(local_port);
            if (socket_fd >= 0 || errno != EADDRINUSE)
                break;
            if (local_port == start_port)
                break;
        }
        if (socket_fd < 0)
        {   fprintf(stderr, "Can't bind to any port in range %d-%d: %s\n", local_port_min, local_port_max, strerror(errno));
            return 1;
        }

        fprintf(stdout, "%hu\n", local_port);
        fflush(stdout);
        key = atoi(argv[1]);
        if (daemon(0, 0) < 0)
        {   fprintf(stderr, "Error daemonizing: %s", strerror(errno));
            return 1;
        }
    }
    else if (strcmp(argv[0], "client") == 0)
    {
        if (!argv[1])
        {   fprintf(stderr, "second parameter (key) required for client mode\n");
            return 1;
        }
        key = atoi(argv[1]);
        local_port = local_port_min;
        socket_fd = open_socket(local_port);
        if (socket_fd < 0 || errno == EADDRINUSE)
        {   fprintf(stderr, "Can't bind to any port in range %d-%d\n", local_port_min, local_port_max);
            return 1;
        }
    }
    else
    {   /* generate random connection key, */
        /* make ssh connection to remote, run "udp-link server" there */
        /* then read port from the server and run local udp-link */
        FILE *new_stdin;
        int pipe_fd[2];
        int rc, i;
        pid_t pid;

        key = rand();
        rc = pipe(pipe_fd);
        if (rc < 0)
        {   fprintf(stderr, "Can't create pipe: %s\n", strerror(errno));
            return 1;
        }
        if ((pid=fork()))
        {
            char *str;
            close(pipe_fd[1]);
            new_stdin = fdopen(pipe_fd[0], "r");
            if (new_stdin == NULL)
            {   fprintf(stderr, "Can't fdopen(): %s\n", strerror(errno));
                return 1;
            }
            str = fgets(rport, sizeof(rport), new_stdin);
            fclose(new_stdin);
            waitpid(pid, &rc, 0);
            if (rc != 0 || str == NULL)
            {   fprintf(stderr, "ssh exited with code %d\n", rc);
                return 1;
            }
            if (debug) fprintf(stderr, "remote port: %s", rport);
        }
        else
        {
            char ssh_cmd[1024];
            char ** ssh_args;
            close(pipe_fd[0]);
            dup2(pipe_fd[1], fileno(stdout));
            close(pipe_fd[1]);
            snprintf(ssh_cmd, sizeof(ssh_cmd),
                "ssh %s-o ConnectTimeout=6 -o ServerAliveInterval=6 -o ServerAliveCountMax=1 -o ExitOnForwardFailure=yes -o ProxyCommand=none %s%s %s udp-link %s--target %s --bind %u-%u server %lu",
                debug ? "-v " : "",
                argv[1] ? "-p " : "", argv[1] ? argv[1] : "",
                argv[0], debug ? "--debug " : "", target[0] ? target : "127.0.0.1:22",
                local_port_min, local_port_max, key);
            if (debug) fprintf(stderr, "ssh_cmd: %s\n", ssh_cmd);
            new_stdin = fopen("/dev/null", "r");
            dup2(fileno(new_stdin), fileno(stdin));
            fclose(new_stdin);
            ssh_args = split(ssh_cmd);
            execvp("ssh", ssh_args);
            fprintf(stderr, "Can't run ssh: %s\n", strerror(errno));
            return 1;
        }

        target[0] = '\0';
        p = strchr(argv[0], '@');
        if (p)
            strncpy(remote, p+1, sizeof(remote)-1);
        else
            strncpy(remote, argv[0], sizeof(remote)-1);
        remote[sizeof(remote)-strlen(rport)-2] = '\0';
        strcat(remote, ":");
        strcat(remote, rport);
        for (i=0; i<8; i++)
        {
            local_port = 40000 + rand()%20000;
            socket_fd = open_socket(local_port);
            if (socket_fd >= 0)
                break;
        }
        if (socket_fd < 0)
        {   fprintf(stderr, "Can't bind to any port in range 40000-60000: %s\n", strerror(errno));
            return 1;
        }
    }
    if (target[0])
    {
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
        write_log(LOG_INFO, "TCP connected to %s %s:%hu", target, inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
    }
    else
    {
        target_in_fd = fileno(stdin);
        target_out_fd = fileno(stdout);
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    if (remote[0])
    {
        struct hostent *remote_host;
        char *p = strchr(remote, ':');
        if (p)
        {   *p = '\0';
            remote_addr.sin_port = htons(atoi(p+1));
        }
        else
            remote_addr.sin_port = htons(LOCAL_PORT_MIN);
        remote_host = gethostbyname(remote);
        if (remote_host == NULL)
        {   fprintf(stderr, "Can't resolve remote host %s\n", remote);
            return 1;
        }
        memcpy(&remote_addr.sin_addr, remote_host->h_addr_list[0], remote_host->h_length);
        remote_addr.sin_family = AF_INET;
        write_log(LOG_INFO, "Connecting to UDP %s %s:%hu", remote, inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
    }

    return 0;
}

unsigned int time_ms(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
    {   write_log(LOG_ERR, "Can't gettimeofday(): %s", strerror(errno));
        return 0;
    }
    if (tv.tv_sec < tv_start.tv_sec || (tv.tv_sec == tv_start.tv_sec && tv.tv_usec < tv_start.tv_usec))
    {   write_log(LOG_ERR, "Time went backwards");
        memcpy(&tv_start, &tv, sizeof(tv_start));
        return 0;
    }
    if (tv.tv_sec > tv_start.tv_sec + 30*24*3600)
    {   // We use 32-bit unsigned int for time_ms, so we can't handle more than 30 days
        int i;
        write_log(LOG_INFO, "Time went forward more than 30 days, restarting");
        memcpy(&tv_start, &tv, sizeof(tv_start));
        for (i=buf_sent.tail; i!=buf_sent.head; i=(i+1)%buf_sent.size)
            buf_sent.msgs[i].timestamp = 0;
        return 0;
    }
    if (tv.tv_usec >= tv_start.tv_usec)
        return (tv.tv_sec-tv_start.tv_sec)*1000 + (tv.tv_usec-tv_start.tv_usec)/1000;
    else
        return (tv.tv_sec-tv_start.tv_sec-1)*1000 + (tv.tv_usec+1000000-tv_start.tv_usec)/1000;
}

int main(int argc, char *argv[])
{
    time_t last_sent, last_received;
    int packet_to_send = 0;
    char *packet_data;
    unsigned int keepalive_interval = KEEPALIVE_INTERVAL;
    unsigned int timeout = TIMEOUT;
    unsigned int curtime;

    if (parse_args(argc, argv) != 0)
        return 1;

    open_log("udp-link", LOG_PID, LOG_DAEMON);

    buf_recv.size = buf_sent.size = BUFSIZE;
    buf_recv.msgs = malloc(buf_recv.size*sizeof(buf_recv.msgs[0]));
    buf_sent.msgs = malloc(buf_sent.size*sizeof(buf_sent.msgs[0]));
    buf_out.size = BUF2SIZE;
    buf_out.data = malloc(buf_out.size);
    packet_data = malloc(mtu);
    if (buf_recv.msgs==NULL || buf_sent.msgs==NULL || buf_out.data==NULL || packet_data==NULL)
    {   fprintf(stderr, "Can't malloc()\n");
        return 1;
    }
    buf_sent.head = buf_sent.tail = 0;
    buf_recv.head = buf_recv.tail = 0;
    buf_out.head  = buf_out.tail  = 0;

    sigaction(SIGPIPE, &(struct sigaction){.sa_handler=sigpipe, .sa_flags=SA_RESTART}, NULL);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGHUP,  sighup_handler);

    if (gettimeofday(&tv_start, NULL) < 0)
    {   write_log(LOG_ERR, "Can't gettimeofday(): %s", strerror(errno));
        return 1;
    }

    if (init_connection() != 0)
        return 3;

    curtime = last_sent = last_received = time_ms();

    while (1)
    {
        struct pollfd fds[3];
        int fds_out_ndx = target_in_fd == target_out_fd ? 1 : 2;
        int poll_timeout, resend_interval;
        int r;

        fds[0].fd = socket_fd;
        fds[0].events = 0;
        fds[1].fd = target_in_fd;
        fds[1].events = 0;
        fds[2].fd = target_out_fd;
        fds[2].events = 0;

        if (packet_to_send == 0 && (buf_sent.head+1)%buf_sent.size != buf_sent.tail && !shutdown_remote && !shutdown_local)
            fds[1].events |= POLLIN;
        if (buf_out.head != buf_out.tail && !shutdown_local)
            fds[fds_out_ndx].events |= POLLOUT;
        if ((buf_out.head+buf_out.size-buf_out.tail)%buf_out.size < buf_out.size-mtu && !shutdown_remote && !killed)
            /* we have space for at least one packet */
            fds[0].events |= POLLIN;
        /* Assume we always can write to socket */
        if (last_sent > curtime)
            last_sent = curtime;
        if (last_received > curtime)
            last_received = curtime;

        resend_interval = RESEND_INTERVAL;
        poll_timeout = keepalive_interval>=curtime-last_sent ? keepalive_interval-(curtime-last_sent) : 0;
        if (timeout)
        {
            int timeout_received = timeout>=curtime-last_received ? timeout-(curtime-last_received) : 0;
            poll_timeout = poll_timeout>timeout_received ? timeout_received : poll_timeout;
        }
        if (packet_to_send || buf_sent.head != buf_sent.tail)
        {
            unsigned int last_timestamp = buf_sent.head != buf_sent.tail ? buf_sent.msgs[buf_sent.head].timestamp : last_received;
            if (curtime > last_timestamp+PASSIVE_AFTER)
                resend_interval = RESEND2_INTERVAL;
            poll_timeout = poll_timeout>resend_interval ? resend_interval : poll_timeout;
        }
        r = poll(fds, fds_out_ndx+1, poll_timeout);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            write_log(LOG_ERR, "Can't poll: %s", strerror(errno));
            send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
            close(socket_fd);
            return 1;
        }
        curtime = time_ms();
        if (curtime > last_received+timeout)
        {
            write_log(LOG_ERR, "Timeout");
            send_msg(MSGTYPE_SHUTDOWN, REASON_TIMEOUT);
            return 1;
        }
        if (curtime > last_sent+keepalive_interval && !packet_to_send)
        {   send_msg(MSGTYPE_KEEPALIVE);
            last_sent = curtime;
        }
        if (fds[0].revents & POLLNVAL)
        {
            write_log(LOG_ERR, "invalid socket");
            shutdown_remote = 1;
            buf_sent.head = buf_sent.tail = 0;
        }
        if (fds[0].revents & POLLHUP)
        {
            write_log(LOG_ERR, "socket closed");
            shutdown_remote = 1;
            buf_sent.head = buf_sent.tail = 0;
        }
        if (fds[0].revents & POLLIN)
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
                if (msgtype == MSGTYPE_SHUTDOWN)
                {
                    shutdown_remote = 1;
                    buf_sent.head = buf_sent.tail = 0;
                }
            }
        }
        if ((fds[1].revents & POLLHUP) || (fds[fds_out_ndx].revents & POLLHUP))
        {
            write_log(LOG_INFO, "target closed (pollhup)");
            shutdown_local = 1;
        }
        else if ((fds[1].revents & POLLNVAL) || (fds[fds_out_ndx].revents & POLLNVAL))
        {
            write_log(LOG_ERR, "target invalid");
            send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
            shutdown_local = 1;
        }
        else if ((fds[fds_out_ndx].revents & POLLOUT) && !shutdown_local)
        {
            int n = write_buf(target_out_fd, &buf_out);
            if (n < 0)
            {
                write_log(LOG_ERR, "Can't write to target: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            if (n == 0)
            {
                write_log(LOG_INFO, "target closed (0 bytes wrote)");
                shutdown_local = 1;
            }
        }
        if (buf_sent.head != buf_sent.tail && buf_sent.msgs[(buf_sent.tail+buf_sent.size-1)%buf_sent.size].timestamp+resend_interval < curtime)
        {
            /* No confirmation for sent packets during resend_interval, resend */
            int n;
            for (n=buf_sent.tail; n!=buf_sent.head; n=(n+1)%buf_sent.size)
            {
                if (debug)
                    write_log(LOG_DEBUG, "Resend packet %u", buf_sent.msgs[n].seq);
                send_msg(MSGTYPE_DATA, buf_sent.msgs[n].seq, buf_sent.msgs[n].len, buf_sent.msgs[n].data);
                buf_sent.msgs[n].timestamp = curtime;
            }
            /* special case: if local end shutdowned, purge output, b/c connection to remote may be lost */
            if (shutdown_local)
                buf_sent.head = buf_sent.tail = 0;
        }
        if ((fds[1].revents & POLLIN) && !shutdown_local)
        {
            int n = read(target_in_fd, packet_data, mtu);
            if (n > 0)
            {
                if (dump)
                    write_log(LOG_DEBUG, "Receive data, len %u, data %s", n, dump_data(packet_data, n));
                else if (debug)
                    write_log(LOG_DEBUG, "Receive data, len %u", n);
                packet_to_send = n;
            }
            else if (n < 0)
            {
                write_log(LOG_ERR, "Can't read from target: %s", strerror(errno));
                send_msg(MSGTYPE_SHUTDOWN, REASON_ERROR);
                return 1;
            }
            else
            {
                write_log(LOG_INFO, "target closed (0 bytes read)");
                shutdown_local = 1;
            }
        }
        if (packet_to_send > 0)
        {
            int n = send_data(packet_data, packet_to_send);
            if (n < 0)
                // try later
                write_log(LOG_INFO, "Can't send_data: %s", strerror(errno));
            else
            {
                last_sent = curtime;
                packet_to_send = 0;
            }
        }
        if (killed)
        {
            send_msg(MSGTYPE_SHUTDOWN, REASON_KILLED);
            return 2;
        }
        if (shutdown_local && buf_sent.head == buf_sent.tail)
        {
            send_msg(MSGTYPE_SHUTDOWN, REASON_NORMAL);
            write_log(LOG_INFO, "Normal shutdown");
            return 0;
        }
        if (shutdown_remote && buf_out.head == buf_out.tail)
        {
            write_log(LOG_INFO, "Remote shutdown");
            return 0;
        }
    }
}
