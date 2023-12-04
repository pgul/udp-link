#include <sys/types.h>
#include <sys/time.h>

#define RESEND_INTERVAL    100     // ms
#define KEEPALIVE_INTERVAL 60      // s
#define TIMEOUT            18*3600 // 18 hours
#define BUFSIZE            64      // packets
#define BUF2SIZE           65536   // bytes
#define MTU                1400    // bytes
#define RESEND_INIT        100     // ms
#define TIMEOUT_INIT       5       // s
#define DATA_HEADER_SIZE   6       // bytes: magic(4), seq(2)
#define LOCAL_PORT_MIN     43200
#define LOCAL_PORT_MAX     44000

#define MSGTYPE_INIT      0
#define MSGTYPE_INIT2     1
#define MSGTYPE_DATA      2
#define MSGTYPE_YAK       3
#define MSGTYPE_NAK       4 // yak female
#define MSGTYPE_KEEPALIVE 5
#define MSGTYPE_SHUTDOWN  6

#define REASON_NORMAL  0
#define REASON_ERROR   1
#define REASON_TIMEOUT 2

#define LOG            "udp-link.log"
// #define LOG_STDOUT     1

struct stored_msg {
    unsigned short int seq;
    unsigned short int len;
    struct timeval timestamp;
    unsigned int yak;
    unsigned char data[MTU];
};
typedef struct buffer_pkt {
    unsigned int head;
    unsigned int tail;
    unsigned int size;
    unsigned int mtu;
    struct stored_msg *msgs;
} buf_pkt_t;

typedef struct buffer {
    unsigned int head;
    unsigned int tail;
    unsigned int size;
    unsigned char *data;
} buffer_t;

int  open_socket(short port);
void close_socket(void);
int  send_msg(int msgtype, ...);
int  send_data(char *data, int len);
int  write_buf(int fd, buffer_t *buffer);
int  read_msg(int *msgtype);
int  init_connection();

#ifdef LOG
#define syslog write_log
#define openlog open_log

void write_log(int level, char *fmt, ...);
void open_log(char *name, int, int);
#endif

extern int socket_fd;
extern u_long key;
extern unsigned int mtu;
extern buffer_t buf_out;
extern buf_pkt_t buf_recv, buf_sent;
extern struct sockaddr_in remote_addr;
