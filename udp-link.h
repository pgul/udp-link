#include <sys/types.h>
#include <stdint.h>
#include <sys/time.h>

#define RESEND_INTERVAL    500     // ms
#define RESEND2_INTERVAL   10*1000 // 10 s
#define PASSIVE_AFTER      60*1000 // 1 min, decrease resend interval after this time
#define KEEPALIVE_INTERVAL 60*1000 // 1 min
#define TIMEOUT            18*3600*1000 // 18 hours
#define PING_TIMEOUT       1000    // ms
#define BUFSIZE            64      // sent packets waiting for YAK
#define BUF2SIZE           65536   // bytes, waiting for output to target stream
#define MTU                1400    // bytes
#define RESEND_INIT        500     // ms
#define TIMEOUT_INIT       5*1000  // ms
#define DATA_HEADER_SIZE   6       // bytes: magic(4), seq(2)
#define LOCAL_PORT_MIN     43200
#define LOCAL_PORT_MAX     44000
#define VERSION            2

#define MSGTYPE_INIT      0
#define MSGTYPE_INIT2     1
#define MSGTYPE_DATA      2
#define MSGTYPE_YAK       3 // Ox
#define MSGTYPE_NAK       4 // yak female
#define MSGTYPE_KEEPALIVE 5
#define MSGTYPE_SHUTDOWN  6
#define MSGTYPE_PING      7
#define MSGTYPE_PONG      8
#define MSGTYPE_NAK2      9
#define MSGTYPE_MAX       9

#define REASON_NORMAL  0
#define REASON_ERROR   1
#define REASON_TIMEOUT 2
#define REASON_KILLED  3

struct stored_msg {
    uint16_t seq;
    uint16_t len;
    unsigned int timestamp;
    unsigned int yak;
    char data[MTU];
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
    char *data;
} buffer_t;

int  open_socket(short port);
void close_socket(void);
int  send_msg(int socket_fd, int msgtype, ...);
int  send_data(char *data, int len);
int  write_buf(int fd, buffer_t *buffer);
int  read_msg(int *msgtype);
int  init_connection(void);
int  udp_ping(void);
unsigned int time_ms(void);
char *dump_data(char *buf, int len);

void write_log(int level, char *fmt, ...);
void open_log(char *name, int, int);

extern int socket_fd;
extern u_long key;
extern unsigned int mtu;
extern buffer_t buf_out;
extern buf_pkt_t buf_recv, buf_sent;
extern struct sockaddr_in remote_addr;
extern int debug, dump;
extern char *logfile;
