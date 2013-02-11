#define SESSION_TTL 3
#define MTU 1500
#define MAX_SESSION 1000
#define MAXEVENTS 16
#define DEV_NAME "map-e"
#define PROCESS_NAME "map-e"
#define SYSLOG_FACILITY LOG_DAEMON
#define MAP_BR 0
#define MAP_CE 1

struct v6_frag {
	char		*buf;
	uint32_t	id;
	int		size;
	int 		count;
};

void timer_set(int sec, int nsec);
int tun_alloc (char * dev);
int tun_up (char * dev);
int tun_set_af(void *buf, uint32_t af);
void send_iovec(struct iovec *iov, int item_num);
void syslog_write(int level, char *fmt, ...);
void syslog_open();
void syslog_close();

extern struct in_addr v4_rule_addr;
extern struct in6_addr v6_rule_addr;
extern struct in6_addr v6_br_addr;
extern int v6_rule_prefix;
extern int v4_rule_prefix;
extern int ea_len;
extern uint32_t ea;
extern int v4_suffix_len;
extern int psid_len;
extern int subnet_id_len;
extern int mode;
extern int a_bits;
extern int subnet_id;
extern struct v6_frag v6_frag;
extern struct mapping **inner_table;
extern struct mapping **outer_table;
extern struct mapping *mapping_table;
extern int tun_fd;
extern int raw_fd;
extern char *optarg;
