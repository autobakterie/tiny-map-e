#define SESSION_TTL 3
#define MTU 1500
#define MAX_SESSION 1000
#define MAXEVENTS 16
#define DEV_NAME "map-e"
#define PROCESS_NAME "map-e"
#define SYSLOG_FACILITY LOG_DAEMON
#define MAP_BR 0
#define MAP_CE 1

struct map_config {
	/* manually configured params */
	struct in_addr v4_rule_addr;
	struct in6_addr v6_rule_addr;
	struct in6_addr v6_br_addr;
	int v6_rule_prefix;
	int v4_rule_prefix;
	int ea_len;

	/* manually configured params only in CE */
	uint32_t ea;

	/* automatically configured params */
	int v4_suffix_len;
	int psid_len;
	int subnet_id_len;

	/* optionally configured params */
	int mode;
	int a_bits;
	int subnet_id;
};

int tun_set_af(void *buf, uint32_t af);
void send_iovec(struct iovec *iov, int item_num);
void send_raw(void *buf, int size, struct sockaddr *dst);
void syslog_write(int level, char *fmt, ...);

extern struct map_config config;
extern struct v6_frag v6_frag;
extern struct mapping **inner_table;
extern struct mapping **outer_table;
extern struct mapping *mapping_table;
extern int tun_fd;
extern int raw_fd;
extern char *optarg;

#define bitset128(target,num) (((uint32_t *)(target))[(num) / 32] |= (1 << 32 - ((num) % 32)))
#define bitcheck128(target,num) (((uint32_t *)(target))[(num) / 32] & (1 << 32 - ((num) % 32)))
#define bitcheck32(target,num) ((target) & (1 << 32 - (num)))
#define bitcheck16(target,num) ((target) & (1 << 16 - (num)))

#define ntoh128(target) \
	((uint32_t *)(target))[0] = ntohl(((uint32_t *)(target))[0]);\
	((uint32_t *)(target))[1] = ntohl(((uint32_t *)(target))[1]);\
	((uint32_t *)(target))[2] = ntohl(((uint32_t *)(target))[2]);\
	((uint32_t *)(target))[3] = ntohl(((uint32_t *)(target))[3]);

#define hton128(target) \
	((uint32_t *)(target))[0] = htonl(((uint32_t *)(target))[0]);\
	((uint32_t *)(target))[1] = htonl(((uint32_t *)(target))[1]);\
	((uint32_t *)(target))[2] = htonl(((uint32_t *)(target))[2]);\
	((uint32_t *)(target))[3] = htonl(((uint32_t *)(target))[3]);


