void bitset_v6addr(struct in6_addr *v6addr, int num);
int bitcheck32(uint32_t target, int num);
int bitcheck16(uint16_t target, int num);
struct in6_addr generate_mapped_v6addr(struct in6_addr v6_rule_addr, struct in_addr v4_addr, uint16_t port);
void process_ipv4_packet(char *buf, int len);
void process_ipv6_packet (char *buf, int len);
void decap_packet(char *buf, int len);
void encap_packet(char *buf, int len);
