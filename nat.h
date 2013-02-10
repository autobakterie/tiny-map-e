struct pseudo_ipv4_header{
	struct in_addr	src_address,
			dst_address;
	uint8_t		ip_p_pad;
	uint8_t		ip_p_nxt;
	uint16_t	ip_p_len;
};

void process_nat_ptog(struct mapping *result, char *buf, int len);
void process_nat_gtop(struct mapping *result, char *buf, int len);
unsigned short ip4_transport_checksum(struct ip *ip, unsigned short *payload, int payloadsize);
unsigned short ip_checksum(unsigned short *buf, int size);
