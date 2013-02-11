struct v6_frag {
	char		*buf;
	uint32_t	id;
	int		size;
	int 		count;
};

void process_ipv4_packet(char *buf, int len);
void process_ipv6_packet (char *buf, int len);
