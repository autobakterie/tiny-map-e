#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <linux/if_tun.h>
#include <syslog.h>

#include "main.h"
#include "session.h"
#include "encapsulate.h"
#include "nat.h"

void ntoh128(uint32_t *target){
	int i;
	for(i = 0; i < 128 / 32; i++){
		target[i] = ntohl(target[i]);
	}
}

void hton128(uint32_t *target){
	int i;
	for(i = 0; i < 128 / 32; i++){
		target[i] = htonl(target[i]);
	}
}

void bitset128(uint32_t *target, int num){
	int index = num / 32;
	uint32_t mask = 1 << 32 - (num % 32);
	target[index] |= mask;
}

int bitcheck128(uint32_t *target, int num){
	int index = num / 32;
	uint32_t mask = 1 << 32 - (num % 32);
	if(target[index] & mask){
		return 1;
	}else{
		return 0;
	}
}

int bitcheck32(uint32_t target, int num){
	int mask = 1 << 32 - num;
	if(target & mask){
		return 1;
	}else{
		return 0;
	}
}

int bitcheck16(uint16_t target, int num){
	int mask = 1 << 16 - num;
	if(target & mask){
		return 1;
	}else{
		return 0;
	}
}

struct in6_addr generate_mapped_v6addr(struct in6_addr v6_rule_addr, struct in_addr v4_addr, uint16_t port){
	struct in6_addr mapped_v6addr;
	struct in6_addr v6_rule_addr_h = v6_rule_addr;
	uint32_t v4addr = ntohl((uint32_t)v4_addr.s_addr);
	int offset = 0;
	uint16_t psid = ntohs(port);
	int i;

	memset(&mapped_v6addr, 0, sizeof(struct in6_addr));
	ntoh128((uint32_t *)&v6_rule_addr_h);
        psid = psid << a_bits;
        psid = psid >> 16 - psid_len;

        /* set interface-id
		If the End-user IPv6 prefix length is larger than 64,
   		the interface identifier is overwritten by the prefix.
	*/
	offset = v6_rule_prefix + ea_len + subnet_id_len + 16;

        for(i = 0; i < v4_rule_prefix; i++){
                if(bitcheck32(v4addr, i + 1)){
                        bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
                }
        }

        offset += v4_rule_prefix;

        for(i = 0; i < v4_suffix_len; i++){
                if(bitcheck32(v4addr, 32 - (v4_suffix_len - (i + 1)))){
                        bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
                }
        }

        offset += v4_suffix_len;

        for(i = 0; i < psid_len; i++){
                if(bitcheck16(psid, 16 - (psid_len - (i + 1)))){
                        bitset128((uint32_t *)&mapped_v6addr, offset + (16 - psid_len) + i + 1);
                }
        }


	/* set v6 rule address */
	offset = 0;

	for(i = 0; i < v6_rule_prefix; i++){
		if(bitcheck128((uint32_t *)&v6_rule_addr_h, i + 1)){
			bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
		}
	}


	offset += v6_rule_prefix;

	/* set v4suffix in EA bits */
	for(i = 0; i < v4_suffix_len; i++){
		if(bitcheck32(v4addr, 32 - (v4_suffix_len - (i + 1)))){
			bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
		}
	}

	offset += v4_suffix_len;

	/* set PSID in EA bits */
	for(i = 0; i < psid_len; i++){
		if(bitcheck16(psid, 16 - (psid_len - i - 1))){
			bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
		}
	}

	offset += psid_len;

	/* set subnet-id */
	for(i = 0; i < subnet_id_len; i++){
		if(bitcheck32(subnet_id, 32 - (subnet_id_len - i -1))){
			bitset128((uint32_t *)&mapped_v6addr, offset + i + 1);
		}
	}

	hton128((uint32_t *)&mapped_v6addr);
	return mapped_v6addr;
}

void process_ipv4_packet(char *buf, int len){
	struct ip *ip = (struct ip *)buf;
	struct icmp *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint16_t source_port = 0;
	struct mapping *result;

        if(ip->ip_p == IPPROTO_ICMP){
		icmp = (struct icmp *)(buf + sizeof(struct ip));
		source_port = icmp->icmp_id;
	}else if(ip->ip_p == IPPROTO_TCP){
		tcp = (struct tcphdr *)(buf + sizeof(struct ip));
		source_port = tcp->source;
	}else if(ip->ip_p == IPPROTO_UDP){
		udp = (struct udphdr *)(buf + sizeof(struct ip));
		source_port = udp->source;
	}else{
		return;
	}

	switch(mode){
		case MAP_BR:
			break;

		case MAP_CE:
        		if((result = search_mapping_table_inner(ip->ip_src, source_port)) != NULL){
                		reset_ttl(result);
                		process_nat_ptog(result, buf, len);
        		}else{
                		result = (struct mapping *)malloc(sizeof(struct mapping));
                		memset(result, 0, sizeof(struct mapping));

                		reset_ttl(result);
                		result->source_addr = ip->ip_src;
				result->source_port = source_port;
                		if(insert_new_mapping(result) < 0){
                        		return;
                		}

                		process_nat_ptog(result, buf, len);
        		}

			break;
	}
	encap_packet(buf, len);

	return;
}

void process_ipv6_packet (char *buf, int len){
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct ip6_frag *ip6f;
	char *tmp;
	int offset;

	if(ip6->ip6_nxt == IPPROTO_FRAGMENT){
		ip6f = (struct ip6_frag *)(buf + sizeof(struct ip6_hdr));

syslog_write(LOG_INFO, "id = %d\n", ntohl(ip6f->ip6f_ident));
		if((v6_frag.id != ip6f->ip6f_ident) && (v6_frag.buf != NULL)){
			/* previous reassembly has given up */
			free(v6_frag.buf);
			memset(&v6_frag, 0, sizeof(struct v6_frag));
		}

		if(v6_frag.buf == NULL){
			v6_frag.id = ip6f->ip6f_ident;
			v6_frag.buf = malloc(sizeof(struct ip6_hdr));
			v6_frag.size = sizeof(struct ip6_hdr);
			v6_frag.count = sizeof(struct ip6_hdr);
			memset(v6_frag.buf, 0, sizeof(struct ip6_hdr));
		}
			
		if(ip6f->ip6f_offlg & IP6F_MORE_FRAG){
			offset = ntohs(ip6f->ip6f_offlg & ~IP6F_MORE_FRAG);
		}else{
			offset = ntohs(ip6f->ip6f_offlg);
		}
syslog_write(LOG_INFO, "offset = %d\n", offset);

		if(v6_frag.size < sizeof(struct ip6_hdr) + offset + ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag)){
			tmp = realloc(v6_frag.buf, sizeof(struct ip6_hdr) + offset + ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag));
			if(tmp == NULL){
				return;
			}

			v6_frag.buf = tmp;
			v6_frag.size = sizeof(struct ip6_hdr) + offset + ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag);

syslog_write(LOG_INFO, "size = %d\n", v6_frag.size);
		}

		memcpy(v6_frag.buf + sizeof(struct ip6_hdr) + offset,
			buf + sizeof(struct ip6_hdr) + sizeof(struct ip6_frag), 
			ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag));
		v6_frag.count += ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag);
syslog_write(LOG_INFO, "count += %d\n", ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag));


		if(!(ip6f->ip6f_offlg & IP6F_MORE_FRAG)){
			if(v6_frag.size == v6_frag.count){
				decap_packet(v6_frag.buf, v6_frag.size);
syslog_write(LOG_INFO, "succeeded to reassemble size = %d, count = %d\n", v6_frag.size, v6_frag.count);
			}else{
				/* failed to reassemble fragmented packets */
syslog_write(LOG_INFO, "failed to reassemble size = %d, count = %d\n", v6_frag.size, v6_frag.count);
			}

			free(v6_frag.buf);
			memset(&v6_frag, 0, sizeof(struct v6_frag));
		}
	}else{
		decap_packet(buf, len);
	}
}

void decap_packet(char *buf, int len){
        struct ip *ip = (struct ip *)(buf + sizeof(struct ip6_hdr));
        struct icmp *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;
	uint16_t dest_port = 0;
	struct tun_pi pi;
	struct iovec iov[2];
	struct sockaddr_in dst;
        struct mapping *result;

        if(ip->ip_p == IPPROTO_ICMP){
                icmp = (struct icmp *)(buf + sizeof(struct ip6_hdr) + sizeof(struct ip));
                dest_port = icmp->icmp_id;
        }else if(ip->ip_p == IPPROTO_TCP){
                tcp = (struct tcphdr *)(buf + sizeof(struct ip6_hdr) + sizeof(struct ip));
                dest_port = tcp->dest;
        }else if(ip->ip_p == IPPROTO_UDP){
                udp = (struct udphdr *)(buf + sizeof(struct ip6_hdr) + sizeof(struct ip));
                dest_port = udp->dest;
        }else{
                return;
        }


	switch(mode){
		case MAP_BR:
			break;

		case MAP_CE:
                        if((result = search_mapping_table_outer(ip->ip_dst, dest_port)) != NULL){
                                reset_ttl(result);
                                process_nat_gtop(result, buf + sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr));

				/* Since NATed packet's source address is pysical interface's,
				bypass packet packet arrival to tun interface
				and directory sends it from pysical interface using raw socket. */
				memset(&dst, 0, sizeof(struct sockaddr_in));
				dst.sin_family = AF_INET;
				dst.sin_addr = ip->ip_dst;
				send_raw(buf + sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr), (struct sockaddr *)&dst);
			}

			return;

			break;
	}

        tun_set_af(&pi, AF_INET);
        iov[0].iov_base = &pi;
        iov[0].iov_len = sizeof(pi);
        iov[1].iov_base = buf + sizeof(struct ip6_hdr);
        iov[1].iov_len = len - sizeof(struct ip6_hdr);

        send_iovec(iov, 2);

	return;
}

void encap_packet(char *buf, int len){
	struct ip *ip = (struct ip *)buf;
	struct ip6_hdr ip6;
	struct ip6_frag ip6f;
        struct icmp *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;
	struct tun_pi pi;
	struct iovec iov[4];
	uint16_t dest_port;
	uint16_t src_port;

        if(ip->ip_p == IPPROTO_ICMP){
                icmp = (struct icmp *)(buf + sizeof(struct ip));
                dest_port = icmp->icmp_id;
		src_port = icmp->icmp_id;
        }else if(ip->ip_p == IPPROTO_TCP){
                tcp = (struct tcphdr *)(buf + sizeof(struct ip));
                dest_port = tcp->dest;
		src_port = tcp->source;
        }else if(ip->ip_p == IPPROTO_UDP){
                udp = (struct udphdr *)(buf + sizeof(struct ip));
                dest_port = udp->dest;
		src_port = udp->source;
        }else{
                return;
        }

	memset(&ip6, 0, sizeof(struct ip6_hdr));
	switch(mode){
		case MAP_BR:
			ip6.ip6_src = v6_br_addr;
			ip6.ip6_dst = generate_mapped_v6addr(v6_rule_addr, ip->ip_dst, dest_port);
			break;
		case MAP_CE:
			ip6.ip6_src = generate_mapped_v6addr(v6_rule_addr, ip->ip_src, src_port);
			ip6.ip6_dst = v6_br_addr;
			break;	
	}
char v6[255];
inet_ntop(AF_INET6, &(ip6.ip6_src), v6, sizeof(v6));
syslog_write(LOG_INFO, "generated v6 addr: %s\n", v6);
        if(sizeof(ip6) + len > MTU){
		int offset = 0;
		int frag_last = 0;
		uint32_t frag_id;


		srand(time(NULL));
		frag_id = rand();

		while(!frag_last){
			int frag_len = 0;

			if(len - 8 * offset
				> MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))){

				frag_len = (MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))) / 8 * 8;
			}else{
				frag_len = len - 8 * offset;
				frag_last = 1;
			}

			ip6.ip6_vfc = 0x60;
			ip6.ip6_plen = htons(frag_len + sizeof(struct ip6_frag));
			ip6.ip6_nxt =  IPPROTO_FRAGMENT;
			ip6.ip6_hlim = ip->ip_ttl;

			memset(&ip6f, 0, sizeof(struct ip6_frag));
			ip6f.ip6f_nxt = IPPROTO_IPIP;
			ip6f.ip6f_offlg = htons(offset * 8);
			ip6f.ip6f_ident = htonl(frag_id);

			if(!frag_last){
				ip6f.ip6f_offlg |= IP6F_MORE_FRAG;
			}

	        	tun_set_af(&pi, AF_INET6);

			iov[0].iov_base = &pi;
			iov[0].iov_len = sizeof(pi);
			iov[1].iov_base = &ip6;
			iov[1].iov_len = sizeof(ip6);
			iov[2].iov_base = &ip6f;
			iov[2].iov_len = sizeof(ip6f);
			iov[3].iov_base = buf + offset;
			iov[3].iov_len = frag_len;

			send_iovec(iov, 4);

			offset += frag_len / 8;
		}

		return;
	}

	ip6.ip6_vfc = 0x60;
	ip6.ip6_plen = htons(len);
	ip6.ip6_nxt = IPPROTO_IPIP;
	ip6.ip6_hlim = ip->ip_ttl;

	tun_set_af(&pi, AF_INET6);

	iov[0].iov_base = &pi;
	iov[0].iov_len = sizeof(pi);
	iov[1].iov_base = &ip6;
	iov[1].iov_len = sizeof(ip6);
	iov[2].iov_base = buf;
	iov[2].iov_len = len;

	send_iovec(iov, 3);
}

