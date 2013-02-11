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
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pthread.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>

#include "main.h"
#include "session.h"
#include "encapsulate.h"

/* manually configured params */
struct in_addr v4_rule_addr;
struct in6_addr v6_rule_addr;
struct in6_addr v6_br_addr;
int v6_rule_prefix = 0;
int v4_rule_prefix = 0;
int ea_len = 0;

/* manually configured params only in CE */
uint32_t ea = 0; /* equals set CE's IPv6 address with WAN interface */

/* automatically configured params */
int v4_suffix_len = 0;
int psid_len = 0;
int subnet_id_len = 0;

/* optionally configured params */
int mode = MAP_BR;
int a_bits = 4;
int subnet_id = 0;

struct v6_frag v6_frag;

struct mapping **inner_table;
struct mapping **outer_table;
struct mapping *mapping_table;

int tun_fd;
int raw_fd;
pthread_t thread_id_ttl;
pthread_mutex_t mutex_session_table = PTHREAD_MUTEX_INITIALIZER;
int syslog_facility = SYSLOG_FACILITY;
char *optarg;

void clean_up(int signal){
        close(tun_fd);
	close(raw_fd);
        exit (0);
}

void usage(){
	printf("\n");
	printf(" Usage:\n");
	printf("\tmap-e -6 [IPv6 rule prefix] -4 [IPv4 rule prefix] -b [BR address] -l [EA bits length] -e [EA bits] -m [MODE]\n");
	printf("\n");
	printf(" Example-1(CE):\n");
	printf("\tmap-e -6 2001:db8:0000::/40 -4 192.0.2.0/24 -b 2001:db8:ffff::1 -l 16 -e 0x1234 -m ce\n");
	printf("\n");
	printf(" Example-2(BR):\n");
	printf("\tmap-e -6 2001:db8:0000::/40 -4 192.0.2.0/24 -b 2001:db8:ffff::1 -l 16 -m br\n");
	printf("\n");
	printf(" Option:\n");
	printf("\t-6 : IPv6 rule prefix\n");
	printf("\t-4 : IPv4 rule prefix\n");
	printf("\t-b : BR address\n");
	printf("\t-l : EA bits length\n");
	printf("\t-e : EA bits (required when CE mode, HEX)\n");
	printf("\t-m : Mode(BR or CE)\n");
	printf("\t-s : Subnet-id(optional)\n");
	printf("\t-a : Offset bit length of restricted NAT port assign(optional)\n");
	printf("\t-d : Debug mode\n");
	printf("\t-h : Show this help\n");
	printf("\n");
	return;
}

int main(int argc, char *argv[]){
        char buf[2048];
        struct tun_pi *pi = (struct tun_pi *)buf;
	int read_len;
	char tun_name[] = DEV_NAME;
	int ether_type;
	int ch;
	int debug_mode = 0;
	char v4_pool_arg[255];
	char v6_pool_arg[255];

	int ipv6_configured = 0;
	int ipv4_configured = 0;
	int ea_len_configured = 0;
	int ea_configured = 0;
	int subnet_id_configured = 0;
	int br_addr_configured = 0;

	while ((ch = getopt(argc, argv, "dh6:4:b:e:l:s:a:m:")) != -1) {
		switch (ch) {
			case 'd' :
				debug_mode = 1;
				break;

			case '6' :
				strcpy(v6_pool_arg, strtok(optarg, "/"));
				v6_rule_prefix = atoi(strtok(NULL, ""));

				if (inet_pton(AF_INET6, v6_pool_arg, &v6_rule_addr) < 1){
					printf ("Invalid IPv6 prefix\n");
					return -1;
				}

				ipv6_configured = 1;

				break;

			case '4' :
				strcpy(v4_pool_arg, strtok(optarg, "/"));
                                v4_rule_prefix = atoi(strtok(NULL, ""));

				if(inet_pton(AF_INET, v4_pool_arg, &v4_rule_addr) < 1){
					printf("Invalid IPv4 prefix\n");
					return -1;
				}

				ipv4_configured = 1;

				break;

			case 'b' :
                                if(inet_pton(AF_INET6, optarg, &v6_br_addr) < 1){
                                        printf("Invalid BR address\n");
                                        return -1;
                                }

				br_addr_configured = 1;

				break;

			case 'e' :
                                if(sscanf(optarg, "%x", &ea) < 1){
                                        printf ("Invalid EA-bits configuration\n");
                                        return -1;
                                }
				ea_configured = 1;

				break;


			case 'l' : 
				if(sscanf(optarg, "%d", &ea_len) < 1){
					printf ("Invalid EA-bits length/IPv4 suffix length\n");
					return -1;
				}

				/* TBD: EA > 32 is not supported yet.
				EA would be 48 bits at most by Internet-Draft. */
				if(ea_len > 32 || ea_len < 0){
					printf ("Invalid EA-bits length/IPv4 suffix length\n");
					return -1;
				}

				if(ea_len + v4_rule_prefix <= 32){
					v4_suffix_len = ea_len;
					psid_len = 0;
				}else if(ea_len + v4_rule_prefix > 32){
					v4_suffix_len = 32 - v4_rule_prefix;
					psid_len = ea_len + v4_rule_prefix - 32;
				}

				ea_len_configured = 1;

				break;

			case 's' :
				if(sscanf(optarg, "%d", &subnet_id) < 1){
					printf("Invalid subnet-id\n");
					return -1;
				}

				subnet_id_configured = 1;
				break;

                        case 'a' :
                                if(sscanf(optarg, "%d", &a_bits) < 1){
                                        printf("Invalid offset bit length of restricted NAT port assign\n");
                                        return -1;
                                }
                                break;

			case 'm' :
				if(!strcmp(optarg, "br")){
					mode = MAP_BR;
				}else if(!strcmp(optarg, "ce")){
					mode = MAP_CE;
				}else{
					printf("Invalid Mode\n");
				}

				break;

			case 'h' :
				usage();
				return 0;

			default :
				usage();
				return -1;
		}
	}

	if((br_addr_configured & ipv4_configured & ipv6_configured & ea_len_configured) == 0){
		usage();
		return -1;
	}

	if(ea_len > 0 && !ea_configured && mode == MAP_CE){
		usage();
		return 1;
	}

	if(64 - (v6_rule_prefix + ea_len) > 0){
		subnet_id_len = 64 - (v6_rule_prefix + ea_len);
	}else{
		subnet_id_len = 0;
		if(subnet_id_configured){
			printf("End-User IPv6 prefix is larger than 64 bits\n");
			return 1;
		}
	}

	mapping_table = init_mapping_table();

        if ((tun_fd = tun_alloc (tun_name)) < 0){
		err(EXIT_FAILURE, "failt to tun_alloc");
	}

        if (tun_up (tun_name) < 0){
		err(EXIT_FAILURE, "failt to tun_up");
	}

        if((raw_fd = create_raw_socket()) < 0){
                err(EXIT_FAILURE, "fail to create raw socket");
        }

        if (signal (SIGINT, clean_up)  == SIG_ERR){
                err(EXIT_FAILURE, "failt to register SIGINT");
	}

        if(!debug_mode){
                if(daemon(0, 1) != 0){
                        err(EXIT_FAILURE, "fail to run as a daemon\n");
                }
        }

	/* start session ttl service */
        if (pthread_create(&thread_id_ttl, NULL, count_down_ttl, NULL) != 0 ){
                exit(1);
        }

	memset(&v6_frag, 0, sizeof(struct v6_frag));
        while ((read_len = read(tun_fd, buf, sizeof(buf))) >= 0){
                ether_type = ntohs(pi->proto);

                switch (ether_type) {
                	case ETH_P_IP :
                       		process_ipv4_packet(buf + sizeof(struct tun_pi), read_len - sizeof(struct tun_pi));
                       		break;
                	case ETH_P_IPV6 :
                       		process_ipv6_packet(buf + sizeof(struct tun_pi), read_len - sizeof(struct tun_pi));
                        	break;
                	default :
                        	break;
                }
        }

}

int create_raw_socket(){
        int fd;

        /* create Raw Socket */
        if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
                perror("rawsocket");
                return -1;
        }

        return fd;
}

int tun_alloc (char * dev){
	int fd;
	struct ifreq ifr;

	if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
		err (EXIT_FAILURE, 
		     "cannot create a control cahnnel of the tun intface.");

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_TUN;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0) {
		close (fd);
		err (EXIT_FAILURE, 
		     "cannot create %s interface.", dev);
	}

	return fd;

}

int tun_up (char * dev){
	int udp_fd;
	struct ifreq ifr;

	/* Make Tunnel interface up state */

	if ((udp_fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		err (EXIT_FAILURE,
		     "failt to create control socket of tun interface.");

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_UP;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (udp_fd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
		err (EXIT_FAILURE,
		     "failed to make %s up.", dev);
		close (udp_fd);
		return -1;
	}

	close (udp_fd);

	return 0;
}

int tun_set_af(void *buf, uint32_t af){
	assert(buf != NULL);

	uint16_t ether_type;

	switch(af) {
	case AF_INET:
		ether_type = ETH_P_IP;
		break;
	case AF_INET6:
		ether_type = ETH_P_IPV6;
		break;
	default:
		warnx("unsupported address family %d", af);
		return (-1);
	}

	struct tun_pi *pi = buf;
	pi->flags = 0;
	pi->proto = htons(ether_type);

	return (0);

	uint32_t *af_space = buf;

	*af_space = htonl(af);

	return (0);
}

void send_iovec(struct iovec *iov, int item_num){
	if(writev(tun_fd, iov, item_num) < 0){
		warn("writev failed");
	}
}

void send_raw(void *buf, int size, struct sockaddr *dst){
	if(sendto(raw_fd, buf, size, 0, dst, sizeof(struct sockaddr_in)) < 0){
		warn("sendto failed");
	}
}

void syslog_write(int level, char *fmt, ...){
        va_list args;
        va_start(args, fmt);

        syslog_open();
        vsyslog(level, fmt, args);
        syslog_close();

        va_end(args);
}

void syslog_open(){
    openlog(PROCESS_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

void syslog_close(){
    closelog();
}
