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
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/signalfd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/epoll.h>

#include "main.h"
#include "session.h"
#include "encapsulate.h"

static void usage();
static void timer_set(int sec, int nsec);
static int create_signal_fd();
static int create_raw_socket();
static int tun_alloc (char * dev);
static int tun_up (char * dev);
static void syslog_open();
static void syslog_close();

struct map_config config;
struct v6_frag v6_frag;

struct mapping **inner_table;
struct mapping **outer_table;
struct mapping *mapping_table;

int tun_fd;
int raw_fd;
int syslog_facility = SYSLOG_FACILITY;
char *optarg;

static void usage(){
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
        char buf[65535];
        struct tun_pi *pi = (struct tun_pi *)buf;
	int read_len;
	char tun_name[] = DEV_NAME;
	int ether_type;
	int ch;
	int debug_mode = 0;
	char v4_pool_arg[255];
	char v6_pool_arg[255];
	struct epoll_event ev, ev_ret[MAXEVENTS]; 
	int i, epfd, nfds;
	struct signalfd_siginfo siginfo;
	int signal_fd;

	int ipv6_configured = 0;
	int ipv4_configured = 0;
	int ea_len_configured = 0;
	int ea_configured = 0;
	int subnet_id_configured = 0;
	int br_addr_configured = 0;

	memset(&config, 0, sizeof(struct map_config));
	config.mode = MAP_BR;
	config.a_bits = 4;

	while ((ch = getopt(argc, argv, "dh6:4:b:e:l:s:a:m:")) != -1) {
		switch (ch) {
			case 'd' :
				debug_mode = 1;
				break;

			case '6' :
				strcpy(v6_pool_arg, strtok(optarg, "/"));
				config.v6_rule_prefix = atoi(strtok(NULL, ""));

				if (inet_pton(AF_INET6, v6_pool_arg, &(config.v6_rule_addr)) < 1){
					printf ("Invalid IPv6 prefix\n");
					return -1;
				}

				ipv6_configured = 1;

				break;

			case '4' :
				strcpy(v4_pool_arg, strtok(optarg, "/"));
                                config.v4_rule_prefix = atoi(strtok(NULL, ""));

				if(inet_pton(AF_INET, v4_pool_arg, &(config.v4_rule_addr)) < 1){
					printf("Invalid IPv4 prefix\n");
					return -1;
				}

				ipv4_configured = 1;

				break;

			case 'b' :
                                if(inet_pton(AF_INET6, optarg, &(config.v6_br_addr)) < 1){
                                        printf("Invalid BR address\n");
                                        return -1;
                                }

				br_addr_configured = 1;

				break;

			case 'e' :
                                if(sscanf(optarg, "%x", &(config.ea)) < 1){
                                        printf ("Invalid EA-bits configuration\n");
                                        return -1;
                                }
				ea_configured = 1;

				break;


			case 'l' : 
				if(sscanf(optarg, "%d", &(config.ea_len)) < 1){
					printf ("Invalid EA-bits length/IPv4 suffix length\n");
					return -1;
				}

				/* TBD: EA > 32 is not supported yet.
				EA would be 48 bits at most by Internet-Draft. */
				if(config.ea_len > 32 || config.ea_len < 0){
					printf ("Invalid EA-bits length/IPv4 suffix length\n");
					return -1;
				}

				if(config.ea_len + config.v4_rule_prefix <= 32){
					config.v4_suffix_len = config.ea_len;
					config.psid_len = 0;
				}else if(config.ea_len + config.v4_rule_prefix > 32){
					config.v4_suffix_len = 32 - config.v4_rule_prefix;
					config.psid_len = config.ea_len + config.v4_rule_prefix - 32;
				}

				ea_len_configured = 1;

				break;

			case 's' :
				if(sscanf(optarg, "%d", &(config.subnet_id)) < 1){
					printf("Invalid subnet-id\n");
					return -1;
				}

				subnet_id_configured = 1;
				break;

                        case 'a' :
                                if(sscanf(optarg, "%d", &(config.a_bits)) < 1){
                                        printf("Invalid offset bit length of restricted NAT port assign\n");
                                        return -1;
                                }
                                break;

			case 'm' :
				if(!strcmp(optarg, "br")){
					config.mode = MAP_BR;
				}else if(!strcmp(optarg, "ce")){
					config.mode = MAP_CE;
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

	if(config.ea_len > 0 && !ea_configured && config.mode == MAP_CE){
		usage();
		return 1;
	}

	if(64 - (config.v6_rule_prefix + config.ea_len) > 0){
		config.subnet_id_len = 64 - (config.v6_rule_prefix + config.ea_len);
	}else{
		config.subnet_id_len = 0;
		if(subnet_id_configured){
			printf("End-User IPv6 prefix is larger than 64 bits\n");
			return 1;
		}
	}

        if(!debug_mode){
                if(daemon(0, 1) != 0){
                        err(EXIT_FAILURE, "fail to run as a daemon\n");
                }
        }

	mapping_table = init_mapping_table();

	/* tun fd preparing */
        if ((tun_fd = tun_alloc (tun_name)) < 0){
		err(EXIT_FAILURE, "failt to tun_alloc");
	}

        if (tun_up (tun_name) < 0){
		err(EXIT_FAILURE, "failt to tun_up");
	}

	/* rawsocket fd preparing */
        if((raw_fd = create_raw_socket()) < 0){
                err(EXIT_FAILURE, "fail to create raw socket");
        }

	/* signal_fd preparing */
	if((signal_fd = create_signal_fd()) < 0){
		err(EXIT_FAILURE, "failt to create signal fd");
	}

        /* epoll fd preparing */
        if((epfd = epoll_create(MAXEVENTS)) < 0){
                err(EXIT_FAILURE, "failt to make epoll fd");
        }

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = tun_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) != 0){
		err(EXIT_FAILURE, "failt to register fd to epoll");
	}

        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = signal_fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, signal_fd, &ev) != 0){
                err(EXIT_FAILURE, "failt to register fd to epoll");
        }

	timer_set(60, 0);
	memset(&v6_frag, 0, sizeof(struct v6_frag));
        while(1){
		if((nfds = epoll_wait(epfd, ev_ret, MAXEVENTS, -1)) <= 0){
			err(EXIT_FAILURE, "Unexpected number of epoll arrived fd");
		}

		for(i = 0; i < nfds; i++){
			if(ev_ret[i].data.fd == tun_fd){
				read_len = read(tun_fd, buf, sizeof(buf));
				if(read_len <= 0){
					err(EXIT_FAILURE, "Unexpected size arrival of tun_fd");
				}

    				ether_type = ntohs(pi->proto);
    				switch (ether_type) {
     					case ETH_P_IP :
						process_ipv4_packet(buf + sizeof(struct tun_pi),
									read_len - sizeof(struct tun_pi));
               					break;
                			case ETH_P_IPV6 :
                       				process_ipv6_packet(buf + sizeof(struct tun_pi),
									read_len - sizeof(struct tun_pi));
                        			break;
                			default :
                        			break;
                		}
			}else if(ev_ret[i].data.fd == signal_fd){
				read_len = read(signal_fd, &siginfo, sizeof(struct signalfd_siginfo));
				if(read_len < sizeof(struct signalfd_siginfo)){
					err(EXIT_FAILURE, "Unexpected size arrival of siginfo");
				}

				if(siginfo.ssi_signo == SIGALRM){
					count_down_ttl();
				}else{
					err(EXIT_FAILURE, "Unexpected signal");
				}
			}

		}

        }

}

static void timer_set(int sec, int nsec){
	struct sigevent ev;  
	ev.sigev_notify = SIGEV_SIGNAL;  
	ev.sigev_signo  = SIGALRM;  
      
	struct itimerspec ts;  
	ts.it_value.tv_sec     = sec;  
	ts.it_value.tv_nsec    = nsec;  
	ts.it_interval.tv_sec  = sec;  
	ts.it_interval.tv_nsec = nsec;  
      
	timer_t timer_id;  
	timer_create(CLOCK_MONOTONIC, &ev, &timer_id);  
	timer_settime(timer_id, 0, &ts, 0);  

	return;
}  

static int create_raw_socket(){
        int fd;

        /* create Raw Socket */
        if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
                perror("rawsocket");
                return -1;
        }

        return fd;
}

static int create_signal_fd(){
        sigset_t sigmask;
        int signal_fd;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGALRM);

	if(sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1){
		perror("signalfd");
		return -1;
	}

	if((signal_fd = signalfd(-1, &sigmask, 0)) < 0){
		perror("signalfd");
		return -1;
	}

	return signal_fd;
}

static int tun_alloc (char * dev){
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

static int tun_up (char * dev){
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

static void syslog_open(){
    openlog(PROCESS_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

static void syslog_close(){
    closelog();
}
