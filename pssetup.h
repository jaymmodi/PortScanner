/*
 * pssetup.h
 *
 *  Created on: Nov 2, 2014
 *      Author: vivek
 */

#ifndef PSSETUP_H_
#define PSSETUP_H_

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include<unistd.h>
#include <netdb.h>
#include <vector>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <map>
#include <algorithm>
#include <time.h>

#include </usr/include/netinet/ether.h>
#include </usr/include/netinet/ip.h>
#include </usr/include/netinet/ip6.h>
//#include </usr/include/netinet/tcp.h>
#include </usr/include/netinet/udp.h>
#include </usr/include/netinet/ip_icmp.h>
#include </usr/include/net/if_arp.h>
#include </usr/include/arpa/inet.h>
#include </usr/include/linux/if_ether.h>
#include </usr/include/pcap/bpf.h>
#include </usr/include/pcap/pcap.h>

using namespace std;

struct pseudo_tcpheader {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};
struct parseV {
	vector<char*> ipAddressList;
	vector<int> portsList;
	int noOfThreads = 1;
	int scanMethod[6] = { 0, 0, 0, 0, 0, 0 }; // SYN FIN XMAS NULL UDP ACK
	int noOfmethodsToScan;
};
//struct parseArgs parseValues;
struct differentJobs {
	char * ip;
	int port;
	string scanMethod;
};
struct activeJobs {
	char * ip;
	int port;
};
struct pseudo_udpheader {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};
/*struct displayOutput {
	int port;
	string result;
};*/


struct DNShdr {
	unsigned short id;       // identification number
	unsigned char rd :1;     // recursion desired
	unsigned char tc :1;     // truncated message
	unsigned char aa :1;     // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1;     // query/response flag
	unsigned char rcode :4;  // response code
	unsigned char cd :1;     // checking disabled
	unsigned char ad :1;     // authenticated data
	unsigned char z :1;      // its z! reserved
	unsigned char ra :1;     // recursion available
	unsigned short q_count;  // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
	char* qname;
	unsigned short qtype;
	unsigned short qclass;
};
struct tcphdr {
	__extension__
	union {
		struct {
			u_int16_t th_sport; /* source port */
			u_int16_t th_dport; /* destination port */
			u_int32_t th_seq; /* sequence number */
			u_int32_t th_ack; /* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int8_t th_x2 :4; /* (unused) */
			u_int8_t th_off :4; /* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
			u_int8_t th_off:4; /* data offset */
			u_int8_t th_x2:4; /* (unused) */
# endif
			u_int8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
			u_int16_t th_win; /* window */
			u_int16_t th_sum; /* checksum */
			u_int16_t th_urp; /* urgent pointer */
		};
		struct {
			u_int16_t source;
			u_int16_t dest;
			u_int32_t seq;
			u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int16_t res1 :4;
			u_int16_t doff :4;
			u_int16_t fin :1;
			u_int16_t syn :1;
			u_int16_t rst :1;
			u_int16_t psh :1;
			u_int16_t ack :1;
			u_int16_t urg :1;
			u_int16_t res2 :2;
# elif __BYTE_ORDER == __BIG_ENDIAN
			u_int16_t doff:4;
			u_int16_t res1:4;
			u_int16_t res2:2;
			u_int16_t urg:1;
			u_int16_t ack:1;
			u_int16_t psh:1;
			u_int16_t rst:1;
			u_int16_t syn:1;
			u_int16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
			u_int16_t window;
			u_int16_t check;
			u_int16_t urg_ptr;
		};
	};
};


class ps_setup {
public:

	ps_setup();
	virtual ~ps_setup();

	void parseargs(int argc, char **argv, struct parseV * parseValues);
	void printHelp();
	void generatePrefix(char* optarg, struct parseV * parseValues);
	void openFile(char* optarg, struct parseV * parseValues);
	void generatePorts(char* optarg, struct parseV * parseValues);
	char* checkValidIP(char * ipToScan, char* DotAddr);
	void display();

};

#endif /* PSSETUP_H_ */
