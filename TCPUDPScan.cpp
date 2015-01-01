/*
 * TCPUDPScan.cpp
 *
 *  Created on: Nov 15, 2014
 *      Author: jay
 */
#include "TCPUDPScan.h"

TCPUDPScan::TCPUDPScan() {
	// TODO Auto-generated constructor stub

}

TCPUDPScan::~TCPUDPScan() {
	// TODO Auto-generated destructor stub
}

void TCPUDPScan::generateChecksum(u_int16_t checksumValue, struct tcphdr*tcp,
		struct pseudo_tcpheader*psh) {
	int noOfwords = 0;
	int noOf16bitwords = 0;
	int noOfbytes = 0;
	u_int16_t word16bit = 0;
	u_int32_t sum = 0;
	char * ipFromList;

	// to calculate number of bytes in TCP header.
	noOfwords = tcp->th_off;
	noOfbytes = noOfwords * 4;
	noOf16bitwords = noOfwords * 2; // number of 16 bit words is equal to number of 32 words * 2
	//to convert TCP header to char * so that to get all bytes
	char * tcpHeaderToChar = (char *) tcp;

	// to form all 16 bit words from bytes
	for (int i = 0; i < noOfbytes; i = i + 2) {
		word16bit = (((unsigned int) tcpHeaderToChar[i] << 8) & 0xFF00)
				+ ((unsigned int) tcpHeaderToChar[i + 1] & 0xFF);
		sum = sum + (u_int32_t) word16bit;
	}
	// add pseudo tcp header in actual sum
	//generatePseudoTCPHeader(psh, dPort, ipFromList);
	char * pseudoHeaderToChar = (char *) psh;
	for (int i = 0; i < sizeof(struct pseudo_tcpheader); i = i + 2) {
		word16bit = (((unsigned int) pseudoHeaderToChar[i] << 8) & 0xFF00)
				+ ((unsigned int) pseudoHeaderToChar[i + 1] & 0xFF);
		sum = sum + (u_int32_t) word16bit;
	}

	// to add carry of 32 bit sum to itself.. as we need 1's complement of sum
	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
// again 1's complement.. this is checksum
	sum = ~sum;

	checksumValue = (u_int16_t) sum;

	tcp->check = htons(checksumValue);
}

void TCPUDPScan::generateTCPHeader(struct tcphdr* tcp, int sPort, int dPort) {

	//TCP Header

	tcp->th_sport = htons(sPort);
	tcp->th_dport = htons(dPort);
	tcp->th_seq = 0;
	tcp->ack_seq = 0;
	tcp->th_off = 5;  //offset = tcp header size without options 5x4=20bytes
	tcp->fin = 0;
	tcp->syn = 0;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->th_win = htons(5840); //Assume 32 Byte Window
	tcp->check = 0; //Zeroed out will be filled by checksum function
	tcp->urg_ptr = 0;

}

void TCPUDPScan::generatePseudoTCPHeader(struct pseudo_tcpheader* psh,
		int dPort, char* ipFromList) {

	//Now the TCP checksum
	char myIP[16];
	memset(&myIP, '\0', sizeof(myIP));
	whatsMyIP(myIP);
	psh->source_address = inet_addr(myIP);

	struct sockaddr_in destSockAddr;

	memset(&destSockAddr, '\0', sizeof(destSockAddr));

	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_port = dPort;
	destSockAddr.sin_addr.s_addr = inet_addr(ipFromList);
	psh->dest_address = destSockAddr.sin_addr.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(sizeof(struct tcphdr));
}

void TCPUDPScan::whatsMyIP(char* myIP) {
	int sockfd;
	struct sockaddr_in openDnsSockStruct;
	memset(&openDnsSockStruct, 0, sizeof(openDnsSockStruct));
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		cout << "Socket Initialization Failed" << endl;
	}
	openDnsSockStruct.sin_family = AF_INET;
	openDnsSockStruct.sin_addr.s_addr = inet_addr("208.67.222.222");
	openDnsSockStruct.sin_port = htons(53);

	if (connect(sockfd, (const struct sockaddr*) &openDnsSockStruct,
			sizeof(openDnsSockStruct)) == -1) {
		cout << "Connect WhatsMyIp Failed" << endl;
	}

	struct sockaddr_in DnsSockName;
	socklen_t DnsSockNameLen = sizeof(struct sockaddr_in);
	if (getsockname(sockfd, (struct sockaddr*) &DnsSockName, &DnsSockNameLen)
			== -1) {
		cout << "WhatsMyIP GetSockName Failed" << endl;
	}

	inet_ntop(AF_INET, &DnsSockName.sin_addr, myIP, 16);
	close(sockfd);
}

void TCPUDPScan::scanTCPport(char* ipToScan, int portToScan,
		string scanMethod) {
	u_int16_t checksumValue = 0;
	int sPort = 8000;
	struct sockaddr packetFrom;
	char packet[200];
	char DotAddr[15];
	string flagToSet = scanMethod;

	/*struct sockaddr_in sa;

	 if (inet_pton(AF_INET, ipToScan, &(sa.sin_addr))) {
	 sprintf(DotAddr, "%s", ipToScan);
	 } else if (gethostbyname(ipToScan) != NULL) {
	 struct hostent * h_ent_file;
	 h_ent_file = gethostbyname(ipToScan);
	 struct in_addr**addr_list_file =
	 (struct in_addr**) h_ent_file->h_addr_list;
	 sprintf(DotAddr, "%s", inet_ntoa(*addr_list_file[0]));
	 } else {
	 cout << "Wrong ip address" << '\t' << ipToScan << endl;
	 return;  							//return or pthread exit not sure
	 }
	 */
	sprintf(DotAddr, "%s", ipToScan);
	struct tcphdr tcp;
	memset(&tcp, 0, sizeof(tcphdr));
	struct pseudo_tcpheader psh;
	memset(&psh, 0, sizeof(pseudo_tcpheader));
	struct sockaddr_in destHost;
	destHost.sin_family = AF_INET;

	destHost.sin_port = htons(portToScan);

	inet_aton(DotAddr, &destHost.sin_addr);
	// to create tcp header with checksum value as 0
	//ALl flags intitislized to zero
	//Flag=1 syn analysis
	//Flag=2 NULL FIN XMAS
	//Flag=3 ACK
	int AnalysisFlag = 0;
	generateTCPHeader(&tcp, sPort, portToScan);
	if (flagToSet.compare("SYN") == 0) {
		AnalysisFlag = 1;
		tcp.syn = 1;
	} else if (flagToSet.compare("FIN") == 0) {
		AnalysisFlag = 2;
		tcp.fin = 1;
	} else if (flagToSet.compare("XMAS") == 0) {
		AnalysisFlag = 2;
		tcp.psh = 1;
		tcp.urg = 1;
		tcp.fin = 1;
	} else if (flagToSet.compare("ACK") == 0) {
		AnalysisFlag = 3;
		tcp.ack = 1;
	} else if (flagToSet.compare("NULL") == 0) {
		AnalysisFlag = 2;
	}

	//to create pseudo tcp header for checksum
	generatePseudoTCPHeader(&psh, portToScan, DotAddr);
	generateChecksum(checksumValue, &tcp, &psh);
	//logic to send to port
	int sendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
// send TCP packet
	//sendTCPPacket(sendSocket, &tcp, &destHost);
	socklen_t len = sizeof(destHost);
	struct pollfd fds[2];
	int recvTCPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	int recvICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	fcntl(recvTCPSocket, F_SETFL, O_NONBLOCK);
	fcntl(recvICMPSocket, F_SETFL, O_NONBLOCK);
	//int timeOut = 4000;
	int countForTimeOut = 3;
	bool tcpPacket = false;
	bool icmpPacket = false;

	fds[0].fd = recvTCPSocket;
	fds[0].events = 0;
	fds[0].events |= POLLIN;

	fds[1].fd = recvICMPSocket;
	fds[1].events = 0;
	fds[1].events |= POLLIN;

	char IP[15];
	int portfromPacket = 0;

	int check;
	char ipAddressToChar[15];
	bool timeoutCheck = false;
	double timeOut = 4;
	int pollCheck;	// = poll(fds, 2, 4000);

	double differenceInTime = 0;
	int bytesRecvd = 0;
	do {
		time_t beforeTimeout = time(0);
		countForTimeOut--;
		sendTCPPacket(sendSocket, &tcp, &destHost);
		pollCheck = poll(fds, 2, 4000);
		while (pollCheck == 1) {
			time_t inLoopTime = time(0);
			double difference = difftime(inLoopTime, beforeTimeout);
			if (difference > timeOut) {
				timeoutCheck = true;
				break;
			}
			if (fds[0].revents & POLLIN) {
				//timeoutCheck = false;
				//pthread_mutex_lock(&recvMutex);
				//tcpPacket = true;
				//icmpPacket = false;
				bytesRecvd = recvfrom(recvTCPSocket, packet, 200, 0,
						(struct sockaddr*) &destHost, &len);
				if (bytesRecvd < 0) {

					//cout << "Receive Error In TCP" << endl;
					//cout << errno << endl;
					//exit(1);
				}
				//pthread_mutex_unlock(&recvMutex);

			}
			if (fds[1].revents & POLLIN) {
				//pthread_mutex_lock(&recvMutex);
				//timeoutCheck = false;
				//icmpPacket = true;
				//tcpPacket= false;
				bytesRecvd = recvfrom(recvICMPSocket, packet, 200, 0,
						(struct sockaddr*) &destHost, &len);
				if (bytesRecvd < 0) {

					//cout << "Receive Error In ICMP" << endl;
					//exit(1);
				}
				//pthread_mutex_unlock(&recvMutex);
			}

			if (bytesRecvd > 0) {
				if (packet != NULL) {
					getIPfromPacket(packet, IP);
					portfromPacket = getPortfromPacket(packet); // true = tcp
					memset(ipAddressToChar, '\0', sizeof(ipAddressToChar));
					strcpy(ipAddressToChar, DotAddr);
					if ((strcmp(IP, ipAddressToChar) == 0
							&& (portfromPacket == portToScan))) {

						timeoutCheck = false;
						break;
					}
				}
			}

		}

	} while (timeoutCheck && countForTimeOut > 0);

	struct iphdr* ip_head = (struct iphdr*) packet;
	if (ip_head->protocol == IPPROTO_TCP) {

		tcpPacket = true;
	} else if (ip_head->protocol == IPPROTO_ICMP) {
		icmpPacket = true;
	}
	/*do {
	 //tcpPacket = false;
	 //icmpPacket = false;
	 if (!timeoutCheck) {
	 usleep(4000000);
	 }
	 //	int pollCheck = poll(fds, 2, timeOut);
	 countForTimeOut--;
	 memset(IP, '\0', 15);
	 if (pollCheck < 0) {
	 cout << "Error in Polling" << endl;
	 cout << "Error No :" << "\t" << errno << endl;
	 } else if (pollCheck == 0) {
	 timeoutCheck = true;
	 cout << "Timeout. No response" << endl;

	 sendTCPPacket(sendSocket, &tcp, &destHost);

	 } else {
	 if (fds[0].revents & POLLIN) {
	 timeoutCheck = false;
	 pthread_mutex_lock(&recvMutex);
	 tcpPacket = true;
	 int bytesRecvdTCP = recvfrom(recvTCPSocket, packet, 200, 0,
	 (struct sockaddr*) &destHost, &len);
	 if (bytesRecvdTCP < 0) {

	 cout << "Receive Error In TCP" << endl;
	 cout << errno << endl;
	 //exit(1);
	 }
	 pthread_mutex_unlock(&recvMutex);

	 }
	 if (fds[1].revents & POLLIN) {
	 pthread_mutex_lock(&recvMutex);
	 timeoutCheck = false;
	 icmpPacket = true;
	 int bytesRecvdICMP = recvfrom(recvICMPSocket, packet, 200, 0,
	 (struct sockaddr*) &destHost, &len);
	 if (bytesRecvdICMP < 0) {

	 cout << "Receive Error In ICMP" << endl;
	 //exit(1);
	 }
	 pthread_mutex_unlock(&recvMutex);
	 }

	 }
	 memset(ipAddressToChar, '\0', sizeof(ipAddressToChar));
	 strcpy(ipAddressToChar, DotAddr);
	 if (packet != NULL) {
	 getIPfromPacket(packet, IP);
	 portfromPacket = getPortfromPacket(packet, true); // true = tcp
	 }

	 } while ((strcmp(IP, ipAddressToChar) != 0 || (portfromPacket != portToScan))
	 && countForTimeOut >= 0);
	 */
	if (icmpPacket) {
		icmpAnalysis(packet, DotAddr, portToScan, flagToSet); // 0 - filtered port    1- do more Syn analysis 2-xmas fin null 3-ack
	} else if (tcpPacket && countForTimeOut > 0 && AnalysisFlag == 1) {
		synAnalysis(packet, portToScan, DotAddr, AnalysisFlag);
	} else if (countForTimeOut <= 0 && AnalysisFlag == 1) {
		synAnalysis(packet, portToScan, DotAddr, 0);
	} else if (tcpPacket && countForTimeOut >= 0 && AnalysisFlag == 2) {
		nullxmasfinAnalysis(packet, portToScan, DotAddr, AnalysisFlag);
	} else if (countForTimeOut < 0 && AnalysisFlag == 2) {
		nullxmasfinAnalysis(packet, portToScan, DotAddr, 0);
	} else if (tcpPacket && countForTimeOut >= 0 && AnalysisFlag == 3) {
		ackAnalysis(packet, portToScan, DotAddr, AnalysisFlag);
	} else if (countForTimeOut < 0 && AnalysisFlag == 3) {
		ackAnalysis(packet, portToScan, DotAddr, 0);
	}

	close(sendSocket);
	close(recvICMPSocket);
	close(recvTCPSocket);

}

void TCPUDPScan::generateChecksumUDP(u_int16_t checksumValue,
		struct udphdr* udp, struct pseudo_udpheader* psh) {

	int noOfbytes = 0;
	u_int16_t word16bit = 0;
	u_int32_t sum = 0;
	char * ipFromList;
	//cout << "Inside checksum UDP" << endl;

// to calculate number of bytes in TCP header.
	noOfbytes = sizeof(struct udphdr);
//to convert TCP header to char * so that to get all bytes
	char * tcpHeaderToChar = (char *) udp;

// to form all 16 bit words from bytes
	for (int i = 0; i < noOfbytes; i = i + 2) {
		word16bit = (((unsigned int) tcpHeaderToChar[i] << 8) & 0xFF00)
				+ ((unsigned int) tcpHeaderToChar[i + 1] & 0xFF);
		sum = sum + (u_int32_t) word16bit;
	}
// add pseudo tcp header in actual sum
//generatePseudoTCPHeader(psh, dPort, ipFromList);
	char * pseudoHeaderToChar = (char *) psh;
	for (int i = 0; i < sizeof(struct pseudo_udpheader); i = i + 2) {
		word16bit = (((unsigned int) pseudoHeaderToChar[i] << 8) & 0xFF00)
				+ ((unsigned int) pseudoHeaderToChar[i + 1] & 0xFF);
		sum = sum + (u_int32_t) word16bit;
	}

// to add carry of 32 bit sum to itself.. as we need 1's complement of sum
	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
// again 1's complement.. this is checksum
	sum = ~sum;

	checksumValue = (u_int16_t) sum;

	udp->check = htons(checksumValue);
}

void TCPUDPScan::generateUDPHeader(struct udphdr* udph, int sPort, int dPort) {
	udph->source = htons(sPort);
	udph->dest = htons(dPort);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0; 				//filled pseudo header

}

void TCPUDPScan::generatePseudoUDPHeader(struct pseudo_udpheader* psh,
		int dPort, char* ipFromList) {
//Now the UDP checksum
	char myIP[16];
	memset(&myIP, '\0', sizeof(myIP));
	whatsMyIP(myIP);
	psh->source_address = inet_addr(myIP);

	struct sockaddr_in destSockAddr;

	memset(&destSockAddr, '\0', sizeof(destSockAddr));

	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_port = dPort;
	destSockAddr.sin_addr.s_addr = inet_addr(ipFromList);
	psh->dest_address = destSockAddr.sin_addr.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_UDP;
	psh->udp_length = htons(sizeof(struct udphdr));
}
void TCPUDPScan::checkServices(char* ipToScan, int portToScan) {

	/*
	 struct sockaddr_in checkServ;
	 memset(&checkServ, '\0', sizeof(checkServ));
	 checkServ.sin_family = AF_INET;
	 checkServ.sin_port = htons(portToScan);
	 checkServ.sin_addr.s_addr = inet_addr(ipToScan);

	 int sockFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	 if (sockFD < 0) {
	 cout << "SocketFD initialization for Services Failed" << endl;
	 }
	 if (connect(sockFD, (struct sockaddr *) &checkServ, sizeof(checkServ))
	 < 0) {
	 cout << "Connect failed"<< endl;
	 }

	 switch (portToScan) {
	 case 80: {
	 char getRequest[50] = "GET / HTTP/1.1\n\n";
	 string::size_type found;
	 send(sockFD, getRequest, strlen(getRequest), 0);
	 char getResponse[1024]; //Took a random guess googles header 758 char long
	 if (recv(sockFD, getResponse, 1024, 0) > 0) {
	 string recvdResponse(getResponse);
	 //cout<<getResponse;
	 if (recvdResponse.find("server:") == string::npos) {
	 cout << "Dont Know Server Version";
	 } else {
	 char buffer[13];
	 memset(buffer, '\0', sizeof(buffer));
	 string recvdResponse(getResponse);
	 if ((found = recvdResponse.find("server:")) != string::npos) {
	 recvdResponse.copy(buffer, 13,
	 found + strlen("Version") + 1);
	 char reutrnversn[20];
	 memset(reutrnversn, '\0', 20);
	 sprintf(reutrnversn, "HTTP Server: %s", buffer);
	 cout << reutrnversn << endl;
	 }
	 }

	 }
	 break;
	 }
	 case 22: {
	 char sshRequest[7] = "";
	 send(sockFD, sshRequest, strlen(sshRequest), 0);
	 char sshResponse[1024]; //Took a random guess googles header 758 char long
	 int countBytes = recv(sockFD, sshResponse, 1024, 0);
	 if (countBytes > 0) {
	 string recvdResponse(sshResponse);
	 cout << recvdResponse;
	 }
	 break;
	 }
	 case 24:
	 case 25:
	 case 587: {
	 char smtpRequest[15] = "EHLO\n";
	 send(sockFD, smtpRequest, strlen(smtpRequest), 0);
	 char smtpResponse[200]; //Took a random guess smtp googles header 758 char long
	 if (recv(sockFD, smtpResponse, 200, 0) > 0) {
	 string recvdResponse(smtpResponse);
	 if (recvdResponse.find("250") != string::npos) {
	 cout << "ESMTP";
	 } else {
	 cout << "SMTP";
	 }
	 }
	 break;
	 }
	 case 43: {
	 std::string::size_type found;
	 char whoisRequest[50] = "www.soic.indiana.edu\r\n";
	 send(sockFD, whoisRequest, strlen(whoisRequest), 0);
	 char whoisResponse[1024]; //Took a random guess smtp googles header 758 char long
	 if (recv(sockFD, whoisResponse, 1024, 0) > 0) {
	 char buffer[5];
	 memset(buffer, '\0', sizeof(buffer));
	 string recvdResponse(whoisResponse);
	 //cout<<recvdResponse;
	 if ((found = recvdResponse.find("Version")) != string::npos) {
	 recvdResponse.copy(buffer, 4, found + strlen("Version") + 1);
	 char reutrnversn[20];
	 memset(reutrnversn, '\0', 20);
	 sprintf(reutrnversn, "WHOIS Version: %s", buffer);
	 cout << reutrnversn;
	 } else {
	 cout << "Unknown WHOIS Version";
	 }
	 }
	 break;
	 }
	 case 110: {
	 std::string::size_type found;
	 int countBytes = 0;
	 char popRequest[20] = "\r\n";
	 send(sockFD, popRequest, strlen(popRequest), 0);
	 char popResponse[200]; //Took a random guess smtp googles header 758 char long
	 if (recv(sockFD, popResponse, 200, 0) > 0) {
	 string recvdResponse(popResponse);
	 if ((found = recvdResponse.find("+OK")) != string::npos) {
	 cout << "POP Active";
	 }
	 }
	 break;
	 }
	 case 143: {
	 std::string::size_type found;
	 int countBytes = 0;
	 char imapRequest[20] = "\r\n";
	 send(sockFD, imapRequest, strlen(imapRequest), 0);
	 char imapResponse[1024]; //Took a random guess smtp googles header 758 char long
	 if (recv(sockFD, imapResponse, 1024, 0) > 0) {
	 char buffer[20];
	 memset(buffer, '\0', sizeof(buffer));
	 string recvdResponse(imapResponse);
	 if ((found = recvdResponse.find("IMAP")) != string::npos) {
	 recvdResponse.copy(buffer, 10, found);
	 char reutrnversn[50];
	 memset(reutrnversn, '\0', sizeof(reutrnversn));
	 sprintf(reutrnversn, "IMAP Version: %s", buffer);
	 cout << reutrnversn;
	 }
	 }
	 break;
	 }
	 default:
	 cout << "UnKown Service";
	 }
	 close(sockFD);*/
}
void TCPUDPScan::scanUDPport(char* ipToScan, int portToScan) {
	u_int16_t checksumValue = 0;
	int sPort = 8000;
	struct sockaddr packetFrom;
	char packet[1024];
	char DotAddr[100];
	int sendSocketUDP = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

	sprintf(DotAddr, "%s", ipToScan);
//init dest soctcpkaddr
	struct udphdr udp;
	memset(&udp, 0, sizeof(udphdr));
	struct pseudo_udpheader psh;
	memset(&psh, 0, sizeof(pseudo_udpheader));
	struct sockaddr_in destHost;
	char buf[65536];
	memset(buf, '\0', sizeof(buf));
	destHost.sin_family = AF_INET;

	destHost.sin_port = htons(portToScan);

	inet_aton(DotAddr, &destHost.sin_addr);
	if (portToScan == 53) {
		struct udphdr *udp = (struct udphdr *) buf;
		// to create tcp header with checksum value as 0
		generateUDPHeader(udp, sPort, portToScan);

		//to create pseudo tcp header for checksum
		generatePseudoUDPHeader(&psh, portToScan, DotAddr);

		struct DNShdr *dns = (struct DNShdr *) (buf + sizeof(struct udphdr));
		dns->id = (unsigned short) htons(getpid());
		dns->qr = 0; //This is a query
		dns->opcode = 0; //This is a standard query
		dns->aa = 0; //Not Authoritative
		dns->tc = 0; //This message is not truncated
		dns->rd = 0; //Recursion Desired
		dns->ra = 0; //Recursion not available! hey we dont have it (lol)
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only 1 question
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;
		dns->qname = '\0';
		dns->qclass = htons(1);
		dns->qtype = htons(1);

		udp->len = htons(sizeof(struct udphdr) + sizeof(struct DNShdr));
		psh.udp_length = htons(sizeof(struct udphdr) + sizeof(struct DNShdr));
		generateChecksumUDP(checksumValue, (struct udphdr *) buf, &psh);
		udp->check = checksumValue;

		/*sendUDPPacket(sendSocketUDP, buf, &destHost,
		 sizeof(struct udphdr) + sizeof(struct DNShdr));*/

	} else {

		char* data = buf + sizeof(struct udphdr);
		strcpy(data, "RandomJunkPayload");
		// to create tcp header with checksum value as 0
		struct udphdr *udp = (struct udphdr *) buf;
		generateUDPHeader(udp, sPort, portToScan);

		//to create pseudo tcp header for checksum
		generatePseudoUDPHeader(&psh, portToScan, DotAddr);
		udp->len = htons(sizeof(struct udphdr) + strlen(data));
		psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));
		generateChecksumUDP(checksumValue, udp, &psh);
		udp->check = checksumValue;
		cout << ntohs(destHost.sin_port) << endl;
		cout << inet_ntoa(destHost.sin_addr) << endl;
		//logic to send to port

		/*sendUDPPacket(sendSocketUDP, buf, &destHost,
		 sizeof(struct udphdr) + strlen("RandomJunkPayload"));*/
	}
	socklen_t len = sizeof(destHost);
	struct pollfd fds[2];
	int recvUDPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	int recvUDPICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	fcntl(recvUDPSocket, F_SETFL, O_NONBLOCK);
	fcntl(recvUDPICMPSocket, F_SETFL, O_NONBLOCK);
	int timeOut = 4;
	int countForTimeOut = 3;
	bool udpPacket;

	fds[0].fd = recvUDPSocket;
	fds[0].events = 0;
	fds[0].events |= POLLIN;

	fds[1].fd = recvUDPICMPSocket;
	fds[1].events = 0;
	fds[1].events |= POLLIN;

	char IP[15];
	int portfromPacket;

	int check;
	char ipAddressToChar[15];
	bool timeoutCheck = true;
	bool icmpPacket;

	int pollCheck;	// = poll(fds, 2, 4000);
//cout << "Hello1" <<endl ;
	double differenceInTime = 0;
	int bytesRecvd = 0;
	do {
		time_t beforeTimeout = time(0);
		countForTimeOut--;
		if (portToScan == 53) {
			sendUDPPacket(sendSocketUDP, buf, &destHost,
					sizeof(struct udphdr) + sizeof(struct DNShdr));
		} else {
			//cout << "Inside UDP pack send" <<endl ;
			sendUDPPacket(sendSocketUDP, buf, &destHost,
					sizeof(struct udphdr) + strlen("RandomJunkPayload"));
		}
		pollCheck = poll(fds, 2, 4000);
		while (pollCheck == 1) {
			time_t inLoopTime = time(0);
			double difference = difftime(inLoopTime, beforeTimeout);
			if (difference > timeOut) {
				timeoutCheck = true;
				break;
			}
			if (fds[0].revents & POLLIN) {
				//timeoutCheck = false;
				//pthread_mutex_lock(&recvMutex);
				//tcpPacket = true;
				//icmpPacket = false;
				//	cout << "Pollling UDP" <<endl ;
				bytesRecvd = recvfrom(recvUDPSocket, packet, 200, 0,
						(struct sockaddr*) &destHost, &len);
				if (bytesRecvd < 0) {

					//cout << "Receive Error In TCP" << endl;
					//cout << errno << endl;
					//exit(1);
				}
				//	pthread_mutex_unlock(&recvMutex);

			}
			if (fds[1].revents & POLLIN) {
				//pthread_mutex_lock(&recvMutex);
				//timeoutCheck = false;
				//icmpPacket = true;
				//tcpPacket= false;
				//	cout << "POLING ICMP" <<endl ;
				bytesRecvd = recvfrom(recvUDPICMPSocket, packet, 200, 0,
						(struct sockaddr*) &destHost, &len);
				if (bytesRecvd < 0) {

					//cout << "Receive Error In ICMP" << endl;
					//exit(1);
				}
				//pthread_mutex_unlock(&recvMutex);
			}

			if (bytesRecvd > 0) {

				if (packet != NULL) {
					getIPfromPacket(packet, IP);
					//cout << "NULL ke baad" <<endl ;
					portfromPacket = getPortfromPacket(packet); // true = tcp
					memset(ipAddressToChar, '\0', sizeof(ipAddressToChar));
					strcpy(ipAddressToChar, DotAddr);
					if ((strcmp(IP, ipAddressToChar) == 0
							&& (portfromPacket == portToScan))) {
						// udpPacket = true;
						timeoutCheck = false;
						//cout << "Ip port dhekha" <<endl ;
						break;
					} else {
						if (verifyICMPacket(packet, ipToScan, portToScan)) {
							//cout << "verfiy maara" <<endl ;
							//icmpPacket = true;
							timeoutCheck = false;
							break;
						}
					}
				}
			}

		}

	} while (timeoutCheck && countForTimeOut > 0);
	//cout << "do while ke baahar" <<endl ;
	struct iphdr* ip_head = (struct iphdr*) packet;
	if (ip_head->protocol == IPPROTO_UDP) {

		udpPacket = true;
	} else if (ip_head->protocol == IPPROTO_ICMP) {
		icmpPacket = true;
	}
	std::map<int, string> mymap;
	if (icmpPacket) {
		udpICMPAnalysis(packet, portToScan, DotAddr);
	} else if (udpPacket && countForTimeOut > 0) {
		cout << DotAddr << "\t" << portToScan << "UDP REPLY PORT OPEN" << endl;
		pthread_mutex_lock(&udpMutex);
		mymap.insert(std::pair<int, string>(portToScan, "OPEN"));
		udpOutputMap.insert(
				pair<string, std::map<int, string>>(DotAddr, mymap));
		pthread_mutex_unlock(&udpMutex);
	} else if (countForTimeOut == 0) {
		cout << DotAddr << "\t" << portToScan << "UDP PORT OPEN FILTERED"
				<< endl;
		pthread_mutex_lock(&udpMutex);
		cout << "INdsede mutex" << endl;
		mymap.insert(std::pair<int, string>(portToScan, "OPEN|FILTERED"));
		udpOutputMap.insert(
				pair<string, std::map<int, string>>(DotAddr, mymap));
		pthread_mutex_unlock(&udpMutex);
	}
	close(recvUDPICMPSocket);
	close(recvUDPSocket);
	close(sendSocketUDP);
}

void TCPUDPScan::sendTCPPacket(int sendSocket, struct tcphdr *tcp,
		struct sockaddr_in *destHost) {

	if (sendto(sendSocket, tcp, sizeof(struct tcphdr), 0,
			(struct sockaddr *) destHost, sizeof(struct sockaddr_in)) == -1) {
		cout << "Problem in sending" << endl;
		cout << "Error Value :" << errno << endl;
		//exit(1);

	}

}
void TCPUDPScan::sendUDPPacket(int sendSocket, char *buf,
		struct sockaddr_in *destHost, int size) {

	if (sendto(sendSocket, buf, size, 0, (struct sockaddr *) destHost,
			sizeof(struct sockaddr_in)) == -1) {
		cout << "sfksd";

	} else {
		cout << "sent";
	}

}
/*
 void TCPUDPScan::sendDNSUDPPacket(int sendSocket, char *buf,
 struct sockaddr_in *destHost) {

 if (sendto(sendSocket, buf, (sizeof(struct udphdr) + sizeof(struct DNShdr)),
 0, (struct sockaddr *) destHost, sizeof(struct sockaddr_in))
 == -1) {
 cout << "Problem in sending" << endl;
 cout << "Error Value :" << errno << endl;
 //exit(1);

 }

 }
 */
void TCPUDPScan::synAnalysis(char* packet, int portToScan, char* DotAddr,
		int check) {
	struct iphdr* ip_header = (struct iphdr*) (packet);
	//struct displayOutput *toOutput = new struct displayOutput;
	std::map<int, string> mymap;
	//toOutput->port = portToScan;
	string ipToPrint;
	bool openFlag = false;

	if (check == 1) {
		struct tcphdr * tcpheader = (struct tcphdr*) (packet
				+ ip_header->ihl * 4);
		if (tcpheader->ack == 1 && tcpheader->syn == 1) {

			cout << DotAddr << '\t' << portToScan << '\t' << "P(SYN)ORT IS OPEN"
					<< endl;

			//toOutput->result = "OPEN";
			pthread_mutex_lock(&synMutex);
			mymap.insert(std::pair<int, string>(portToScan, " (SYN) OPEN "));
			openFlag = true;
			synOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&synMutex);
		} else if (tcpheader->rst == 1) {
			cout << DotAddr << '\t' << portToScan << '\t'
					<< "(SYN)PORT IS CLOSED" << endl;
			//toOutput->result = "CLOSED";
			pthread_mutex_lock(&synMutex);
			mymap.insert(std::pair<int, string>(portToScan, "(SYN)CLOSED"));
			synOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&synMutex);
			/*synOutputMap.insert(
			 pair<string, std::map<int,string>>(DotAddr, toOutput));*/

		} else {
			cout << DotAddr << '\t' << portToScan << '\t'
					<< "SYN UNKNOWN PACKET" << endl;
		}
	}

	else {
		cout << DotAddr << '\t' << portToScan << '\t'
				<< "(SYN TCP)PORT FILTERED" << endl;
		//toOutput->result = "FILTERED";
		pthread_mutex_lock(&synMutex);
		cout << "HI" << endl;
		mymap.insert(std::pair<int, string>(portToScan, "(SYN)FILTERED"));
		synOutputMap.insert(
				pair<string, std::map<int, string>>(DotAddr, mymap));
		pthread_mutex_unlock(&synMutex);
		/*synOutputMap.insert(
		 pair<string, std::map<int,string>>(DotAddr, toOutput));*/

	}

}

void TCPUDPScan::getIPfromPacket(char* packet, char*IP) {

	struct iphdr* ip_header = (struct iphdr*) (packet);
	struct sockaddr_in ipSource;
	memset(&ipSource, 0, sizeof(ipSource));
	ipSource.sin_addr.s_addr = ip_header->saddr;
	sprintf(IP, "%s", inet_ntoa(ipSource.sin_addr));
}

int TCPUDPScan::getPortfromPacket(char* packet) { // true - tcp    false- udp
	int portfromPacket = 0;
	struct iphdr* ip_header = (struct iphdr*) (packet);

	char * portNumberInString;
	if (ip_header->protocol == IPPROTO_ICMP) {
		struct icmphdr * icmp_header = (struct icmphdr *) (packet
				+ ip_header->ihl * 4);
		struct iphdr * insideIpheader = (struct iphdr *) (packet
				+ ip_header->ihl * 4 + sizeof(struct icmphdr));
		char * insideIpheaderChar = (char *) insideIpheader;
		if (insideIpheader->protocol == IPPROTO_TCP) {
			struct tcphdr * tcp_header = (struct tcphdr *) (packet
					+ ip_header->ihl * 4 + sizeof(struct icmphdr)
					+ insideIpheader->ihl * 4);
			portfromPacket = ntohs(tcp_header->dest);
		} else if (insideIpheader->protocol == IPPROTO_UDP) {
			struct udphdr * udp_header = (struct udphdr *) (packet
					+ ip_header->ihl * 4 + sizeof(struct icmphdr)
					+ insideIpheader->ihl * 4);
			portfromPacket = ntohs(udp_header->dest);
		}

	}
	//struct servent * serv;
	else if (ip_header->protocol == IPPROTO_TCP) {
		struct tcphdr* tcp_header = (struct tcphdr*) (packet
				+ sizeof(struct iphdr));

		portfromPacket = ntohs(tcp_header->source);
	} else if (ip_header->protocol == IPPROTO_UDP) {
		struct udphdr* udp_header = (struct udphdr*) (packet
				+ sizeof(struct iphdr));
		portfromPacket = ntohs(udp_header->source);
	}

	return portfromPacket;
}

void TCPUDPScan::icmpAnalysis(char* packet, char*DotAddr, int portToScan,
		string scanMethod) {
	char Ip[15];
	int portFromICMPHeader = 0;
	struct iphdr * ip_header = (struct iphdr *) packet;

	getIPfromPacket(packet, Ip);
	struct icmphdr * icmp_header = (struct icmphdr *) (packet
			+ ip_header->ihl * 4);
	struct iphdr * insideIpheader = (struct iphdr *) (packet
			+ ip_header->ihl * 4 + sizeof(struct icmphdr));
	char * insideIpheaderChar = (char *) insideIpheader;

	struct tcphdr * tcp_header = (struct tcphdr *) (packet + ip_header->ihl * 4
			+ sizeof(struct icmphdr) + insideIpheader->ihl * 4);

	portFromICMPHeader = ntohs(tcp_header->dest);
	//struct displayOutput* toOutput = new struct displayOutput;
	//toOutput->port = portToScan;
	std::map<int, string> mymap;
	if (strcmp(DotAddr, Ip) == 0 && (portFromICMPHeader == portToScan)) {
		if (icmp_header->type == 3
				&& (icmp_header->code == 1 || icmp_header->code == 2
						|| icmp_header->code == 3 || icmp_header->code == 9
						|| icmp_header->code == 10 || icmp_header->code == 13)) {
			cout << DotAddr << '\t' << portFromICMPHeader << '\t'
					<< " PORT IS FILTERED (SYN)" << endl;

			//toOutput->result = "FILTERED";
			if ((scanMethod.compare("SYN") == 0)) {
				pthread_mutex_lock(&synMutex);
				mymap.insert(
						std::pair<int, string>(portToScan, "(SYN)FILTERED"));
				synOutputMap.insert(
						pair<string, std::map<int, string>>(DotAddr, mymap));
				pthread_mutex_unlock(&synMutex);
				/*synOutputMap.insert(
				 pair<string, std::map<int,string>>(DotAddr, toOutput));*/
			} else if (((scanMethod.compare("FIN") == 0)
					|| (scanMethod.compare("NULL") == 0)
					|| (scanMethod.compare("XMAS") == 0))) {
				pthread_mutex_lock(&xmasMutex);
				mymap.insert(std::pair<int, string>(portToScan, "FILTERED"));
				nullXmasFinOutputMap.insert(
						pair<string, std::map<int, string>>(DotAddr, mymap));
				pthread_mutex_unlock(&xmasMutex);
				/*nullXmasFinOutputMap.insert(
				 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
			} else if ((scanMethod.compare("ACK") == 0)) {
				pthread_mutex_lock(&ackMutex);
				mymap.insert(std::pair<int, string>(portToScan, "FILTERED"));
				ackOutputMap.insert(
						pair<string, std::map<int, string>>(DotAddr, mymap));
				pthread_mutex_unlock(&ackMutex);
				/*ackOutputMap.insert(
				 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
			}
		}

	} else {
		if ((scanMethod.compare("SYN") == 0)) {
			cout << "jvdsjf" << endl;
			pthread_mutex_lock(&synMutex);
			mymap.insert(std::pair<int, string>(portToScan, "(SYN)FILTERED"));
			synOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&synMutex);
			/*synOutputMap.insert(
			 pair<string, std::map<int,string>>(DotAddr, toOutput));*/
		} else if (((scanMethod.compare("FIN") == 0)
				|| (scanMethod.compare("NULL") == 0)
				|| (scanMethod.compare("XMAS") == 0))) {
			pthread_mutex_lock(&xmasMutex);
			mymap.insert(std::pair<int, string>(portToScan, "FILTERED"));
			nullXmasFinOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&xmasMutex);
			/*nullXmasFinOutputMap.insert(
			 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
		} else if ((scanMethod.compare("ACK") == 0)) {
			pthread_mutex_lock(&ackMutex);
			mymap.insert(std::pair<int, string>(portToScan, "FILTERED"));
			ackOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&ackMutex);
			/*ackOutputMap.insert(
			 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
		}
	}
}
void TCPUDPScan::udpICMPAnalysis(char* packet, int portToScan, char* DotAddr) {
	char Ip[15];
	int portFromICMPHeader;

	struct iphdr * ip_header = (struct iphdr *) packet;

	getIPfromPacket(packet, Ip);
	struct icmphdr * icmp_header = (struct icmphdr *) (packet
			+ ip_header->ihl * 4);
	struct iphdr * insideIpheader = (struct iphdr *) (packet
			+ ip_header->ihl * 4 + sizeof(struct icmphdr));

	struct udphdr * udp_header = (struct udphdr *) (packet + ip_header->ihl * 4
			+ sizeof(struct icmphdr) + insideIpheader->ihl * 4);

	portFromICMPHeader = ntohs(udp_header->dest);
	//struct displayOutput* toOutput = new struct displayOutput;
	//toOutput->port = portToScan;
	std::map<int, string> mymap;
	if (strcmp(DotAddr, Ip) == 0 && (portFromICMPHeader == portToScan)) {
		if (icmp_header->type == 3
				&& (icmp_header->code == 1 || icmp_header->code == 2
						|| icmp_header->code == 9 || icmp_header->code == 10
						|| icmp_header->code == 13)) {
			cout << DotAddr << '\t' << portToScan << " (UDP)PORT IS FILTERED"
					<< endl;
			pthread_mutex_lock(&udpMutex);
			mymap.insert(std::pair<int, string>(portToScan, "(UDP)FILTERED"));
			udpOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&udpMutex);
		} else if (icmp_header->type == 3 && icmp_header->code == 3) {
			cout << DotAddr << '\t' << portToScan << " (UDP)PORT IS CLOSED"
					<< endl;
			pthread_mutex_lock(&udpMutex);
			mymap.insert(std::pair<int, string>(portToScan, "(UDP)CLOSED"));
			udpOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&udpMutex);
		}

	} else {
		pthread_mutex_lock(&udpMutex);
		mymap.insert(std::pair<int, string>(portToScan, "(UDP)FILTERED"));
		if (DotAddr != NULL && !mymap.empty()) {
			udpOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
		}
		pthread_mutex_unlock(&udpMutex);
	}
}

void TCPUDPScan::nullxmasfinAnalysis(char* packet, int portToScan,
		char* DotAddr, int check) {
	struct iphdr* ip_header = (struct iphdr*) (packet);
	//struct displayOutput* toOutput = new struct displayOutput;
	//toOutput->port = portToScan;
	std::map<int, string> mymap;
	if (check == 2) {
		struct tcphdr * tcpheader = (struct tcphdr*) (packet
				+ ip_header->ihl * 4);
		if (tcpheader->rst == 1) {
			cout << DotAddr << '\t' << portToScan << '\t' << "PORT IS CLOSED"
					<< endl;
			/*toOutput->result = "CLOSED";
			 nullXmasFinOutputMap.insert(
			 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
			pthread_mutex_lock(&xmasMutex);
			mymap.insert(std::pair<int, string>(portToScan, "CLOSED"));
			nullXmasFinOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&xmasMutex);
		} else {
			cout << DotAddr << '\t' << portToScan << '\t'
					<< "XMAS NULL FIN UNKNOWN PACKET" << endl;

		}
	} else {
		cout << DotAddr << '\t' << portToScan << '\t' << "OPEN|FILTERED"
				<< endl;
		/*toOutput->result = "OPEN|PORT FILTERED";
		 nullXmasFinOutputMap.insert(
		 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
		pthread_mutex_lock(&xmasMutex);
		mymap.insert(std::pair<int, string>(portToScan, "OPEN|FILTERED"));

		nullXmasFinOutputMap.insert(
				pair<string, std::map<int, string>>(DotAddr, mymap));
		cout << "Hi" << endl;
		pthread_mutex_unlock(&xmasMutex);
	}
}

void TCPUDPScan::ackAnalysis(char* packet, int portToScan, char* DotAddr,
		int check) {
	struct iphdr* ip_header = (struct iphdr*) (packet);
	//udpICMPAnalysis	//struct displayOutput* toOutput = new struct displayOutput;
	//toOutput->port = portToScan;
	std::map<int, string> mymap;
	if (check == 3) {
		struct tcphdr * tcpheader = (struct tcphdr*) (packet
				+ ip_header->ihl * 4);
		if (tcpheader->rst == 1) {
			cout << "PORT IS UNFILTERED" << endl;
			/*toOutput->result = "UNFILTERED";
			 ackOutputMap.insert(
			 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
			pthread_mutex_lock(&ackMutex);
			mymap.insert(std::pair<int, string>(portToScan, "UNFILTERED"));
			ackOutputMap.insert(
					pair<string, std::map<int, string>>(DotAddr, mymap));
			pthread_mutex_unlock(&ackMutex);
		} else {
			cout << "ACK UNKNOWN PACKET" << endl;
		}
	} else {
		cout << "PORT FILTERED" << endl;
		/*toOutput->result = "FILTERED";
		 ackOutputMap.insert(
		 pair<string, struct displayOutput*>(DotAddr, toOutput));*/
		pthread_mutex_lock(&ackMutex);
		mymap.insert(std::pair<int, string>(portToScan, "FILTERED"));
		ackOutputMap.insert(
				pair<string, std::map<int, string>>(DotAddr, mymap));
		pthread_mutex_unlock(&ackMutex);
	}
}

void TCPUDPScan::display(string ipToPrint, struct parseV* parseValues) {

	cout << "IP address :" << '\t' << ipToPrint << endl;
	cout << "Port" << "\t" << "Service Name" << "\t" << "Service Version"
			<< "\t\t" << "Result" << "\t\t\t\t\t\t" << "Conclusion" << endl;
	cout
			<< "----------------------------------------------------------------------------------------------------------------------------"
			<< endl;
	/*cout << "Open Ports:" << endl;
	 cout << "Port" << "\t" << "Service Name" << "\t" << "Service Version"
	 << "\t\t" << "Result" << "\t\t\t\t\t\t" << "Conclusion" << endl;
	 cout
	 << "----------------------------------------------------------------------------------------------------------------------------"
	 << endl;*/

	std::pair<std::multimap<string, std::map<int, string>>::iterator,
			std::multimap<string, std::map<int, string>>::iterator> retSyn;
	std::pair<std::multimap<string, std::map<int, string>>::iterator,
			std::multimap<string, std::map<int, string>>::iterator> retACK;
	std::pair<std::multimap<string, std::map<int, string>>::iterator,
			std::multimap<string, std::map<int, string>>::iterator> retUDP;
	std::pair<std::multimap<string, std::map<int, string>>::iterator,
			std::multimap<string, std::map<int, string>>::iterator> retXNF;
	std::multimap<string, std::map<int, string>>::iterator it1;
	std::multimap<string, std::map<int, string>>::iterator itExtra;
	std::multimap<string, std::map<int, string>>::iterator it2Extra, it3Extra;
	std::multimap<string, std::map<int, string>>::iterator it2;
	std::multimap<string, std::map<int, string>>::iterator it3;
	std::multimap<string, std::map<int, string>>::iterator it4;
	char *servName = new char[50];
	struct servent serv;
	int a;

	if (synOutputMap.size() != 0) {
		retSyn = synOutputMap.equal_range(ipToPrint);
		it1 = retSyn.first;
		a = synOutputMap.count(ipToPrint);

	} else {
		it1 = synOutputMap.end();
	}
	if (ackOutputMap.size() != 0) {
		retACK = ackOutputMap.equal_range(ipToPrint);
		it2 = retACK.first;
		a = ackOutputMap.count(ipToPrint);
	} else {
		it2 = ackOutputMap.end();
	}
	if (udpOutputMap.size() != 0) {
		retUDP = udpOutputMap.equal_range(ipToPrint);
		it3 = retUDP.first;
		a = udpOutputMap.count(ipToPrint);
	} else {
		it3 = udpOutputMap.end();
	}

	if (nullXmasFinOutputMap.size() != 0) {
		retXNF = nullXmasFinOutputMap.equal_range(ipToPrint);
		it4 = retXNF.first;
		a = nullXmasFinOutputMap.count(ipToPrint);
	} else {
		it4 = nullXmasFinOutputMap.end();
	}

	string synOP = "";
	string udpOp = "";
	string ackOp = "";
	string XNFOp = "";
	int port;
	int port2;
	int port3;

	while (a != 0) {
		string toOutput = "";
		a--;
		if (it1 != synOutputMap.end()) {
			std::map<int, string> consoleOutput1 = it1->second;
			std::map<int, string>::iterator inter1 = consoleOutput1.begin();
			synOP = inter1->second;
			port = inter1->first;
			toOutput = to_string(inter1->first) + "\t"
					+ string(serviceName(inter1->first, &serv)) + "\t\t"
					+ "VERSION" + "\t\t\t" + synOP;
			itExtra = it1;
			it1++;

		} else {
			toOutput += "";
			itExtra = it1;
		}

		if (it2 != ackOutputMap.end() && itExtra != synOutputMap.end()) {

			for (it2 = ackOutputMap.begin(); it2 != ackOutputMap.end(); it2++) {
				std::map<int, string> consoleOutput2 = it2->second;
				std::map<int, string>::iterator inter2 = consoleOutput2.find(
						port);

				if (inter2 != consoleOutput2.end()) {
					ackOp = inter2->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput2 = it2->second;
			 std::map<int, string>::iterator inter2 = consoleOutput2.find(port);
			 ackOp = inter2->second;*/
			toOutput = toOutput + "\t\t\t" + ackOp;
			it2Extra = it2;
			//it2++;
		} else if (it2 != ackOutputMap.end() && itExtra == synOutputMap.end()) {
			std::map<int, string> consoleOutput2 = it2->second;
			std::map<int, string>::iterator inter2 = consoleOutput2.begin();
			ackOp = inter2->second;
			port2 = inter2->first;
			toOutput = to_string(inter2->first) + "\t"
								+ string(serviceName(inter2->first, &serv)) + "\t\t"
								+ "VERSION" + "\t\t\t" + ackOp;

			it2Extra = it2;
			it2++;
		} else {
			toOutput += "";
			it2Extra = it2;
		}

		if (it3 != udpOutputMap.end() && itExtra != synOutputMap.end()
				&& it2Extra != ackOutputMap.end()) {

			for (it3 = udpOutputMap.begin(); it3 != udpOutputMap.end(); it3++) {
				std::map<int, string> consoleOutput3 = it3->second;
				std::map<int, string>::iterator inter3 = consoleOutput3.find(
						port);

				if (inter3 != consoleOutput3.end()) {
					udpOp = inter3->second;
					break;
				}
			}
			/*
			 std::map<int, string> consoleOutput3 = it3->second;
			 std::map<int, string>::iterator inter3 = consoleOutput3.find(port);
			 udpOp = inter3->second;
			 */
			toOutput = toOutput + "\t\t\t" + udpOp;
			it3Extra = it3;
//			it3++;
		} else if (it3 != udpOutputMap.end() && it2Extra != ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			for (it3 = udpOutputMap.begin(); it3 != udpOutputMap.end(); it3++) {
				std::map<int, string> consoleOutput3 = it3->second;
				std::map<int, string>::iterator inter3 = consoleOutput3.find(
						port2);

				if (inter3 != consoleOutput3.end()) {
					udpOp = inter3->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput3 = it3->second;
			 std::map<int, string>::iterator inter3 = consoleOutput3.find(port2);
			 udpOp = inter3->second;
			 */toOutput = toOutput + "\t\t\t" + udpOp;
			it3Extra = it3;
			//it3++;
		} else if (it3 != udpOutputMap.end() && it2Extra == ackOutputMap.end()
				&& itExtra != synOutputMap.end()) {
			for (it3 = udpOutputMap.begin(); it3 != udpOutputMap.end(); it3++) {
				std::map<int, string> consoleOutput3 = it3->second;
				std::map<int, string>::iterator inter3 = consoleOutput3.find(
						port);

				if (inter3 != consoleOutput3.end()) {
					udpOp = inter3->second;
					break;
				}

			}
			toOutput = toOutput + "\t\t\t" + udpOp;
			it3Extra = it3;
			//it3++;
		} else if (it3 != udpOutputMap.end() && it2Extra == ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			std::map<int, string> consoleOutput3 = it3->second;
			std::map<int, string>::iterator inter3 = consoleOutput3.begin();
			udpOp = inter3->second;
			port3 = inter3->first;
			toOutput = to_string(inter3->first) + "\t"
								+ string(serviceName(inter3->first, &serv)) + "\t\t"
								+ "VERSION" + "\t\t\t" + udpOp;

			it3Extra = it3;
			it3++;
		} else {
			toOutput += "";
			it3Extra = it3;
		}

		if (it4 != nullXmasFinOutputMap.end() && it3Extra != udpOutputMap.end()
				&& itExtra != synOutputMap.end()
				&& it2Extra != ackOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;

			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra != udpOutputMap.end()
				&& it2Extra != ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port2);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port2);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra != udpOutputMap.end()
				&& it2Extra == ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port3);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port3);
			 XNFOp = inter4->second;
			 */toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra == udpOutputMap.end()
				&& it2Extra != ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port2);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port2);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra == udpOutputMap.end()
				&& it2Extra != ackOutputMap.end()
				&& itExtra != synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra != udpOutputMap.end()
				&& it2Extra == ackOutputMap.end()
				&& itExtra != synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*			std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra == udpOutputMap.end()
				&& it2Extra == ackOutputMap.end()
				&& itExtra == synOutputMap.end()) {
			std::map<int, string> consoleOutput4 = it4->second;
			std::map<int, string>::iterator inter4 = consoleOutput4.begin();

			toOutput = to_string(inter4->first) + "\t"
								+ string(serviceName(inter4->first, &serv)) + "\t\t"
								+ "VERSION" + "\t\t\t" + inter4->second;

			it4++;
		} else if (it4 != nullXmasFinOutputMap.end()
				&& it3Extra == udpOutputMap.end()
				&& it2Extra == ackOutputMap.end()
				&& itExtra != synOutputMap.end()) {
			for (it4 = nullXmasFinOutputMap.begin();
					it4 != nullXmasFinOutputMap.end(); it4++) {
				std::map<int, string> consoleOutput4 = it4->second;
				std::map<int, string>::iterator inter4 = consoleOutput4.find(
						port);

				if (inter4 != consoleOutput4.end()) {
					XNFOp = inter4->second;
					break;
				}

			}

			/*std::map<int, string> consoleOutput4 = it4->second;
			 std::map<int, string>::iterator inter4 = consoleOutput4.find(port);
			 XNFOp = inter4->second;*/
			toOutput = toOutput + "\t\t\t" + XNFOp;
			//it4++;
		} else {
			toOutput += "";
		}
		cout << toOutput + "\t\t" + getConclusion(synOP, udpOp, ackOp, XNFOp) << endl;

	}
	cout <<"\n" ;


	/*if (synOutputMap.size() != 0) {
	 retSyn = synOutputMap.equal_range(ipToPrint);
	 cout << "SYN SCAN" << endl;

	 for (it1 = retSyn.first; it1 != retSyn.second; ++it1) {
	 std::map<int, string> consoleOutput1 = it1->second;
	 std::map<int, string>::iterator inter1 = consoleOutput1.begin();
	 cout << inter1->first << "\t" << serviceName(inter1->first, &serv)
	 << "\t" << "VERSION" << "\t\t\t" << inter1->second << endl;
	 memset(servName, '\0', sizeof(servName));
	 << "\tUDP " << (parseValues->scanMethod[0] == 1?inter3->second:"N/A")<< "\tXMAS "
	 << inter4->second << endl;
	 }
	 cout << endl;
	 }
	 if (ackOutputMap.size() != 0) {
	 retACK = ackOutputMap.equal_range(ipToPrint);
	 //it2 = retACK.first;
	 cout << "ACK SCAN" << endl;

	 for (it2 = retACK.first; it2 != retACK.second; ++it2) {
	 std::map<int, string> consoleOutput2 = it2->second;
	 std::map<int, string>::iterator inter2 = consoleOutput2.begin();
	 cout << inter2->first << "\t" << serviceName(inter2->first, &serv)
	 << "\t" << "VERSION" << "\t\t\t" << inter2->second << endl;
	 memset(servName, '\0', sizeof(servName));
	 }
	 cout << endl;
	 }
	 if (udpOutputMap.size() != 0) {
	 retUDP = udpOutputMap.equal_range(ipToPrint);
	 it3 = retUDP.first;
	 cout << "UDP SCAN" << endl;

	 for (it3 = retUDP.first; it3 != retUDP.second; it3++) {
	 std::map<int, string> consoleOutput3 = it3->second;
	 std::map<int, string>::iterator inter3 = consoleOutput3.begin();

	 cout << inter3->first << "\t" << serviceName(inter3->first, &serv)
	 << "\t" << "VERSION" << "\t\t\t" << inter3->second << endl;
	 memset(servName, '\0', sizeof(servName));
	 }
	 cout << endl;
	 }
	 int i = 1;
	 if (nullXmasFinOutputMap.size() != 0) {
	 cout << nullXmasFinOutputMap.size() << endl;
	 std::map<int, string> mymap;
	 mymap.insert(std::pair<int, string>(12345667, "FILTERED"));
	 ackOutputMap.insert(
	 pair<string, std::map<int, string>>("255.255.255.255", mymap));

	 retXNF = nullXmasFinOutputMap.equal_range(ipToPrint);
	 it4 = retXNF.first;
	 cout << "XNF SCAN" << endl;
	 for (it4 = retXNF.first;
	 it4 != retXNF.second ||it4!= nullXmasFinOutputMap.end();
	 it4++) {
	 std::map<int, string> consoleOutput4 = it4->second;
	 std::map<int, string>::iterator inter4 = consoleOutput4.begin();
	 //(consoleOutput4.begin())->first;
	 cout << inter4->first << "\t" << serviceName(inter4->first, &serv)
	 << "\t" << "VERSION" << "\t\t\t" << "XNF " << inter4->second
	 << endl;
	 memset(servName, '\0', sizeof(servName));
	 i++;
	 }
	 cout << i << endl;
	 }

	 std::multimap<string, std::map<int, string>>::iterator it2 = retACK.first;
	 std::multimap<string, std::map<int, string>>::iterator it3 = retUDP.first;
	 std::multimap<string, std::map<int, string>>::iterator it4 = retXNF.first;

	 // 0 - syn   1 - fin    2 -xmas    3 - null   4 -udp  5- ack
	 if (parseValues->scanMethod[0] == 1) {
	 std::multimap<string, std::map<int, string>>::iterator it1 =
	 retSyn.first;
	 }
	 if (parseValues->scanMethod[5] == 1) {
	 std::multimap<string, std::map<int, string>>::iterator it2 =
	 retACK.first;
	 }
	 if (parseValues->scanMethod[4] == 1) {
	 std::multimap<string, std::map<int, string>>::iterator it3 =
	 retUDP.first;
	 }
	 if (parseValues->scanMethod[1] == 1 || parseValues->scanMethod[2] == 1
	 || parseValues->scanMethod[3] == 1) {
	 std::multimap<string, std::map<int, string>>::iterator it4 =
	 retXNF.first;
	 }

	 for (it1, it2; it1 != retSyn.second; ++it1, ++it2) {
	 std::map<int, string> consoleOutput1 = it1->second;
	 std::map<int, string>::iterator inter1 = consoleOutput1.begin();

	 std::map<int, string> consoleOutput2 = it2->second;
	 std::map<int, string>::iterator inter2 = consoleOutput2.begin();

	 std::map<int, string> consoleOutput3 = it3->second;
	 std::map<int, string>::iterator inter3 = consoleOutput3.begin();

	 std::map<int, string> consoleOutput4 = it4->second;
	 std::map<int, string>::iterator inter4 = consoleOutput4.begin();

	 cout << parseValues->scanMethod[0]==1? inter1->first : << "\t" << "SERVICES" << "\t" << "VERSION"
	 << "\t\t\t" << "SYN " << inter1->second << "\tACK "
	 << inter2->second << endl;
	 << "\tUDP " << (parseValues->scanMethod[0] == 1?inter3->second:"N/A")<< "\tXMAS "
	 << inter4->second << endl;

	 }*/
}

char* TCPUDPScan::serviceName(int port, struct servent * serv) {

	string sName;
	if ((serv = getservbyport(htons(port), NULL)) != NULL) {
		return serv->s_name;

	}
	return "sd";
}

string TCPUDPScan::getConclusion(string synOP, string udpOp, string ackOp,
		string XNFOp) {

	string asd = "hello";

	return asd;
}

bool TCPUDPScan::verifyICMPacket(char* packet, char * iptoScan,
		int portToScan) {
	struct iphdr * ip_header = (struct iphdr *) packet;
	bool verify = false;
	char Ip[15];
	int portFrompacket;
	//getIPfromPacket(packet, Ip);
	if (ip_header->protocol == IPPROTO_ICMP) {
		struct icmphdr * icmp_header = (struct icmphdr *) (packet
				+ ip_header->ihl * 4);
		struct iphdr * insideIpheader = (struct iphdr *) (packet
				+ ip_header->ihl * 4 + sizeof(struct icmphdr));

		struct sockaddr_in ipSource;
		memset(&ipSource, 0, sizeof(ipSource));
		ipSource.sin_addr.s_addr = ip_header->daddr;
		sprintf(Ip, "%s", inet_ntoa(ipSource.sin_addr));
		if (strcmp(Ip, iptoScan) == 0) {
			if (insideIpheader->protocol == IPPROTO_TCP) {
				struct tcphdr * tcp_header = (struct tcphdr *) (packet
						+ ip_header->ihl * 4 + sizeof(struct icmphdr)
						+ insideIpheader->ihl * 4);
				portFrompacket = ntohs(tcp_header->dest);
			} else if (ip_header->protocol == IPPROTO_UDP) {
				struct udphdr * udp_header = (struct udphdr *) (packet
						+ ip_header->ihl * 4 + sizeof(struct icmphdr)
						+ insideIpheader->ihl * 4);
				portFrompacket = ntohs(udp_header->dest);
			}

			if (portFrompacket == portToScan) {

				verify = true;
			}

		}

	}
	return verify;
}
