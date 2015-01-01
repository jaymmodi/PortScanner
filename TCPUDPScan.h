/*
 * TCPUDPScan.h
 *
 *  Created on: Nov 15, 2014
 *      Author: jay
 */

#ifndef TCPUDPSCAN_H_
#define TCPUDPSCAN_H_
#include "pssetup.h"
static int a = 25;
static multimap<string, std::map<int,string>> synOutputMap;
static multimap<string, std::map<int,string>> ackOutputMap;
static multimap<string, std::map<int,string>> nullXmasFinOutputMap;
static multimap<string, std::map<int,string>> udpOutputMap;

class TCPUDPScan {
public:
	TCPUDPScan();
	virtual ~TCPUDPScan();
	pthread_mutex_t recvMutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t synMutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t udpMutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t ackMutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t xmasMutex = PTHREAD_MUTEX_INITIALIZER;


	//map<string, struct displayOutput*> synOutputMap;

	void generateChecksum(u_int16_t checksumValue, struct tcphdr*tcp,
			struct pseudo_tcpheader*psh);
	void generateChecksumUDP(u_int16_t checksumValue, struct udphdr*tcp,
			struct pseudo_udpheader*psh);
	void generateTCPHeader(struct tcphdr* tcph, int sPort, int dPort);
	void generateUDPHeader(struct udphdr* udph, int sPort, int dPort);
	void generatePseudoTCPHeader(struct pseudo_tcpheader* psh, int dPort,
			char* ipFromList);
	void generatePseudoUDPHeader(struct pseudo_udpheader* psh, int dPort,
			char* ipFromList);
	void whatsMyIP(char* myIP);
	void scanTCPport(struct parseV * parseValues, string flagToSet);
	void createTCPheaderWithCorrectChecksum(struct tcphdr * tcp);
	void createIPheader(struct iphdr* ipheader, struct parseV);
	void scanTCPport(char* ipToScan, int portToScan, string scanMethod);
	void scanUDPport(char* ipToScan, int portToScan);
	void checkServices(char* ipToScan, int portToScan);
	void sendTCPPacket(int sendSocket, struct tcphdr *tcp,
			struct sockaddr_in *destHost);
	void synAnalysis(char* packet, int portToScan, char* DotAddr, int check);
	void getIPfromPacket(char*packet, char*IP);
	int getPortfromPacket(char*packet);
	void icmpAnalysis(char* packet, char*DotAddr, int portToScan,string flagToSet);
	void nullxmasfinAnalysis(char* packet, int portToScan, char* DotAddr,
			int check);
	void ackAnalysis(char* packet, int portToScan, char* DotAddr, int check);
	void udpICMPAnalysis(char* packet, int portToScan, char* DotAddr);
	void sendUDPPacket(int sendSocket, char *buf, struct sockaddr_in *destHost,int size);
	void sendDNSUDPPacket(int sendSocket, char *buf,
			struct sockaddr_in *destHost);
	void display(string ipToPrint,struct parseV* parseValues);
	char* serviceName(int port,struct servent * serv);
	string getConclusion(string synOP, string udpOp,string ackOp,string XNFOp);
	bool verifyICMPacket(char* packet, char * iptoScan,
			int portToScan);

};

#endif /* TCPUDPSCAN_H_ */
