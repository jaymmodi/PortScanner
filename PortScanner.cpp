//============================================================================
// Name        : PortScanner.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include "pssetup.h"
#include <string.h>
#include <list>
#include <pthread.h>
#include <map>
#include "TCPUDPScan.h"
struct parseV parseValues;
list<struct differentJobs*> jobList; // common job list                     // TODO: DO NOT FORGET TO DELETE VECTOR AT THE END. CHECK MEMORY LEAK.
list<struct activeJobs*> activeJobsList;    // list for active jobs
list<struct differentJobs*>::iterator it;   // iterator for job list
list<struct activeJobs*>::iterator it_activeJobs; // iterator for active jobs
pthread_mutex_t distinctJobMutex = PTHREAD_MUTEX_INITIALIZER; // mutex for common job list
pthread_mutex_t activeJobMutex = PTHREAD_MUTEX_INITIALIZER; // mutex for common job list
//map<string,struct displayOutput*> synOutputMap;  // map<IP,struct analysis>

struct activeJobs * activeJob = new struct activeJobs;
using namespace std;

void* startScan(void * ptr) {
	TCPUDPScan tcpUdpScan;
	char *ip;
	int port;
	string scanType;
	struct differentJobs *jobs;

	while (true) {
		pthread_mutex_lock(&distinctJobMutex);
		if (jobList.size() > 0) {
			// lock...take job.. remove job..unlock Mutex
			jobs = jobList.front();
			ip = jobs->ip;
			port = jobs->port;
			scanType = jobs->scanMethod;
			jobList.remove(jobs);
			pthread_mutex_unlock(&distinctJobMutex);
		} else {
			pthread_mutex_unlock(&distinctJobMutex);
			break;
		}
		pthread_mutex_lock(&activeJobMutex);
		bool isSameIpAndPortJob;
		if (!(activeJobsList.empty())) {
			// will go inside only if active job list is not empty
			for (it_activeJobs = activeJobsList.begin();
					it_activeJobs != activeJobsList.end(); it_activeJobs++) {
				bool isSameIpAndPortJob = true;
				struct activeJobs * localAJStruct = *it_activeJobs;
				int check = memcmp(jobs->ip, localAJStruct->ip, 50); // to check whether a new job is present in active jobs list or not
				bool checkIp = false; // to check for IP in both active job list and different job list
				if (check == 0) {
					checkIp = true;
				}
				if (!(checkIp && (localAJStruct->port == jobs->port))) { // go inside if its a new job with different ip and different port
					//call tcp or udp method with localDJStruct
					isSameIpAndPortJob = false;
					activeJob->ip = jobs->ip;
					activeJob->port = jobs->port;
					activeJobsList.push_back(activeJob); // if different job then add to active jobs list

					ip = jobs->ip;
					port = jobs->port;
					scanType = jobs->scanMethod;
					delete jobs;
					jobList.remove(jobs); // remove distinct from different jobs list after assigning it properly
					pthread_mutex_unlock(&activeJobMutex);
					if (scanType.compare("UDP") == 0) {
						cout << ip << port << scanType << endl;
						tcpUdpScan.scanUDPport(ip, port); // scan udp port
					} else {
						cout << ip << port <<"job to be done"<< endl;
						tcpUdpScan.scanTCPport(ip, port, scanType);
					}
					pthread_mutex_lock(&activeJobMutex);
					activeJobsList.remove(activeJob);
					pthread_mutex_unlock(&activeJobMutex);
					break;
				} else {
					pthread_mutex_unlock(&activeJobMutex);
				}
			}
			if (isSameIpAndPortJob) {
				pthread_mutex_lock(&distinctJobMutex);
				jobList.push_back(jobs);
				pthread_mutex_unlock(&distinctJobMutex);
			}
		} else {
			// put 1st job in active queue;
			activeJob->ip = jobs->ip;
			activeJob->port = jobs->port;
			activeJobsList.push_back(activeJob); // if different job then add to active jobs list
			ip = jobs->ip;
			port = jobs->port;
			scanType = jobs->scanMethod;
			delete jobs;
			jobList.remove(jobs); // remove distinct from different jobs list after assigning it properly
			pthread_mutex_unlock(&activeJobMutex);
			if (scanType.compare("UDP") == 0) {
				cout << ip << port << scanType <<endl;
				tcpUdpScan.scanUDPport(ip, port); // scan udp port
			} else {
				cout << ip << port <<"job to be done"<< endl;
				tcpUdpScan.scanTCPport(ip, port, scanType);
				pthread_mutex_lock(&activeJobMutex);
				activeJobsList.remove(activeJob);
				pthread_mutex_unlock(&activeJobMutex);
			}
		}

	}
	pthread_exit(0);
	return NULL;
}

int main(int argc, char * argv[]) {
	ps_setup pssetup;
	struct differentJobs jobs;
	TCPUDPScan tCPUDPScan;
	string flagToSet = "";
//list of jobs

//parse arguments
	pssetup.parseargs(argc, argv, &parseValues);

// to create number of jobs
	int i = 0;
	long noOfjobs = parseValues.ipAddressList.size()
			* parseValues.portsList.size() * parseValues.noOfmethodsToScan;
//it=jobList.begin();
	for (int i = 0; i < parseValues.ipAddressList.size(); i++) {
		for (int j = 0; j < parseValues.portsList.size(); j++) {

			if (parseValues.scanMethod[0] == 1) {

				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "SYN";
				jobList.push_back(insideJobs);
				//delete DotAddr;

			}
			if (parseValues.scanMethod[1] == 1) {
				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "FIN";
				jobList.push_back(insideJobs);
			}
			if (parseValues.scanMethod[2] == 1) {
				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "XMAS";
				jobList.push_back(insideJobs);
			}
			if (parseValues.scanMethod[3] == 1) {
				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "NULL";
				jobList.push_back(insideJobs);
			}
			if (parseValues.scanMethod[4] == 1) {
				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "UDP";
				jobList.push_back(insideJobs);
			}
			if (parseValues.scanMethod[5] == 1) {
				char *DotAddr = new char[15];
				struct differentJobs* insideJobs = new struct differentJobs;
				insideJobs->ip = pssetup.checkValidIP(
						parseValues.ipAddressList.at(i), DotAddr);
				insideJobs->port = parseValues.portsList.at(j);
				insideJobs->scanMethod = "ACK";
				jobList.push_back(insideJobs);
			}

		}

	}

	for (it = jobList.begin(); it != jobList.end(); it++) {
		struct differentJobs* ab = *it;
		cout << ab->ip << "\t" << ab->port << ab->scanMethod<<endl;
	}
// 0 - syn   1 - fin    2 -xmas    3 - null   4 -udp  5- ack
	pthread_t th[parseValues.noOfThreads];
	int threadReturn = 0;
	for (int i = 0; i < parseValues.noOfThreads; i++) {
		threadReturn = pthread_create(&th[i], NULL, startScan, (void*) NULL);

		if (threadReturn) {
			cout << "Error Creating in thread" << endl;
			exit(1);
		}

	}
	for (int i = 0; i < parseValues.noOfThreads; i++) {
		pthread_join(th[i], NULL);

	}

	vector<char*>::iterator it;
	//otp.displayScanningTime();
	//pssetup.display();
	for (it = parseValues.ipAddressList.begin();
			it != parseValues.ipAddressList.end(); it++) {

		char DotAddr[15];
		pssetup.checkValidIP(*it, DotAddr);
		tCPUDPScan.display(DotAddr, &parseValues);

	}

	for (it = parseValues.ipAddressList.begin();
			it != parseValues.ipAddressList.end(); it++) {
		delete[] *it;
	}

	cout << "End main" << endl;

	return 0;
}
