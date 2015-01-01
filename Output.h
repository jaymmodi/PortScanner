/*
 * Output.h
 *
 *  Created on: Dec 5, 2014
 *      Author: jay
 */

#ifndef OUTPUT_H_
#define OUTPUT_H_
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


using namespace std;

class Output {
public:
	Output();
	virtual ~Output();

	void displayScanningTime();
	void display(string IpToPrint,std::map<string, struct displayOutput*> &mapToprint);

};


#endif /* OUTPUT_H_ */
