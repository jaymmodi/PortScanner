/*
 * pssetup.cpp
 *
 *  Created on: Nov 2, 2014
 *      Author: vivek
 */

#include "pssetup.h"

ps_setup::ps_setup() {
	// TODO Auto-generated constructor stub

}

ps_setup::~ps_setup() {
	// TODO Auto-generated destructor stub
}

void ps_setup::parseargs(int argc, char **argv, struct parseV*parseValues) {
	int c;
	bool prefixflag = false;
	bool ipflag = false;
	bool fileflag = false;
	bool portflag = false;

	while (1) {
		static struct option long_options[] = { { "help", no_argument, 0, 'h' },
				{ "ports", required_argument, 0, 'p' }, { "ip",
				required_argument, 0, 'i' }, { "prefix",
				required_argument, 0, 'c' }, { "file",
				required_argument, 0, 'f' }, { "speedup",
				required_argument, 0, 't' }, { "scan",
				required_argument, 0, 's' }, { 0, 0, 0, 0 } };
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "hp:i:c:f:t:s:", long_options,
				&option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {

		case 'h':			//help
			printHelp();
			break;

		case 'p':			//ports
			portflag = true;
			generatePorts(optarg, parseValues);
			break;

		case 'i': {			//ip
			ipflag = true;
			char* ipOnConsole = new char[100];
			memcpy(ipOnConsole, optarg, 100);
			cout << ipOnConsole << endl;
			parseValues->ipAddressList.push_back(ipOnConsole);
			break;
		}
		case 'c':			//prefix CIDR
			prefixflag = true;
			generatePrefix(optarg, parseValues);
			break;

		case 'f':			//file open
			fileflag = true;
			openFile(optarg, parseValues);
			break;

		case 't':			//speedup threads
			cout << optarg << endl;
			parseValues->noOfThreads = atoi(optarg);
			break;

		case 's':			//scans
			if (fileflag || prefixflag || ipflag) {
				//scan logic
				int Location = optind - 1;
				int count = 0;
				while (Location < argc) {
					char *check = argv[Location];
					char syn[4] = "SYN";
					char fin[4] = "FIN";
					char xmas[5] = "XMAS";
					char null[5] = "NULL";
					char udp[4] = "UDP";
					char ack[4] = "ACK";
					if (!strncmp(check, syn, 4)) {
						parseValues->scanMethod[0] = 1;
						count++;
					} else if (!strncmp(check, fin, 4)) {
						parseValues->scanMethod[1] = 1;
						count++;
					} else if (!strncmp(check, xmas, 5)) {
						parseValues->scanMethod[2] = 1;
						count++;
					} else if (!strncmp(check, null, 5)) {
						parseValues->scanMethod[3] = 1;
						count++;
					} else if (!strncmp(check, udp, 4)) {
						parseValues->scanMethod[4] = 1;
						count++;
					} else if (!strncmp(check, ack, 4)) {
						parseValues->scanMethod[5] = 1;
						count++;
					}

					Location++;
				}
				//parseValues.
				parseValues->noOfmethodsToScan = count;

			} else {
				cout << "Please enter a IP or File name or Prefix ." << endl;
				printHelp();
				exit(1);
			}
			break;
		default:
			cout << "Please enter a IP or File name or Prefix ." << endl;
			printHelp();
			exit(1);
		}
	}

	if (!(fileflag || prefixflag || ipflag)) {
		cout << "Please enter a IP or File name or Prefix" << endl;
		printHelp();
		exit(1);

	}
	if ((ipflag || fileflag || prefixflag) && !(portflag)) {
		if (parseValues->portsList.size() == 0) {
			cout << "By Default Scanning 1-1024 Ports" << endl;

			for (int i = 1; i <= 1024; i++) {

				parseValues->portsList.push_back(i);
			}
		}
	}

}

void ps_setup::printHelp() {
	cout << "MAN PAGE PORTSCANNER:" << endl;
	cout << "COMMAND:" << endl;
	cout << "“$./portScanner [option1, ..., optionN]”\n" << endl;
	cout << "OPTIONS\t\t\tEXAMPLE" << endl;
	cout << "1 --help. Example: “./portScanner --help”." << endl;
	cout
			<< "2 --ports <ports to scan>. Example: “./portScanner --ports 1,2,3-5”."
			<< endl;
	cout
			<< "3 --ip <IP address to scan>. Example: “./portScanner --ip 127.0.0.1”."
			<< endl;
	cout
			<< "4 --prefix <IP prefix to scan>. Example: “./portScanner --prefix 127.143.151.123/24”."
			<< endl;
	cout
			<< "5 --file <file name containing IP addresses to scan>. Example: “./portScanner --file filename.txt”."
			<< endl;
	cout
			<< "6 --speedup <parallel threads to use>. Example: “./portScanner --speedup 10”."
			<< endl;
	cout
			<< "7 --scan <one or more scans>. Example: “./portScanner --scan SYN NULL FIN XMAS”."
			<< endl;
}

void ps_setup::generatePrefix(char* optarg, struct parseV* parseValues) {
	int CIDRNo = 0;
	int secondOctet = 0;
	int thirdOctet = 0;
	int fourthOctet = 0;
	int firstOctet = 0;
	int rangeOfIPaddress = 0;
	int startIndexOf4thOctet = 0;
	int lastIndexOf4thOctet = 0;
	int startIndexof3rdOctet = 0;
	int lastIndexof3rdOctet = 0;
	int startIndexof2ndOctet = 0;
	int lastIndexof2ndOctet = 0;
	int startIndexof1stOctet = 0;
	int lastIndexof1stOctet = 0;

	int i = 0;
	char * word;
	char * ipAddress;
	//it = ipAddressList.end();
	//only can have 2 tokens max, but may have less
	for (word = strtok(optarg, "./"), i = 0; (word && i < 5);
			word = strtok(NULL, "./"), i++) {
		//printf("%d:%s\n",i,word);
		switch (i) {
		case 0:			//firstOctet
			firstOctet = atoi(word);
			break;
		case 1:			//SecondOctet
			secondOctet = atoi(word);
			break;
		case 2:			//ThirdOctet
			thirdOctet = atoi(word);
			break;
		case 3:			//FourthOctet
			fourthOctet = atoi(word);
			break;
		case 4:			//CIDRindex
			CIDRNo = atoi(word);
			break;
		default:
			break;
		}

	}

	if (CIDRNo >= 24 && CIDRNo < 32) {
		rangeOfIPaddress = pow(2, 32 - CIDRNo);
		startIndexOf4thOctet = fourthOctet - (fourthOctet % rangeOfIPaddress);
		lastIndexOf4thOctet = startIndexOf4thOctet + rangeOfIPaddress - 1;

		startIndexof1stOctet = lastIndexof1stOctet = firstOctet;
		startIndexof2ndOctet = lastIndexof2ndOctet = secondOctet;
		startIndexof3rdOctet = lastIndexof3rdOctet = thirdOctet;

	}
	if (CIDRNo >= 16 && CIDRNo < 24) {
		rangeOfIPaddress = pow(2, 32 - CIDRNo);
		startIndexof3rdOctet = thirdOctet;
		lastIndexof3rdOctet = thirdOctet + ((rangeOfIPaddress / 256) - 1); // 256 is the maximum number of variation

		startIndexof1stOctet = lastIndexof1stOctet = firstOctet;
		startIndexof2ndOctet = lastIndexof2ndOctet = secondOctet;
		startIndexOf4thOctet = 0;
		lastIndexOf4thOctet = 255;

	}
	if (CIDRNo >= 8 && CIDRNo < 16) {
		rangeOfIPaddress = pow(2, 32 - CIDRNo);
		startIndexof2ndOctet = secondOctet;
		lastIndexof2ndOctet = secondOctet
				+ ((rangeOfIPaddress / 256 / 256) - 1);

		startIndexof1stOctet = lastIndexof1stOctet = firstOctet;
		startIndexOf4thOctet = 0;
		lastIndexOf4thOctet = 255;

		startIndexof3rdOctet = 0;
		lastIndexof3rdOctet = 255;

	}
	if (CIDRNo < 8) {
		rangeOfIPaddress = pow(2, 32 - CIDRNo);
		startIndexof1stOctet = firstOctet;
		lastIndexof1stOctet = firstOctet
				+ ((rangeOfIPaddress / 256 / 256 / 256) - 1);

		startIndexOf4thOctet = 0;
		lastIndexOf4thOctet = 255;

		startIndexof3rdOctet = 0;
		lastIndexof3rdOctet = 255;

		startIndexof2ndOctet = 0;
		lastIndexof2ndOctet = 255;

	}

	for (int l = startIndexof1stOctet; l <= lastIndexof1stOctet; l++) {
		for (int k = startIndexof2ndOctet; k <= lastIndexof2ndOctet; k++) {
			for (int j = startIndexof3rdOctet; j <= lastIndexof3rdOctet; j++) {
				for (int i = startIndexOf4thOctet; i <= lastIndexOf4thOctet;
						i++) {
					ipAddress = new char[15];
					sprintf(ipAddress, "%d.%d.%d.%d", l, k, j, i);
					parseValues->ipAddressList.push_back(ipAddress);
				}
			}
		}
	}

}
void ps_setup::openFile(char* optarg, struct parseV * parseValues) {
	std::ifstream ifs;
	ifs.open(optarg, std::ifstream::in);

	while (ifs.good()) {
		string ipOnLine;
		std::getline(ifs, ipOnLine);
		//struct sockaddr_in sa;
		if ((strlen(ipOnLine.c_str()))>2) {
			char * ipFromFile = new char[ipOnLine.size() + 1];
			std::copy(ipOnLine.begin(), ipOnLine.end(), ipFromFile);
			ipFromFile[ipOnLine.size()] = '\0';
			parseValues->ipAddressList.push_back(ipFromFile);
		}
	}

	ifs.close();
}
void ps_setup::generatePorts(char* optarg, struct parseV * parseValues) {
	char * pch;
	pch = strtok(optarg, ",");

	while (pch != NULL) {
		std::string str2(pch);
		if (str2.find("-") == -1) {
			int firstPortNumber = atoi(pch);
			if (firstPortNumber < 65535) {
				parseValues->portsList.push_back(firstPortNumber);
			} else {
				cout << "Port Number should be between 1-65535" << endl;
			}

		} else {
			string buffer = pch;
			int found = buffer.find("-");
			string temp = buffer.substr(0, found);
			int firstNo = stoi(temp);
			temp = buffer.substr(found + 1, buffer.length());
			int secondNo = stoi(temp);

			for (int i = firstNo; i <= secondNo; i++) {
				if (i < 65535) {
					parseValues->portsList.push_back(i);
				} else {
					cout << "Port Number should be between 1-65535" << endl;
				}
			}
		}
		pch = strtok(NULL, ",");
	}
	/*if (parseValues->portsList.size() == 0) {
	 for (int i = 1; i <= 1024; i++) {
	 cout << "By Default Scanning 1-1024 Ports" << endl;
	 parseValues->portsList.push_back(i);
	 }
	 }*/
	cout << "NO of ports :  " << parseValues->portsList.size() << endl;

}
char* ps_setup::checkValidIP(char * ipToScan, char* DotAddr) {

	struct sockaddr_in sa;
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
		//return or pthread exit not sure
	}
	return DotAddr;
}
/*
 void ps_setup::display() {

 char * DotAddr;
 string ipToPrint;
 vector<char*>::iterator it;
 for (it = parseValues.ipAddressList.begin();
 it != parseValues.ipAddressList.end(); it++) {

 checkValidIP(*it,DotAddr);
 memcpy(&ipToPrint,DotAddr,strlen(DotAddr));
 tCPUDPScan.display(ipToPrint);

 }

 }
 */
