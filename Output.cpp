/*
 * Output.cpp
 *
 *  Created on: Dec 5, 2014
 *      Author: jay
 */

#include "Output.h"

Output::Output() {
	// TODO Auto-generated constructor stub

}

Output::~Output() {
	// TODO Auto-generated destructor stub
}

void Output::displayScanningTime() {

	cout << "Scan Took " << endl;
}

void Output::display(string IpToPrint,
		std::map<string, struct displayOutput*> &mapToprint) {
	cout << "IP address :" << '\t' << IpToPrint << endl;
	cout << "Open Ports:" << endl;
	cout << "Port" << "\t\t\t" << "Service Name" << "\t\t\t"
			<< "Service Version" << "\t\t\t" << "Result" << "\t\t\t"
			<< "Conclusion" << endl;
	cout
			<< "----------------------------------------------------------------------------------------------------------------------------"
			<< endl;
	map<string, struct displayOutput*>::iterator it;
	it =mapToprint.find(IpToPrint);

	cout << it->second->port << it->second->result << endl;





}
