PortScanner :	tcpudpscan.o pssetup.o PortScanner.cpp	
		g++ -g -std=c++0x -pthread pssetup.o tcpudpscan.o PortScanner.cpp -o portScanner

pssetup.o:	pssetup.cpp
		g++ -g -std=c++0x -pthread -c pssetup.cpp -o pssetup.o

tcpudpscan.o:	TCPUDPScan.cpp
		g++ -g -std=c++0x -pthread -c TCPUDPScan.cpp -o tcpudpscan.o

clean:
	rm *.o portScanner















