//
// Created by thrypuro on 18/07/23.
//

#ifndef TOP_BFT_DISS_UTILS_H
#define TOP_BFT_DISS_UTILS_H
// socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

int setup_connection(int port, const char *ip_addr);

int start_port( int port  );

#endif //TOP_BFT_DISS_UTILS_H
