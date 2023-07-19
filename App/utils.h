//
// Created by thrypuro on 18/07/23.
//

#ifndef TOP_BFT_DISS_UTILS_H
#define TOP_BFT_DISS_UTILS_H

#include <stdint.h>
#include <iostream>
#include <stdio.h>
#include <fstream>
#include "json.hpp"
// socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>




int setup_connection(int port, const char *ip_addr);

int start_port( int port  );
int send_message(int sockfd, uint8_t *message, int size);
int receive_message(int sockfd, uint8_t *message, int size);
nlohmann::json read_json_file(const char *filename);
#endif //TOP_BFT_DISS_UTILS_H
