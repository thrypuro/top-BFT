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

#include <stdexcept>
#include <string>

// socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>




int setup_connection(int port, const char *ip_addr);

int start_port( int port  );
int send_message(int sockfd, uint8_t *message, int size);
int receive_message(int sockfd, uint8_t *message, int size);
nlohmann::json read_json_file(const char *filename);
int send_json(int sockfd, nlohmann::json &j,size_t size);
int receive_json(int sockfd, nlohmann::json &j);
std::string string_to_hex(const std::string& input);
std::string hex_to_string(const std::string& input);
void string_to_uint8( const std::string& input, size_t len, uint8_t * output);
void hex_to_uint8( const std::string& input, size_t len, uint8_t * output);
void fulfill_client_request(const std::string& request, char * output);
#endif //TOP_BFT_DISS_UTILS_H
