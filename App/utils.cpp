//
// Created by thrypuro on 18/07/23.
//

#include "utils.h"

// Utility function to set up a connection
// Mainly to connect with Replica and Passive nodes
int setup_connection(int port, const char *ip_addr) {
    struct sockaddr_in addr;
    int sockfd;
    int ret;
    int opt = 1;
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket\n");
        exit(1);
    }
    // Set socket options

    // Set up address
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) port);
    ret = inet_pton( AF_INET, ip_addr, &addr.sin_addr );
    if (ret < 0) {
        printf("Error converting ip address\n");
        exit(1);
    }
    // connect to the address and port and make sure the ip address is valid
    ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        printf("Error connecting to address\n");
        exit(1);
    }

    return sockfd;
}

// open a port, bind and listen
int start_port( int port ) {
    int sockfd;
    struct sockaddr_in addr;
    int ret;
    int opt = 1;
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket\n");
        return -1;
    }
    // Set socket options
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    if (ret < 0) {
        printf("Error setting socket options\n");
        return -1;
    }
    // Set up address
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to address
    ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printf("Error binding socket to address\n");
        exit(1);
    }
    // Listen for connections
    ret = listen(sockfd, 1024);
    if (ret < 0) {
        printf("Error listening for connections\n");
        exit(1);
    }

    // accept connection
    int addrlen = sizeof(addr);
    int new_socket = accept(sockfd, (struct sockaddr *)&addr, (socklen_t*)&addrlen);
    std::cout << "new socket is " << new_socket << std::endl;
    if (new_socket < 0) {
        printf("Error accepting connection\n");
        exit(1);
    }

    return new_socket;
}


int send_message(int sockfd, uint8_t *message, int size) {
    int ret;
    ret = send(sockfd, message, size * sizeof(uint8_t), 0);
    if (ret < 0) {
        printf("Error sending message\n");
        exit(1);
    }
    return ret;
}

int receive_message(int sockfd, uint8_t *message, int size) {
    int ret;
    ret = recv(sockfd, message, size* sizeof(uint8_t), 0);
    if (ret < 0) {
        printf("Error receiving message\n");
        exit(1);
    }
    return ret;
}

nlohmann::json read_json_file(const char *filename) {
    std::ifstream i(filename);
    if (!i.is_open()) {
        std::cout << "Error opening file " << filename << std::endl;
        exit(1);
    }
    nlohmann::json j;
    i >> j;
    return j;
}