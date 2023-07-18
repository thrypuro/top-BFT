//
// Created by thrypuro on 18/07/23.
//

#include "utils.h"



// Utility function to set up a connection
// Mainly to connect with Replica and Passive nodes
int setup_connection(int port, const char *ip_addr) {
    struct sockaddr_in *addr;
    int *sockfd;
    int ret;
    int opt = 1;
    // Create socket
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0) {
        printf("Error creating socket\n");
        return -1;
    }
    // Set socket options
    ret = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    if (ret < 0) {
        printf("Error setting socket options\n");
        return -1;
    }
    // Set up address
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = inet_addr(ip_addr);

    // connect to the address and port and make sure the ip address is valid
    ret = connect(*sockfd, (struct sockaddr *)addr, sizeof(*addr));
    if (ret < 0) {
        printf("Error connecting to address\n");
        return -1;
    }

    return 0;
}

// open a port, bind and listen
int start_port( int port ) {
    int sockfd;
    struct sockaddr_in *addr;
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
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = INADDR_ANY;

    // Bind socket to address
    ret = bind(sockfd, (struct sockaddr *)addr, sizeof(*addr));
    if (ret < 0) {
        printf("Error binding socket to address\n");
        return -1;
    }
    // Listen for connections
    ret = listen(sockfd, 1024);
    if (ret < 0) {
        printf("Error listening for connections\n");
        return -1;
    }

    // accept connection
    int addrlen = sizeof(*addr);
    int new_socket = accept(sockfd, (struct sockaddr *)addr, (socklen_t*)&addrlen);

    return new_socket;
}