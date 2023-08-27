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
    struct sockaddr_in addr{};
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
    ssize_t ret = -1;

    ret = send(sockfd, message, size * sizeof(uint8_t), 0);
    if (ret < 0) {
        printf("Error sending message\n");
        exit(1);
    }

    return 0;
}

int receive_message(int sockfd, uint8_t *message, int size) {
    ssize_t ret;
    ret = recv(sockfd, message, size* sizeof(uint8_t), 0);
    if (size == 4){
        // print bytes in hex
        for (int i = 0; i < 4; i++){
            std :: cout << std :: hex << (int) message[i] << std :: endl;
        }
    }
    if (ret < 0) {
        printf("Error receiving message\n");
        exit(1);
    }
    return 0;
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

// convert 64 bit uint to 8 bytes
void uint64_to_bytes(uint64_t num, uint8_t bytes[8])
{
    for (int i = 0; i < 8; i++)
    {
        bytes[i] = (num >> (8 * i)) & 0xff;
    }
}

int send_json(int sockfd, nlohmann::json &j, size_t size)
{
    std::string s = j.dump();
    // send size of message first so that receiver knows how much to receive


    uint8_t bytes[8] = {0};
    uint64_to_bytes( s.size(), bytes);
    send_message(sockfd, bytes, 8);

//    std :: cout << "Sending size of json " << s.size() << std::endl;
//
//    std :: cout << "Sending json " << s << std::endl;
   send_message(sockfd, (uint8_t *) s.c_str(), s.size());

    return 0;

}

int receive_json(int sockfd, nlohmann::json & j)
{
    std :: cout << "Receiving json from " << sockfd << std::endl;
    int size = 0;
        uint8_t bytes[8] = {0};
        receive_message(sockfd, bytes, 8);
        for (int i = 0; i < 8; i++) {
            size += ( bytes[i]) << (8 * i);
        }




    std :: cout << "Size of json is " << size << std::endl;

    // make unique pointer
    std :: unique_ptr<uint8_t []> buffer (new uint8_t [size]);

     receive_message(sockfd, buffer.get(), (int) size);

     // print buffer
    j = nlohmann::json::parse(buffer.get());


    return 0;
}


std::string string_to_hex(const std::string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}


int hex_value(unsigned char hex_digit)
{
    static const signed char hex_values[256] = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    int value = hex_values[hex_digit];
    if (value == -1) throw std::invalid_argument("invalid hex digit");
    return value;
}

std::string hex_to_string(const std::string& input)
{
    const auto len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (auto it = input.begin(); it != input.end(); )
    {
        int hi = hex_value(*it++);
        int lo = hex_value(*it++);
        output.push_back(hi << 4 | lo);
    }
    return output;
}

void string_to_uint8( const std::string& input, size_t len, uint8_t * output)
{
    for (int i = 0; i < len; i++){
        output[i] = (uint8_t) input[i];
    }
}

void fulfill_client_request(const std::string& request, char * output){

    if (request == "NOP"){

        strcpy(output, "Did nothing");
    }

}


void hex_to_uint8( const std::string& input, size_t len, uint8_t * output)
{
    std :: string s = hex_to_string(input);
    string_to_uint8(s, len, output);
}
