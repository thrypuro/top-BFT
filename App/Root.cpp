//
// Created by thrypuro on 17/07/23.
//

#include "Root.h"
#include "utils.h"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

Root::Root() {};

Root::~Root() {};

Root::Root(int total_primary, int total_replica, int total_passive, int total_node_address) {
    this->total_primary = total_primary;
    this->total_replica = total_replica;
    this->total_passive = total_passive;
    this->total_node_address = total_node_address;
}

void Root::start() {

    int primary_address[total_primary];
    ifstream f1("node_addresses.json");
    if (!f1){
        cout << "Error opening file" << std :: endl;
        exit(1);
    }
    nlohmann::json j1;
    f1 >> j1;
    for (int i = 0; i < total_node_address; i = i + total_replica + total_passive + 1 ){
        // convert i to string
        string s = to_string(i);
        // get the address of the ith primary node
        string ip = j1[s]["ip"];
        int port = j1[s]["port"];
        primary_address[i] =  setup_connection(port, ip.c_str());
        cout << "Primary address is " << primary_address[i] << endl;

    }




}

