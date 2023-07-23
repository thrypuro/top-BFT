//
// Created by thrypuro on 17/07/23.
//

#include "Leader.h"
#include <stdio.h>
#include "utils.h"

#include <iostream>

#include <string>



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_root;

using namespace std;


Leader::Leader() {}
Leader::~Leader() {}



Leader ::Leader( int node_index,int total_replica_nodes,
                 int total_passive_nodes, sgx_enclave_id_t  global_eid){
    this->total_replica_nodes = total_replica_nodes;
    this->total_passive_nodes = total_passive_nodes;
    this->node_index = node_index;
    global_eid_root = global_eid;
}

void Leader :: run (){

    /**
     * Initialisation phase
     */
    nlohmann::json j1 = read_json_file("node_addresses.json");

    int root_address = start_port(j1[to_string(node_index)] ["port"]);

    int replica_address[total_replica_nodes];

    uint8_t root_public_key [64];

    receive_message(root_address, root_public_key, 64);

    cout << "Leader received root public key" << root_public_key << endl;
    cout << "Leader sending root public key to passive nodes" << endl;
    // send root public key to all replica nodes
    for(int i = 0; i < total_replica_nodes; i++){

        cout << "Replica index = " << node_index+1+ i << endl;
        string ip = j1[to_string(i)] ["ip"];
        int port  (j1[to_string(node_index+1+ i)] ["port"]);

        replica_address[i] = setup_connection(port, ip.c_str());
        send_message(replica_address[i], root_public_key, 64);
    }

    uint8_t  public_key[64];
    // Generate leader's public key and shared key with root
    ecall_generate_PublicKey(global_eid_root, public_key);
    ecall_root_sharedKey(global_eid_root,root_public_key);


    // Send leader's and Replica's public key to root
    send_message(root_address, public_key, 64);
    for (int i = 0; i < total_replica_nodes; i++) {
        uint8_t  temp_public_key[64];
        receive_message(replica_address[i], temp_public_key, 64);
        send_message(root_address, temp_public_key, 64);
    }

    /**
     * Initialisation Phase done
     */

    /**
     * Pre-prepare phase
     */

    // while (true){

    // Leader receives a request from client

    // Leader Request a set of secret-shares from the root node



    // }
}



