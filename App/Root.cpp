//
// Created by thrypuro on 17/07/23.
//

#include "Root.h"
#include "utils.h"



using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_leader;

Root::Root() {};

Root::~Root() {};

Root::Root(int total_primary, int total_replica, int total_passive, int total_node_address, sgx_enclave_id_t global_eid
) {
    this->total_primary = total_primary;
    this->total_replica = total_replica;
    this->total_passive = total_passive;
    this->total_node_address = total_node_address;
    global_eid_leader = global_eid;
}

void Root::start() {

    int primary_address[total_primary];

    nlohmann::json j1 =  read_json_file("node_addresses.json");

    for (int i = 0; i < total_node_address; i = i + total_replica + total_passive + 1 ){
        // convert i to string
        string s = to_string(i);
        // get the address of the ith primary node
        string ip = j1[s]["ip"];
        int port = j1[s]["port"];
        primary_address[i] = setup_connection(port,ip.c_str());
        cout << "Primary address is " << primary_address[i] << endl;
    }
    uint8_t publicKey[64];

    ecall_generate_PublicKey(global_eid_leader, publicKey);
    cout << "Public key is " << publicKey << endl;

    // send public key to all primary nodes
    for(int i = 0; i < total_primary; i++){
        send_message( primary_address[i], publicKey, 64);
    }

    cout << "Public key sent to all primary nodes" << endl;


}

