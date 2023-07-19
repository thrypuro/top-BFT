//
// Created by thrypuro on 17/07/23.
//

#include "Replica.h"

sgx_enclave_id_t global_eid_replica;

using namespace std;

Replica ::Replica() {
}


Replica :: ~Replica() {
}

Replica ::Replica(int node_index,int partition_num, int view_num, int leader_index, sgx_enclave_id_t eid) {
    this -> partition_num = partition_num;
    this -> view_num = view_num;
    this -> node_index = node_index;
    this -> leader_index = leader_index;
    global_eid_replica = eid;
}


void Replica :: run() {

    nlohmann::json j1 = read_json_file("node_addresses.json");
    int port = j1[to_string(node_index)]["port"];


    int replica_address = start_port(port);

    uint8_t ver_public_key[64];

    receive_message(replica_address, ver_public_key, 64);

   cout << "Dumb key : " << ver_public_key << endl;

   uint8_t  public_key[64];
    ecall_generate_PublicKey(global_eid_replica, public_key);

    ecall_root_sharedKey(global_eid_replica,public_key);

}