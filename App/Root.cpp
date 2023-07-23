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
    ecall_root_size( global_eid_leader, total_primary,total_replica);
}

void Root::start() {

    int primary_address[total_primary];
    // test issue secret shares
    uint8_t  p_dst[ (total_replica+1) * (16*2+44)];
    ecall_leader_issueSecret(global_eid_leader, 0,  p_dst);


//
//
//    nlohmann::json j1 =  read_json_file("node_addresses.json");
//
//    for (int i = 0; i < total_node_address; i = i + total_replica + total_passive + 1 ){
//        // convert i to string
//        string s = to_string(i);
//        // get the address of the ith primary node
//        string ip = j1[s]["ip"];
//        int port = j1[s]["port"];
//        primary_address[i] = setup_connection(port,ip.c_str());
//        cout << "Primary address is " << primary_address[i] << endl;
//    }
//    uint8_t publicKey[64];
//
//    ecall_generate_PublicKey(global_eid_leader, publicKey);
//    cout << "Public key is " << publicKey << endl;
//
//    // send public key to all primary nodes
//    for(int i = 0; i < total_primary; i++){
//        send_message( primary_address[i], publicKey, 64);
//    }
//
//    cout << "Public key sent to all primary nodes" << endl;
//
//    // receive public key from all primary nodes and its replicas
//    for(int i = 0; i < total_primary; i++){
//        uint8_t temp_publicKey[64];
//        // get Leader's key
//        receive_message(primary_address[i], temp_publicKey, 64);
//        ecall_setNodeKey( global_eid_leader, temp_publicKey, i, 0);
//
//        for (int j = 1; j < total_replica+1; j++){
//            receive_message(primary_address[i], temp_publicKey, 64);
//            cout << "Public key received from primary node " << i << " replica " << j << endl;
//            cout << "Public key is " << temp_publicKey << endl;
//            ecall_setNodeKey( global_eid_leader, temp_publicKey, i, j);
//        }
//
//    }
//
//
//    // while(true){
//
//    // Root waits for the leader to request a set of secret-shares
//
//    uint8_t message[7];
//
//    receive_message(primary_address[0], message, 7);
//
//    if (!strcmp((char*)message, "request")){
//        cout << "Leader requested a set of secret-shares" << endl;
//        // Root generates a set of secret-shares
//
//    }
//    else{
//        cout << "Leader did not request a set of secret-shares" << endl;
//    }
//
//    // }
//



}

