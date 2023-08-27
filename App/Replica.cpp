//
// Created by thrypuro on 17/07/23.
//

#include "Replica.h"

sgx_enclave_id_t global_eid_replica;
const uint32_t concat_size = 52;
const uint32_t hash_size = 32;
const uint32_t signature_size = 64;
const uint32_t public_key_size = 64;
const uint32_t encrypted_size = 52;
const uint32_t iv_size = 12;
const uint32_t tag_size = 16;
const uint32_t total_size = (concat_size + iv_size + tag_size);


using namespace std;

Replica::Replica() {

}


Replica::~Replica() {
}

Replica::Replica(int node_index , int partition_num , int view_num , int leader_index , sgx_enclave_id_t eid) {
    this->partition_num = partition_num;
    this->view_num = view_num;
    this->node_index = node_index;
    this->leader_index = leader_index;
    global_eid_replica = eid;
}

void Replica::Initialisation() {
    leader_address = start_port(port);
    uint8_t ver_public_key[public_key_size];
    uint8_t leader_public_key[public_key_size];

    cout << "Leader address : " << leader_address << "\n";

    receive_message(leader_address , ver_public_key , public_key_size);
    receive_message(leader_address , leader_public_key , public_key_size);
    ecall_setLeaderPublicKey(global_eid_replica , leader_public_key);

    cout << "Dumb key : " << hex << ver_public_key << "\n";
    cout << "Leader public key : " << hex << leader_public_key << "\n";
    uint8_t public_key[public_key_size];
    ecall_generate_PublicKey(global_eid_replica , public_key);

    ecall_root_sharedKey(global_eid_replica , ver_public_key);

    cout << "Public key : " << public_key << "\n";

    send_message(leader_address , public_key , public_key_size);


}

void Replica::Prepare(){
    nlohmann::json encrypted_data;
    receive_json(leader_address , encrypted_data);

    uint8_t encrypted_data_uint8[concat_size];
    uint8_t iv_uint8[iv_size];
    uint8_t tag_uint8[tag_size];

    hex_to_uint8(encrypted_data["encrypted_data"] , concat_size , encrypted_data_uint8);
    hex_to_uint8(encrypted_data["iv"] , iv_size , iv_uint8);
    hex_to_uint8(encrypted_data["tag"] , tag_size , tag_uint8);


    cout << "Received json\n" << encrypted_data << "\n";
    // Receive Pre-prepare message
//    while (true) {

    nlohmann::json leader_message;
    receive_json(leader_address , leader_message);
    cout << "Received json\n" << leader_message << "\n";

    /*
     *     j5["leader_hash"] = hash;
j5["leader_signature"] = signature1;
j5["leader_view"] = view;
j5["leader_counter"] = counter;
     */
    uint8_t leader_signature[signature_size] = {0};
    uint8_t leader_hash[hash_size] = {0};
    uint32_t leader_view = 0;
    uint32_t leader_counter = 0;
    for (size_t i = 0; i < signature_size; i++) {
        leader_signature[i] = leader_message["leader"]["leader_signature"][i];
    }
    for (size_t i = 0; i < hash_size; i++) {
        leader_hash[i] = leader_message["leader"]["leader_hash"][i];
    }
    leader_view = leader_message["leader"]["leader_view"];
    leader_counter = leader_message["leader"]["leader_counter"];




    // bool ecall_verify_counter(uint8_t hash[hash_size] ,uint8_t signature[signature_size],
    //                          uint32_t leader_view,uint32_t leader_counter, uint8_t encrypted_data[concat_size], uint8_t iv[iv_size], uint8_t tag[tag_size]
    //                          ,uint8_t secret[64]
    //                          )

    uint8_t secret[8] = {0};
    uint8_t verify;
    ecall_verify_counter(global_eid_replica , leader_hash , leader_signature , leader_view , leader_counter ,
                         encrypted_data_uint8 , iv_uint8 , tag_uint8 , secret , verify);

    string client_request = leader_message["request"]["operation"];
    char output[100] = {0};
    fulfill_client_request(client_request , output);
    // concatenate output with the request json string
    char output_request[200] = {0};
    strcpy(output_request , client_request.c_str());
    strcat(output_request , output);

    cout << "\nOutput is " << output_request << "\n";


    // hash output_request
    uint8_t hash[hash_size] = {0};
    ecall_hash(global_eid_replica , output_request , (uint32_t) sizeof(output_request) , hash);

    // print hash

    // compare leader hash and replica hash
    if (memcmp(hash , leader_hash , hash_size) != 0) {
        cout << "Hashes do not match" << endl;
        cout << " Faulty Leader Detected! " << endl;
        exit(1);
    }
    cout << "Hashes match" << endl;

    string s = "Prepare";
    // concat hash to s
    for (unsigned char i : hash) {
        s += i;
    }
    // concat secret to s
    for (unsigned char i : secret) {
        s += i;
    }
    // sign s
    uint8_t signature[signature_size] = {0};
    ecall_sign(global_eid_replica , (uint8_t *) s.c_str() , (uint32_t) s.size() , signature);

    nlohmann::json j6;

    j6["replica_signature"] = string_to_hex(string((char *) signature , 64));
    j6["replica_secret"] = string_to_hex(string((char *) secret , 8));
    j6["replica_hash"] = string_to_hex(string((char *) hash , 32));
    j6["status"] = "Prepare";

    send_json(leader_address , j6 , j6.dump().size());

}


void Replica::run() {

    nlohmann::json j1 = read_json_file("node_addresses.json");
    port = j1[to_string(node_index)]["port"];


    Initialisation();

    cout << "Initialisation done\n";



    // Prepare stage

    Prepare();

    cout << "Prepare stage done\n";




}