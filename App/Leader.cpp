//
// Created by thrypuro on 17/07/23.
//

#include "Leader.h"
#include "utils.h"
#include <iostream>
#include <string>

using  std :: cout , std :: endl, std :: string, std :: to_string, std :: hex, std :: strcpy, std :: strcat;


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_root;

const uint32_t concat_size = 52;
const uint32_t hash_size = 32;
const uint32_t signature_size = 64;
const uint32_t public_key_size = 64;
const uint32_t encrypted_size = 52;
const uint32_t iv_size = 12;
const uint32_t tag_size = 16;
const uint32_t total_size = (concat_size + iv_size + tag_size);



Leader::~Leader() {}



Leader ::Leader( int node_index, int serial_number,
                 int total_replica_nodes,
                 int total_passive_nodes, sgx_enclave_id_t  global_eid){
    this->total_replica_nodes = total_replica_nodes;
    this->total_passive_nodes = total_passive_nodes;
    this->node_index = node_index;
    this -> serial_number = serial_number;
    global_eid_root = global_eid;
}


void json_to_alldata( nlohmann::json j2, char * all_data, int total_replica_nodes){


for (uint32_t i = 0; i < (uint32_t) total_replica_nodes; i++) {
    string encrypted_data = j2[to_string(i)]["encrypted_data"];
    string iv = j2[to_string(i)]["iv"];
    string tag = j2[to_string(i)]["tag"];

    encrypted_data = hex_to_string(encrypted_data);
    iv = hex_to_string(iv);
    tag = hex_to_string(tag);

    uint8_t encrypted_data_uint8[concat_size];
    uint8_t iv_uint8[iv_size];
    uint8_t tag_uint8[tag_size];


    string_to_uint8(encrypted_data, concat_size, encrypted_data_uint8);
    string_to_uint8(iv, iv_size, iv_uint8);
    string_to_uint8(tag, tag_size, tag_uint8);

    for (uint32_t j = 0; j < concat_size; j++) {
        all_data[i * total_size + j] = (char) encrypted_data_uint8[j];
    }
    for (uint32_t j = 0; j < iv_size; j++) {
        all_data[i * total_size + concat_size + j] = (char)  iv_uint8[j];
    }
    for (uint32_t j = 0; j < tag_size; j++) {
        all_data[i * total_size + concat_size + iv_size + j] = (char)  tag_uint8[j];
    }
}

}

void Leader :: Initialise(){
    nlohmann::json j1 = read_json_file("node_addresses.json");

    root_address = start_port(j1[to_string(node_index)] ["port"]);


    uint8_t root_public_key [public_key_size];



    receive_message(root_address, root_public_key, public_key_size);

    cout << "Leader received root public key" << root_public_key << endl;
    cout << "Leader sending root public key to passive nodes" << endl;
    // send root public key to all replica nodes
    for(int i = 0; i < total_replica_nodes; i++){

        cout << "Replica index = " << node_index+1+ i << endl;
        string ip = j1[to_string(i)] ["ip"];
        int port  (j1[to_string(node_index+1+ i)] ["port"]);
        replica_address.push_back(setup_connection(port, ip.c_str()));
        send_message(replica_address[i], root_public_key, 64);
    }

    uint8_t  public_key[public_key_size];
    // Generate leader's public key and shared key with root
    ecall_generate_PublicKey(global_eid_root, public_key);

    ecall_root_sharedKey(global_eid_root,root_public_key);


    // Send leader's and Replica's public key to root
    send_message(root_address, public_key, public_key_size);
    for (int i = 0; i < total_replica_nodes; i++) {
        uint8_t  temp_public_key[64];
        send_message(replica_address[i], public_key, 64);
        receive_message(replica_address[i], temp_public_key, public_key_size);
        send_message(root_address, temp_public_key, public_key_size);
    }

}

void Leader::Pre_prepare(nlohmann::json request) {

    char  message[] = "request";
    send_message(root_address, (uint8_t *)message, 8);
    nlohmann::json j2;
    receive_json( root_address, j2);

    cout << "Leader received json from root" << endl;
    cout << j2 << endl;

    // retrieve leader's secret
    string encrypted_data = j2["0"]["encrypted_data"];
    string iv = j2["0"]["iv"];
    string tag = j2["0"]["tag"];
    string signature = j2["signature"];

    // print replica addresses

    // hex to string to uint8_t

    encrypted_data = hex_to_string(encrypted_data);
    iv = hex_to_string(iv);
    tag = hex_to_string(tag);
    signature = hex_to_string(signature);

    uint8_t encrypted_data_uint8[concat_size];
    uint8_t iv_uint8[iv_size];
    uint8_t tag_uint8[tag_size];
    uint8_t signature_uint8[signature_size];


    string_to_uint8(encrypted_data, concat_size, encrypted_data_uint8);
    string_to_uint8(iv, iv_size, iv_uint8);
    string_to_uint8(tag, tag_size, tag_uint8);
    string_to_uint8(signature, signature_size, signature_uint8);



    char all_data[total_size*(total_replica_nodes+1)];
    for (uint32_t i = 0; i < concat_size; i++) {
        all_data[i] = 0;
    }
    json_to_alldata( j2, all_data, total_replica_nodes);
    // check if requested secrets are valid before sending it off to replicas
    ecall_request_secret(global_eid_root, all_data, total_size*(total_replica_nodes+1),
                         signature_uint8, encrypted_data_uint8, iv_uint8, tag_uint8);



    // send encrypted data to replicas
    for (int i = 0; i < total_replica_nodes; i++) {

        nlohmann::json j3 = j2[to_string(i+1)];
        cout << "Sending prepare to replica " << replica_address[i] << endl;
        send_json(replica_address[i], j3,j3.dump().size());

    }

    // fulfill client request
    char output[100] = {0};
    string client_request = request["operation"];
    fulfill_client_request(client_request, output);
    cout << "Client request fulfilled" << endl;
    // concatenate output with the request json string
    char output_request[200] = {0};
    strcpy(output_request, client_request.c_str());
    strcat(output_request, output);

    cout << "\nOutput is " << output_request << "\n";

    // hash output_request
    uint8_t hash[hash_size] = {0};
    ecall_hash(global_eid_root, output_request, (uint32_t) sizeof(output_request), hash);

    // print hash
    cout << "Hash of output_request is " << endl;
    for (unsigned char i : hash) {
        cout << hex << (int) i;
    }
    cout << "\n";
    int counter, view;
    counter = 0;
    view = 0;
//    void ecall_call_counter(char * secret, uint32_t size_len,uint8_t signature[signature_size], int Serial_num, int counter_p, int view_num_p)
    uint8_t signature1[signature_size];
    ecall_call_counter(global_eid_root, (char *) hash, hash_size, signature1, serial_number, counter, view);

    nlohmann::json pre_prepare_message;
    pre_prepare_message["request"] = request;
    nlohmann::json j5;
    j5["leader_hash"] = hash;
    j5["leader_signature"] = signature1;
    j5["leader_view"] = view;
    j5["leader_counter"] = counter;
    pre_prepare_message["leader"] = j5;

    // send pre-prepare message to replicas
    for (int i = 0; i < total_replica_nodes; i++) {
        send_json(replica_address[i], pre_prepare_message,pre_prepare_message.dump().size());
    }
    cout << "Pre-prepare message sent to replicas" << endl;

    // verify counter
    uint8_t secret[8] = {0};
    uint8_t verify;
    ecall_verify_counter(global_eid_root, hash, signature1, view, counter,
                         encrypted_data_uint8, iv_uint8, tag_uint8, secret, verify);

    nlohmann::json prepare_messages;

//    string s = "Prepare";
//    // concat hash to s
//    for (unsigned char i : hash) {
//        s += i;
//    }
//    // concat secret to s
//    for (unsigned char i : secret) {
//        s += i;
//    }
//    uint8_t signature2[signature_size] = {0};
//    ecall_sign(global_eid_root, (uint8_t *) s.c_str(), s.size(), signature2);

    nlohmann::json j1;
//    j1["signature"] = signature2;

    j1["hash"] = string_to_hex(string((char *) hash, hash_size));
    j1["secret"] = string_to_hex(string((char *) secret, 8));
    j1["status"] = "Prepare";

    prepare_messages["0"] = j1;

    // print secret
    cout << "\n Secret is " << to_string((uint64_t)secret) << endl;


    /*
     * {
     * "0" : {
     *
     */

    // prepare
    // receive prepare message from replicas
    for (int i = 0; i < total_replica_nodes; i++) {
        nlohmann::json prepare_message;
        receive_json(replica_address[i], prepare_message);
        cout << "Leader received prepare message from replica " << i << endl;
        cout << prepare_message << endl;
        prepare_messages[to_string(i+1)] = prepare_message;
    }

    prepare_messages["request"] = request;
    prepare_messages["output"] = output;
    // send verify message to root

    send_message(root_address, (uint8_t *) "verify", 8);

    send_json(root_address, prepare_messages, prepare_messages.dump().size());


}

void Leader::Commit() {


    // receive commit json from root
    nlohmann::json commit_message;
    receive_json(root_address, commit_message);

    string block_hash = commit_message["block_hash"];
    string secret = commit_message["secret"];

    uint8_t hash[hash_size];
    // hash block_hash + secret
    string s = block_hash + secret;
    ecall_hash(global_eid_root, (char *) s.c_str(), s.size(), hash);

    send_message(root_address, (uint8_t *) "request", 8);



}

void Leader :: run (){

    /**
     * Initialisation phase
     */

    Initialise();
    /**
     * Initialisation Phase done
     */


    // while (true){

    /**
    * Pre-prepare phase
    */
    nlohmann::json request = read_json_file("request.json");

    Pre_prepare(request);


    // Leader Request a set of secret-shares from the root node

    Commit();



    // Leader receives a request from client

    // fake client request for testing

    // Pre-prepare stage done

    // Prepare stage

    


    // }
}



