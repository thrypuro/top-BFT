//
// Created by thrypuro on 17/07/23.
//

#include "Root.h"
#include "utils.h"
#include<unistd.h>
#include<iostream>


const uint32_t concat_size = 52;
const uint32_t hash_size = 32;
const uint32_t signature_size = 64;
const uint32_t public_key_size = 64;
const uint32_t encrypted_size = 52;
const uint32_t iv_size = 12;
const uint32_t tag_size = 16;
const uint32_t total_size = (concat_size + iv_size + tag_size);

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_leader;

Root::Root() {};

Root::~Root() {};

Root::Root(uint32_t total_primary, uint32_t total_replica, uint32_t total_passive, uint32_t total_node_address, sgx_enclave_id_t global_eid
)  : total_primary(total_primary), total_replica(total_replica), total_passive(total_passive), total_node_address(total_node_address)
{
    global_eid_leader = global_eid;
    ecall_root_size(global_eid_leader, total_primary, total_replica);
}

void Root::initialisation() {
    nlohmann::json j1 = read_json_file("node_addresses.json");

    for (uint32_t i = 0; i < total_node_address; i = i + total_replica + total_passive + 1) {
        // convert i to string
        string s = to_string(i);
        // get the address of the ith primary node
        string ip = j1[s]["ip"];
        int port = j1[s]["port"];
        primary_address.push_back(setup_connection(port, ip.c_str()));
    }
    uint8_t publicKey[public_key_size];

    ecall_generate_PublicKey(global_eid_leader, publicKey);

    // print public key in hex with printf
    printf("Public key is ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", publicKey[i]);
    }
    printf("\n");

    // send public key to all primary nodes
    for (int i = 0; i < total_primary; i++) {
        send_message(primary_address[i], publicKey, public_key_size);
    }


    // receive public key from all primary nodes and its replicas
    for (int i = 0; i < total_primary; i++) {
        uint8_t temp_publicKey[public_key_size];
        // get Leader's key
        receive_message(primary_address[i], temp_publicKey, public_key_size);
        ecall_setNodeKey(global_eid_leader, temp_publicKey, i, 0);

        for (int j = 1; j < total_replica + 1; j++) {
            receive_message(primary_address[i], temp_publicKey, 64);
            cout << "Public key received from primary node " << i << " replica " << j << endl;
            ecall_setNodeKey(global_eid_leader, temp_publicKey, i, j);
        }

    }
}

void Root::Prepare(int sockfd, int SerialNumber) {

        // Root generates a set of secret-shares
        uint8_t secret_shares[ ( concat_size + iv_size + tag_size)   * (total_replica+1)];
        uint8_t signature[64] = {0};

        ecall_leader_issueSecret(global_eid_leader, SerialNumber, (char *) secret_shares, signature,
                                  (total_size * (total_replica + 1)));
        // have the data in the form of json and send it to the leader
        // print signature in hex with printf
        printf("Ocall secret share is ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");

        nlohmann::json j2;
        j2["signature"] = string_to_hex(string((char *) signature, 64));
        //




        /*
         * {
         * "signature" : ... ,
         * secret_shares : {
         *              "0" : {
         *                   "encrypted_data" : ... ,
         *                   "iv" : ... ,
         *                   "tag" : ...
         *                   }
         *               "1" : {
         *               "encrypted_data" : ... ,
         *               "iv" : ... ,
         *
         *
         *  where, encrypted data is 52 bytes, iv is 12 bytes and tag is 16 bytes and signature is 64 bytes
         *  convert the data to hex before sending
         *
         */
        for (size_t j = 0; j < total_replica + 1; j++) {
            nlohmann::json j3;
            j3["encrypted_data"] = string_to_hex(string((char *) secret_shares + (j * total_size), concat_size));
            j3["iv"] = string_to_hex(string((char *) secret_shares + (j * total_size) + encrypted_size, iv_size));
            j3["tag"] = string_to_hex(string((char *) secret_shares + (j * total_size) + encrypted_size + iv_size, tag_size));
            j2[to_string(j)] = j3;
        }
        send_json(sockfd, j2,j2.dump().size());

}

void Root ::Verify(int sockfd, int SerialNumber) {
    uint8_t signature[signature_size*(total_replica+1)];
    uint8_t secret_shares[(7) * (total_replica + 1)];

    nlohmann::json j2;
    receive_json(sockfd, j2);
    cout << "Received json\n" << j2 << "\n";

    for (size_t j = 0; j < total_replica + 1; j++) {
//        uint8_t temp_signature[signature_size] = {0};
//        string signature_string = j2[to_string(j)]["signature"];
//        string_to_uint8(signature_string, signature_size, temp_signature);\

        // concat "Prepare" + hash + secret
//        string data = "Prepare";
//
//        string hash = j2[to_string(j)]["hash"];
//        string secret = j2[to_string(j)]["secret"];
//        for (unsigned char i : hash) {
//            data += i;
//        }
//        for (unsigned char i : secret) {
//            data += i;
//        }
//
//
//        // verify signature
//        uint8_t verify;
//        //         public void ecall_root_verify( [in,size=data_len] uint8_t * p_data, uint32_t data_len, [in] uint8_t * p_signature,int Serial_num, int Replica_num,uint8_t verify);
//
//        ecall_root_verify(global_eid_leader, (uint8_t *) data.c_str(), data.size(), temp_signature, SerialNumber, j,
//                          verify);

        // retrieve secret shares
        string secret_shares_string = j2[to_string(j)]["secret"];
        hex_to_uint8(secret_shares_string, 8, secret_shares + (j * 8));
    }

    // verify secret
    uint8_t verify[1];
    long long secret[1];
    // public void ecall_verify_secret([in,size=share_len] uint8_t * shares, uint32_t share_len, uint8_t verify )
    ecall_verify_secret(global_eid_leader, secret_shares, 8 * (total_replica + 1), verify,secret);

    if (verify[0] == 1) {
        cout << "Secret verified" << endl;
        // secret + request + request_output + hash+ counter + serial + view
        string s = to_string(secret[0]);
        s += j2["request"]["operation"];
        s +=  j2["request"]["timestamp"];
        s += j2["output"];
        s += j2["0"]["hash"];
        s += j2["0"]["counter"];
        s += j2["0"]["serial"];
        s += j2["0"]["view"];

        // hash s
        uint8_t hash[hash_size] = {0};
        ecall_hash(global_eid_leader, (char *) s.c_str(), s.size(), hash);
        string s_hash = string((char *) hash, hash_size);
        blocks[s_hash] = s;

        // send hash and secret to all primary nodes in the form of a json
        nlohmann::json j3;
        j3["hash"] = string_to_hex(s_hash);
        j3["secret"] = string_to_hex(to_string(secret[0]));
        for (int i = 0; i < total_primary; i++) {
            send_json(primary_address[i], j3,j3.dump().size());
        }

    } else {
        cout << "Secret not verified" << endl;
    }

}


void Root::start() {



    initialisation();

    // print primary addresses
    for (int i = 0; i < total_primary; i++) {
        cout << "Primary address is " << primary_address[i] << endl;
    }


    while (true) {
        struct pollfd pfds[total_primary];
        // once input is
        for (int i = 0; i < total_primary; i++) {
            pfds[i].fd = primary_address[i];
            pfds[i].events = POLLIN;
        }

        int num_events = poll(pfds, total_primary, -1);
        if (num_events == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }


        for (int i = 0; i < total_primary; i++) {


            if (pfds[i].revents & POLLIN) {
                // do stuff
                cout << "Primary node " << i << " is ready to receive" << endl;
                uint8_t message[8]  = {0};
                receive_message(primary_address[i], message, 8);
                cout << "Message received is " << message << endl;

                if (!strcmp((char *) message, "request")) {
                    cout << "Received request from primary node " << i << endl;
                    Prepare(primary_address[i],i);
                } else if (!strcmp((char *) message, "verify")) {

                    cout << "Received verify from primary node " << i << endl;
                    // verify signature and secret logic
                    Verify(primary_address[i],i);

                } else {
                    cout << "Unknown message received" << endl;
                    sleep(2);

                }


            }


        }


    }
}

