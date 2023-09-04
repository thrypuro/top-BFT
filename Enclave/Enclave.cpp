/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include<iostream>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <sgx_tcrypto.h>
#include "sgx_trts.h"

#include "Shamir.h"
#include "enclave_shared.h"

uint32_t TOTAL_REPLICAS = 0;
uint32_t TOTAL_LEADERS = 0;

// shared key for every node in the network
std :: unique_ptr< sgx_ec256_dh_shared_t[] > p_shared_key;

//sgx_ec256_public_t * p_public_key;
std :: unique_ptr< sgx_ec256_public_t[] > p_public_key;

// this key is used if you are leader node or replica node
sgx_ec256_dh_shared_t root_shared_key;

sgx_ec256_public_t leader_public_key;

sgx_ec256_private_t private_key;
sgx_ec256_public_t root_public_key;


std :: unique_ptr< uint32_t[] > Node_counter;

std :: unique_ptr< uint32_t[] > view_counter;


uint32_t counter_local = 0;
uint32_t view_local = 0;

// for Shamir's secret sharing

// Prime choosen randomly
int64_t prime = 3219499371683451161;
int64_t secret = 0;

int64_t secret_local = 0;
vector<point> shares_local;

// const
const uint32_t concat_size = 52;
const uint32_t hash_size = 32;
const uint32_t signature_size = 64;
const uint32_t public_key_size = 64;
const uint32_t encrypted_size = 52;
const uint32_t iv_size = 12;
const uint32_t tag_size = 16;
const uint32_t total_size = (concat_size + iv_size + tag_size);
const uint32_t secret_size = 7;

using namespace std;


/*
 * Set Leader public key in enclave (used by the replica node)
 */
void ecall_setLeaderPublicKey(uint8_t publicKey[64])
{
    for (int i = 0; i < 32; i++)
    {
        leader_public_key.gx[i] = publicKey[i];
        leader_public_key.gy[i] = publicKey[i+32];
    }
}




/*
 * Generate public key and private key and sets the public key in the parameter
 * arg : public key
 */

void ecall_generate_PublicKey( uint8_t publicKey[64])
{

    generate_key_pair( &private_key, &root_public_key);


    for (int i = 0; i < 32; i++)
    {
        publicKey[i] = root_public_key.gx[i] ;
        publicKey[i+32] =  root_public_key.gy[i];
    }

    // print public key
    printf("ECALL public key is ");
    for (int i = 0; i < 64; i++)
    {
        printf("%02x", publicKey[i]);
    }
    printf("\n");


}


/*
 * Generate shared key and sets the shared key in the parameter
 * arg : public key
 */
void generate_sharedKey(uint8_t publicKey[64], sgx_ec256_dh_shared_t * shared_key)
{
    sgx_ec256_public_t public_key;
    sgx_ec256_dh_shared_t *p_shared_key = shared_key;
    sgx_ec256_public_t *p_public_key = &public_key;

    for (int i = 0; i < 32; i++)
    {
        p_public_key->gx[i] = publicKey[i];
        p_public_key->gy[i] = publicKey[i+32];
    }

    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_open_context failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_compute_shared_dhkey(&private_key, p_public_key, p_shared_key, ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_compute_shared_dhkey failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_close_context(ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_close_context failed [%s].\n", __FUNCTION__);
        return;
    }

}

/*
 * Generate shared key and sets the shared key in the parameter
 * arg : public key
 */
void ecall_root_sharedKey(uint8_t publicKey[64])
{
    generate_sharedKey(publicKey, &root_shared_key);
}


void ecall_root_size(uint32_t  L_size, uint32_t  R_size)
{
    TOTAL_LEADERS = L_size;
    TOTAL_REPLICAS = R_size;

    // print Total leaders and replicas

    p_shared_key = std :: unique_ptr< sgx_ec256_dh_shared_t[] > (new sgx_ec256_dh_shared_t[TOTAL_LEADERS * (1+TOTAL_REPLICAS)]);
    p_public_key = std :: unique_ptr< sgx_ec256_public_t[] > (new sgx_ec256_public_t[TOTAL_LEADERS * (1+TOTAL_REPLICAS)]);



    Node_counter = std :: unique_ptr< uint32_t[] > (new uint32_t[TOTAL_LEADERS]);

    view_counter = std :: unique_ptr< uint32_t[] > (new uint32_t[TOTAL_LEADERS]);

    for (int i = 0; i < TOTAL_LEADERS; i++)
    {
        Node_counter[i] = 1;
        view_counter[i] = 0;

        // print Node_counter[i]
        printf("Node_counter[%d] is %d\n", i, Node_counter[i]);
        printf("view_counter[%d] is %d\n", i, view_counter[i]);

    }

}




void ecall_setNodeKey(uint8_t publicKey[64], int serial_index, int view_index)
{
    for (int i = 0; i < 32; i++)
    {
        p_public_key[serial_index * TOTAL_REPLICAS + view_index].gx[i] = publicKey[i];
        p_public_key[serial_index * TOTAL_REPLICAS + view_index].gy[i] = publicKey[i+32];
    }
    generate_sharedKey(publicKey, &p_shared_key[serial_index * TOTAL_REPLICAS + view_index]);
}


// Root Functions Starts

void generateSecret(int Serial_num, int64_t * secret, vector<point>  * shares,sgx_sha256_hash_t* h_ck , uint8_t * c_t, uint8_t * v_t){

    //
    Shamir S = Shamir(prime);

    unsigned char randsecret[7] = {0};
    sgx_read_rand(randsecret, 6);
    // convert 8 bytes to uint64_t
    for (int i = 0; i < 7; i++)
    {
        *secret = (*secret << 8) + randsecret[i];
    }

    secret_local = *secret;
    // generate shares
    *shares = S.split_secret(*secret, TOTAL_REPLICAS+1);

    // convert serial number to 4 bytes
    uint8_t Serial_num_bytes[4];
    uint64_to_bytes(Serial_num, Serial_num_bytes);

    // hash ( secret || counter || serial_num || view_num )

    uint8_t all_bytes[7+4+4+4] = {0};
    // copy secret to all_bytes
    for (int i = 0; i < 7; i++)
    {
        all_bytes[i] = randsecret[i];
    }
    // copy counter to all_bytes
    for (int i = 0; i < 4; i++)
    {
        all_bytes[i+7] = c_t[i];
        all_bytes[i+15] = Serial_num_bytes[i];
        all_bytes[i+11] = v_t[i];
    }

    hash_message(all_bytes, 7+4+4+4, h_ck);

    Node_counter[Serial_num]++;

}



void ecall_leader_issueSecret(int Serial_num, char * encrypted_data, uint8_t signature[64], size_t len) {

    // uint64_t secret, vector<point> shares,sgx_sha256_hash_t* h_ck , uint8_t c_t[4], uint8_t v_t[4]
    vector<point> shares;
    sgx_sha256_hash_t h_ck;
    uint8_t c_t[4];
    uint8_t v_t[4];

    // print serial number
    printf("Serial_num is %d\n", Serial_num);

    // print Node_counter[Serial_num]
    printf("Node_counter[%d] is %d\n", Serial_num, Node_counter[Serial_num]);
    // print view_counter[Serial_num]
    printf("view_counter[%d] is %d\n", Serial_num, view_counter[Serial_num]);

    // copy counter to c_t
    uint32_to_bytes(Node_counter[Serial_num], c_t);
    // copy view_counter to v_t
    uint32_to_bytes(view_counter[Serial_num], v_t);


    generateSecret(Serial_num, &secret, &shares, &h_ck, c_t, v_t);

    shares_local = shares;

    printf("secret is %llu\n", secret);

    // print shares, hash and counters
    for (int i = 0; i < TOTAL_REPLICAS + 1; i++) {
//        printf("share %d is (%llu, %llu)\n", i, shares[i].x, shares[i].y); in hex
        printf("for share %d\n", i);
        printf("Share x = %02llx\n", shares[i].x);
        printf("Share y = %02llx\n", shares[i].y);
    }
    printf("hash is ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", h_ck[i]);
    }
    printf("\n");
    // print c_temp and v_temp
    printf("c_t is ");
    for (int i = 0; i < 4; i++) {
        printf("%02x", c_t[i]);
    }
    printf("\n");
    printf("v_t is ");
    for (int i = 0; i < 4; i++) {
        printf("%02x", v_t[i]);
    }
    printf("\n");
    Shamir S = Shamir(prime);

    int64_t a = (S.reconstruct_secret(shares));

    printf("reconstructed secret is %llu\n", a);


    uint8_t p_src[TOTAL_REPLICAS + 1][concat_size];
    uint8_t temp_iv[TOTAL_REPLICAS + 1][SGX_AESGCM_IV_SIZE];
    uint8_t temp_tag[TOTAL_REPLICAS + 1][SGX_AESGCM_MAC_SIZE];
    // encrypt E( share || h_ck || c_t || v_t )
    for (uint64_t i = 0; i < TOTAL_REPLICAS + 1; i++) {
        long long  temp_secret_y = shares[i].y;
        uint8_t p_secret_y[8] = {0};
        int jj = 0;
        while (temp_secret_y > 0) {
            p_secret_y[7-jj] = temp_secret_y % 256;
            temp_secret_y = temp_secret_y / 256;
            jj++;
        }

        // print p_secret_y
        printf("p_secret_y is ");
        for (int j = 0; j < 8; j++) {
            printf("%02x", p_secret_y[j]);
        }
        printf("\n");


        uint8_t p_iv[tag_size];
        uint8_t temp_secret_y_bytes[8];
        uint64_to_bytes(static_cast<uint64_t>(temp_secret_y), temp_secret_y_bytes);

        uint8_t all_bytes[concat_size];

        for (int j = 0; j < hash_size; j++) {
            all_bytes[j] = h_ck[j];
        }

        for (uint64_t j = 0; j < 8; j++) {
            all_bytes[j + hash_size] = p_secret_y[j];
        }

        for (uint64_t j = 0; j < 4; j++) {
            all_bytes[j + 40] = c_t[j];
        }

        for (uint64_t j = 0; j < 4; j++) {
            all_bytes[j + 44] = v_t[j];
        }
        // copy serial number to all_bytes
        uint8_t Serial_num_bytes[4];
        uint32_to_bytes((uint32_t) Serial_num, Serial_num_bytes);

        for (int j = 0; j < 4; j++) {
            all_bytes[j + 48] = Serial_num_bytes[j];
        }

        uint8_t key[SGX_AESCTR_KEY_SIZE];
        // copy from p_shared_key[i]

        for (int j = 0; j < SGX_AESCTR_KEY_SIZE; j++) {
            key[j] = p_shared_key[Serial_num * TOTAL_LEADERS + i * TOTAL_REPLICAS].s[j];
        }

        // print key
        printf("key is ");
        for (int j = 0; j < 16; j++) {
            printf("%02x", key[j]);
        }
        printf("\n");



        // tag
        uint8_t tag[tag_size];
        // random IV
        sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE);

        encrypt_message(all_bytes, concat_size, p_src[i], key, p_iv, NULL, NULL, tag);

        // decrypt
        uint8_t decrypted_data[concat_size];
        decrypt_message(p_src[i], concat_size, decrypted_data, key, p_iv, NULL, NULL, tag);
        printf("decrypted_data is ");
        for (int j = 0; j < concat_size; j++) {
            printf("%02x", decrypted_data[j]);
        }
        printf("\n");

        printf("p_src1 is ");
        for (int j = 0; j < concat_size; j++) {
            printf("%02x", p_src[i][j]);
        }
        printf("\n");
        // copy iv to p_src
        for (int j = 0; j < SGX_AESGCM_IV_SIZE; j++) {
            temp_iv[i][j] = p_iv[j];
        }

        for (int j = 0; j < SGX_AESGCM_MAC_SIZE; j++) {
            temp_tag[i][j] = tag[j];
        }

        // print iv and tag
        printf("iv is ");
        for (int j = 0; j < 12; j++) {
            printf("%02x", temp_iv[i][j]);
        }
        printf("\n");
        printf("tag is ");
        for (int j = 0; j < 16; j++) {
            printf("%02x", temp_tag[i][j]);
        }
        printf("\n");


    }

    // copy to encrypted_data
    for (int i = 0; i < TOTAL_REPLICAS + 1; i++) {
        for (int j = 0; j < concat_size; j++) {
            encrypted_data[i * (concat_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) + j] = p_src[i][j];
        }
        for (int j = 0; j < 12; j++) {
            encrypted_data[i * (concat_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) + concat_size +
                           j] = temp_iv[i][j];
        }
        for (int j = 0; j < 16; j++) {
            encrypted_data[i * (concat_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) + concat_size +
                           SGX_AESGCM_IV_SIZE + j] = temp_tag[i][j];
        }
    }

    // sign encrypted_data
    sgx_ec256_signature_t signature1;


    sign_message(&private_key, (uint8_t *) encrypted_data,
                 (TOTAL_REPLICAS + 1) * (concat_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE), &signature1);

    // copy signature1 to signature
    for (int i = 0; i < 8; i++) {
        uint8_t temp[4];
        uint32_to_bytes(signature1.x[i], temp);
        for (int j = 0; j < 4; j++) {
            signature[i * 4 + j] = temp[j];
        }

        uint32_to_bytes(signature1.y[i], temp);
        for (int j = 0; j < 4; j++) {
            signature[i * 4 + j + 32] = temp[j];
        }
    }

}

// Root Functions Ends


// Leader Functions Starts
void ecall_request_secret(char * all_data, size_t len,uint8_t signature[signature_size], uint8_t encrypted_data[concat_size], uint8_t iv[iv_size], uint8_t tag[tag_size])
{


    // verify signature
    sgx_ec256_signature_t signature1 = *(sgx_ec256_signature_t *) signature;
    verify_signature(&root_public_key, (uint8_t *) all_data, len, &signature1);

    // decrypt encrypted_data
    uint8_t key[16];

    // copy from p_shared_key[i]

    for (int j = 0; j < 16; j++) {
        key[j] = root_shared_key.s[j];
    }
    // print key
    printf("key is ");
    for (int j = 0; j < 16; j++) {
        printf("%02x", key[j]);
    }
    printf("\n");

    uint8_t decrypted_data[concat_size];

    // decrypt
    int ret = decrypt_message(encrypted_data, concat_size, decrypted_data, key, iv, NULL, NULL, tag);
    if (ret != 0)
    {
        return;
    }
    // extract counter and view_counter
    uint32_t counter = 0;
    uint32_t view_counter_l = 0;

    for (int i = 0; i < 4; i++)
    {
        counter = (counter << 8) + decrypted_data[43-i];

    }

    // print counter


    for (int i = 0; i < 4; i++)
    {
        view_counter_l = (view_counter_l << 8) + decrypted_data[47-i];
    }

    if ( counter_local+1 != counter ){
        printf("Verify counter failed\n");
        return;
    }

    if ( view_local != view_counter_l ){
        printf("Verify view_counter failed\n");
        return;
    }


    // update counter and view_counter
    counter_local ++;

    printf("Verify counter and view_counter success\n");

}

/*
 * Function TEE .call counter(x)
 *
 */
void ecall_call_counter(char * secret, uint32_t size_len,uint8_t signature[signature_size], int Serial_num, int counter_p, int view_num_p)
{

    // Sign ( x , counter , serial_num, view_num )
    uint8_t Serial_num_bytes[4];
    uint64_to_bytes(Serial_num, Serial_num_bytes);
    uint8_t all_bytes[size_len+4+4+4];
    // copy secret to all_bytes
    for (int i = 0; i < size_len; i++)
    {
        all_bytes[i] = secret[i];
    }
    // copy counter to all_bytes
    for (int i = 0; i < 4; i++)
    {
        all_bytes[i+7] = counter_local;
        all_bytes[i+15] = Serial_num_bytes[i];
        all_bytes[i+11] = view_local;
    }

    sgx_ec256_signature_t signature1 = *(sgx_ec256_signature_t *) signature;
    sign_message(&private_key, all_bytes, size_len+4+4+4, &signature1);

    counter_p = counter_local;
    view_num_p = view_local;

    printf("call counter success\n");

}



// Leader Functions Ends



// verify counter and view_counter
/*
 * hash
 *
 */
void ecall_verify_counter(uint8_t hash[hash_size] ,uint8_t signature[signature_size],
                          uint32_t leader_view,uint32_t leader_counter, uint8_t encrypted_data[concat_size], uint8_t iv[iv_size], uint8_t tag[tag_size]
                          ,uint8_t secret[8] , uint8_t verify
                          ){
    // verify signature
    sgx_ec256_signature_t signature1 = *(sgx_ec256_signature_t *) signature;
    verify_signature(&leader_public_key, encrypted_data, hash_size+4+4+4, &signature1);

    // decrypt encrypted_data
    uint8_t decrypted_data[concat_size];
    uint8_t key[16];

    // copy from root_shared_key

    for (int j = 0; j < 16; j++) {
        key[j] = root_shared_key.s[j];
    }

    uint8_t all_data[concat_size] = {0};

    for (int i = 0; i < concat_size; i++)
    {
        all_data[i] = encrypted_data[i];
    }

    // decrypt
    decrypt_message(all_data, concat_size, decrypted_data, key, iv, NULL, NULL, tag);

    printf("Decryption success\n");

    for (int i = 0; i < concat_size; i++)
    {
        printf("%02x", decrypted_data[i]);
    }

    // hash is decrypted_data[0:32], counter is decrypted_data[32:36], view_counter is decrypted_data[36:40], rest is secrete
    uint8_t l_hash[32];
    uint32_t counter = 0;
    uint32_t view_counter_l = 0;

    for (int i = 0; i < 32; i++)
    {
        l_hash[i] = decrypted_data[i];
    }
    for (int i = 0; i < 4; i++)
    {
        counter = (counter << 8) + decrypted_data[i+32+7];
    }
    for (int i = 0; i < 4; i++)
    {
        view_counter_l = (view_counter_l << 8) + decrypted_data[i+44];
    }
    printf("\n");

    for (int i = 0; i < 8; i++)
    {
        secret[i] = decrypted_data[i+hash_size];
        // print decrypted_data[i+hash_size]
        printf("%02x", decrypted_data[i+hash_size]);
    }

    printf("\n");

    // if (c′_k , v′_k , s′_k )̸ = (c_k , v_k , s_k ) then “ invalid ordering”;
    if ( counter != leader_counter ){
        verify= false;
    }
    if ( view_counter_l != leader_view ){
        verify= false;
    }



    if ( counter_local+1 != counter ){
        verify = false;
    }
    if ( view_local != view_counter_l ){
        verify = false;
    }

    counter_local ++;

    verify = true;

}



bool ecall_update_counter(int Serial_num, uint8_t encrypted_data[concat_size],uint8_t iv[12], uint8_t tag[16], uint8_t signature[64], uint8_t * secret)
{
    sgx_ec256_signature_t signature1 = *(sgx_ec256_signature_t *) signature;

    // verify signature with leader_public_key
    verify_signature(&leader_public_key, encrypted_data, concat_size, &signature1);

    // decrypt encrypted_data
    uint8_t decrypted_data[concat_size];
    uint8_t key[16];

    // copy from p_shared_key[i]

    for (int j = 0; j < 16; j++) {
        key[j] = root_shared_key.s[j];
    }

    uint8_t all_data[concat_size] = {0};

    for (int i = 0; i < concat_size; i++)
    {
        all_data[i] = encrypted_data[i];
    }

    // decrypt
    decrypt_message(all_data, concat_size, decrypted_data, key, iv, NULL, NULL, tag);

    // hash is decrypted_data[0:32], counter is decrypted_data[32:36], view_counter is decrypted_data[36:40]
    uint8_t hash[32];
    uint32_t counter = 0;
    uint32_t view_counter_l = 0;

    for (int i = 0; i < 32; i++)
    {
        hash[i] = decrypted_data[i];
    }
    for (int i = 0; i < 4; i++)
    {
        counter = (counter << 8) + decrypted_data[i+32];
    }
    for (int i = 0; i < 4; i++)
    {
        view_counter_l = (view_counter_l << 8) + decrypted_data[i+36];
    }

    if ( counter_local+1 != counter ){
        return false;
    }
    if ( view_local != view_counter_l ){
        return false;
    }

    // check if Hash ( secret || counter || serial_num || view_num ) == hash


    uint8_t all_bytes[7+4+4+4] = {0};
    // copy secret to all_bytes
    for (int i = 0; i < 7; i++)
    {
        all_bytes[i] = secret[i];
    }
    // copy counter to all_bytes
    for (int i = 0; i < 4; i++)
    {
        all_bytes[i+7] = decrypted_data[i+32];
        all_bytes[i+15] = decrypted_data[i+36];
    }

    sgx_sha256_hash_t h_ck;
    hash_message(all_bytes, 7+4+4+4, &h_ck);

    // compare hash and h_ck
    for (int i = 0; i < 32; i++)
    {
        if ( hash[i] != h_ck[i] ){
            return false;
        }
    }
    counter_local ++;

    return true;
}



void ecall_hash(char * p_src, uint32_t src_len, uint8_t * p_hash)
{

    hash_message( (uint8_t *) p_src, src_len, (sgx_sha256_hash_t *) p_hash);
}

void ecall_sign(uint8_t * p_data, uint32_t data_len, uint8_t * p_signature)
{
    sign_message(&private_key, p_data, data_len, (sgx_ec256_signature_t *) p_signature);
}


void ecall_verify(uint8_t * p_data, uint32_t data_len, uint8_t * p_signature, uint8_t verify)
{
    verify_signature(&root_public_key, p_data, data_len, (sgx_ec256_signature_t *) p_signature);
    verify = 1;
}

void ecall_root_verify( uint8_t * p_data, uint32_t data_len, uint8_t * p_signature,int Serial_num, int Replica_num,uint8_t verify)
{
    sgx_ec256_public_t temp_public_key;
    // copy from  p_public_key[Serial_num * TOTAL_LEADERS + Replica_num * TOTAL_REPLICAS];
    for (int i = 0; i < 32; i++)
    {
        temp_public_key.gx[i] = p_public_key[Serial_num * TOTAL_LEADERS + Replica_num * TOTAL_REPLICAS].gx[i];
        temp_public_key.gy[i] = p_public_key[Serial_num * TOTAL_LEADERS + Replica_num * TOTAL_REPLICAS].gy[i];
    }
    verify_signature(&temp_public_key, p_data, data_len, (sgx_ec256_signature_t *) p_signature);
    verify = 1;
}

void ecall_verify_secret(uint8_t * shares,uint32_t share_len, uint8_t verify[1], long long secret[1] ){

    // print secret
    printf("secret is %llu\n", secret_local);
    // print uint8_t * shares
    for (int i = 0; i < share_len; i++)
    {
        printf("%02x", shares[i]);
    }
    printf("\n");


    Shamir S = Shamir(prime);
    vector<point> shares1;
    for (int i = 8; i < share_len+1; i=i+8)
    {
        long long  x = i>>3;
        long long  y = 0;
        for (int j = 0; j < 8; j++)
        {
            y = (y << 8) + shares[(x-1)*8 + j];
        }

        shares1.push_back(point{x,y});
    }



    auto s = S.reconstruct_secret(shares1);

    if ( s != secret_local ){
        verify[0] = 0;
        printf("Verify secret failed\n");
        // print shares1 and shares local
        for (int i = 0; i < TOTAL_REPLICAS + 1; i++) {
            printf("share %d is (%llu, %llu)\n", i, shares1[i].x, shares1[i].y);
        }
        for (int i = 0; i < TOTAL_REPLICAS + 1; i++) {
            printf("share %d is (%llu, %llu)\n", i, shares_local[i].x, shares_local[i].y);
        }
        // print local secret and secret
        printf("local secret is %llu\n", secret_local);
        printf("wrong secret is %llu\n", s);
        secret[0] = secret_local;

    }
    else{
        verify[0] = 1;
        printf("Verify secret success\n");
    }


}