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
#include "Leader_enc.h"
#include "enclave_shared.h"

int TOTAL_REPLICAS ;
int TOTAL_LEADERS;

// shared key for every node in the network
sgx_ec256_dh_shared_t * p_shared_key;

sgx_ec256_public_t * p_public_key;

// this key is used if you are leader node or replica node
sgx_ec256_dh_shared_t root_shared_key;

sgx_ec256_private_t private_key;
sgx_ec256_public_t public_key;


uint32_t * Node_counter;
uint32_t * view_counter;

uint32_t counter_local = 1;
uint32_t view_local = 0;

// for Shamir's secret sharing

// Prime choosen randomly
int64_t prime = 3219499371683451161;


using namespace std;



/*
 * Generate public key and private key and sets the public key in the parameter
 * arg : public key
 */

void ecall_generate_PublicKey( uint8_t publicKey[64])
{
    generate_key_pair( private_key, public_key);

    for (int i = 0; i < 64; i++)
    {
        publicKey[i] = public_key.gx[i] ;
        publicKey[i+32] =  public_key.gy[i];
    }

}


/*
 * Generate shared key and sets the shared key in the parameter
 * arg : public key
 */
void generate_sharedKey(uint8_t publicKey[64], sgx_ec256_dh_shared_t shared_key)
{
    sgx_ec256_public_t public_key;
    sgx_ec256_dh_shared_t *p_shared_key = &shared_key;
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
    generate_sharedKey(publicKey, root_shared_key);
}


void ecall_root_size(int  L_size, int  R_size)
{
    TOTAL_LEADERS = L_size;
    TOTAL_REPLICAS = R_size;

    p_shared_key = (sgx_ec256_dh_shared_t *) malloc(sizeof(sgx_ec256_dh_shared_t) * (TOTAL_LEADERS * TOTAL_REPLICAS));
    p_public_key = (sgx_ec256_public_t *) malloc(sizeof(sgx_ec256_public_t) * (TOTAL_LEADERS * TOTAL_REPLICAS));


    Node_counter = (uint32_t *) malloc(sizeof(uint32_t) * (TOTAL_LEADERS));

    view_counter = (uint32_t *) malloc(sizeof(uint32_t) * (TOTAL_LEADERS));

    for (uint32_t i = 0; i < TOTAL_LEADERS; i++)
    {
        Node_counter[i] = 1;
        view_counter[i] = 0;

    }

}




void ecall_setNodeKey(uint8_t publicKey[64], int serial_index, int view_index)
{
    for (int i = 0; i < 32; i++)
    {
        p_public_key[serial_index * TOTAL_REPLICAS + view_index].gx[i] = publicKey[i];
        p_public_key[serial_index * TOTAL_REPLICAS + view_index].gy[i] = publicKey[i+32];
    }
    generate_sharedKey(publicKey, p_shared_key[serial_index * TOTAL_REPLICAS + view_index]);
}



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

    // generate shares
    *shares = S.split_secret(*secret, TOTAL_REPLICAS+1);

    // hash ( secret || counter || serial_num || view_num )

    sgx_sha_state_handle_t h_sha;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_sha256_init(&h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_init failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_update((const uint8_t *) &secret, sizeof(secret), h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_update failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_update((const uint8_t *) &Node_counter[Serial_num], sizeof(Node_counter[Serial_num]), h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_update failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_update((const uint8_t *) &Serial_num, sizeof(Serial_num), h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_update failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_update((const uint8_t *) &view_counter, sizeof(view_counter[Serial_num]), h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_update failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_get_hash(h_sha, h_ck);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_get_hash failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_sha256_close(h_sha);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_close failed [%s].\n", __FUNCTION__);
        return;
    }

    Node_counter[Serial_num]++;

}

// convert 64 bit uint to 8 bytes
void uint64_to_bytes(uint64_t num, uint8_t * bytes)
{
    for (int i = 0; i < 8; i++)
    {
        bytes[i] = (num >> (8 * i)) & 0xff;
    }
}

void ecall_leader_issueSecret(int Serial_num, uint8_t * p_dst)
{

    // uint64_t secret, vector<point> shares,sgx_sha256_hash_t* h_ck , uint8_t c_t[4], uint8_t v_t[4]
    int64_t secret = 0;
    vector<point> shares;
    sgx_sha256_hash_t h_ck;
    uint8_t c_t[4];
    uint8_t v_t[4];

    // copy 4 bytes of counter to c_t
    memcpy(c_t, &Node_counter[Serial_num], 4);
    // copy 4 bytes of view_counter to v_t
    memcpy(v_t, &view_counter[Serial_num], 4);

    generateSecret(Serial_num, &secret, &shares, &h_ck, c_t, v_t);

    printf("secret is %llu\n", secret);

    // print shares, hash and counters
    for (int i = 0; i < TOTAL_REPLICAS+1; i++)
    {
        printf("share %d is (%llu, %llu)\n", i, shares[i].x, shares[i].y);
    }
    printf("hash is ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", h_ck[i]);
    }
    printf("\n");
    printf("counter is %d\n", Node_counter[Serial_num]);
    printf("view_counter is %d\n", view_counter[Serial_num]);
    Shamir S = Shamir(prime);

    int64_t a = (S.reconstruct_secret(shares));

    printf("reconstructed secret is %llu\n", a);

    uint8_t p_src[TOTAL_REPLICAS+1][48+16*2];
    // encrypt E( share || h_ck || c_t || v_t )
    for (uint64_t i = 0 ; i < TOTAL_REPLICAS + 1 ; i++){
        uint64_t temp_secret_y = shares[i].y;

        uint8_t p_iv[12];
        uint8_t temp_secret_y_bytes[8];
        uint64_to_bytes(temp_secret_y, temp_secret_y_bytes);

        uint8_t all_bytes[8+32+4+4] = {0};

        for (int j = 0; j < 8; j++)
        {
            all_bytes[j] = temp_secret_y_bytes[j];
        }

        for (uint64_t j = 0; j < 32; j++)
        {
            all_bytes[j+8] = h_ck[j];
        }

        for (uint64_t j = 0; j < 4; j++)
        {
            all_bytes[j+40] = c_t[j];
        }

        for (uint64_t j = 0; j < 4; j++)
        {
            all_bytes[j+44] = v_t[j];
        }

        uint8_t key[16];
        memcpy(key, &p_shared_key[Serial_num * TOTAL_REPLICAS + i], 16);

        // tag
        uint8_t tag[16];
        // random IV
        sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE);

        encrypt_message(all_bytes, 8+32+4+4, p_src[i], key, p_iv, NULL, NULL,tag);
        printf("p_src1 is ");
        for (int j = 0; j < 48; j++)
        {
            printf("%02x", p_src[i][j]);
        }
        printf("\n");
        // copy iv to p_src
        for (int j = 0; j < SGX_AESGCM_IV_SIZE; j++)
        {
            p_src[i][j+48] = p_iv[j];
        }

        for (int j = 0; j < SGX_AESGCM_MAC_SIZE; j++)
        {
            p_src[i][j+48+12] = tag[j];
        }

        // print p_src
        printf("p_src is ");
        for (int j = 0; j < 48+16+12; j++)
        {
            printf("%02x", p_src[i][j]);
        }
        printf("\n");

    }

    // copy to p_dst
    for (int i = 0 ; i < TOTAL_REPLICAS + 1 ; i++){
        for (int j = 0; j < 48+16+12; j++)
        {
            p_dst[i*(44+16*2)+j] = p_src[i][j];
        }
    }

    // sign p_dst
    uint8_t signature[64];
    sgx_ec256_signature_t &signature1 = *(sgx_ec256_signature_t *) signature;
    sign_message(private_key, p_dst, (TOTAL_REPLICAS+1)*(48+16+12), signature1);






}
