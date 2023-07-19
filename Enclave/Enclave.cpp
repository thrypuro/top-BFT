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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <sgx_tcrypto.h>

// shared key for every node in the network
sgx_ec256_dh_shared_t p_shared_key[10][10];

// this key is used if you are leader node or replica node
sgx_ec256_dh_shared_t root_shared_key;

sgx_ec256_private_t private_key;
sgx_ec256_public_t public_key;

using namespace std;
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void printf_helloworld()
{
    printf("Hello World\n");
}


// generate Elliptic curve key pair

void generate_key_pair(sgx_ec256_private_t &private_key, sgx_ec256_public_t &public_key)
{
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_open_context failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_create_key_pair(&private_key, &public_key, ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_create_key_pair failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_close_context(ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_close_context failed [%s].\n", __FUNCTION__);
        return;
    }
    printf("generate key pair success\n");
}


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

