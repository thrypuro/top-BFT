//
// Created by thrypuro on 23/07/23.
//

#include "enclave_shared.h"
#include "Enclave_t.h"  /* print_string */
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
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
/**
 * AES-GCM encryption
 * IV cannot be reused for the same key, there is an attack on GCM which can recover the plaintext and key
 * if the same IV is used twice
 * p_add : additional data to be authenticated but not encrypted, this data in our code is used to distinguish Replicas and Leaders
 * p_add_len : length of additional data
 * p_dst : encrypted data
 */

void encrypt_message(uint8_t * p_src, uint32_t src_len, uint8_t * p_dst,
                     uint8_t * p_key, uint8_t * p_iv,
                     const uint8_t *p_aad, const uint8_t* p_add_len,
                     uint8_t * p_dst_tag
)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;



    ret = sgx_rijndael128GCM_encrypt( (sgx_aes_gcm_128bit_key_t *) p_key,
                                      p_src,
                                      src_len, p_dst, p_iv,
                                      SGX_AESGCM_IV_SIZE,
                                      p_add_len,
                                      0,
                                      (sgx_aes_gcm_128bit_tag_t *) p_dst_tag);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_rijndael128GCM_encrypt failed [%s].\n", __FUNCTION__);
        return;
    }
}

/**
 * AES-GCM decryption
 * p_add : additional data to be authenticated but not encrypted, this data in our code is used to distinguish Replicas and Leaders
 * p_add_len : length of additional data
 * p_dst : decrypted data
 */
int decrypt_message(uint8_t * p_src, uint32_t src_len, uint8_t * p_dst, uint8_t * p_key,
                     uint8_t * p_iv,const uint8_t *p_aad,const uint8_t* p_add_len, uint8_t * p_dst_tag)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;



    ret = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *) p_key,
                                     p_src,
                                     src_len, p_dst, p_iv,
                                     SGX_AESGCM_IV_SIZE,
                                     p_add_len,
                                     0,
                                     (sgx_aes_gcm_128bit_tag_t *) p_dst_tag);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_rijndael128GCM_decrypt failed [%s].\n", __FUNCTION__);
        return -1;
    }
    return 0;
}



// generate Elliptic curve key pair

void generate_key_pair(sgx_ec256_private_t *private_key, sgx_ec256_public_t *public_key)
{
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_open_context failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_create_key_pair(private_key, public_key, ecc_handle);
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


// sign the message with private key

void sign_message(sgx_ec256_private_t * private_key, uint8_t * p_src, uint32_t src_len, sgx_ec256_signature_t * signature)
{
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_open_context failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecdsa_sign(p_src, src_len, private_key, signature, ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecdsa_sign failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_close_context(ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_close_context failed [%s].\n", __FUNCTION__);
        return;
    }
    printf("sign message success\n");
}

// verify the signature with public key

void verify_signature(sgx_ec256_public_t *public_key, uint8_t * p_src, uint32_t src_len, sgx_ec256_signature_t * signature)
{
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_open_context failed [%s].\n", __FUNCTION__);
        return;
    }
    uint8_t verify_result = 0;
    ret = sgx_ecdsa_verify(p_src, src_len,public_key, signature, &verify_result, ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecdsa_verify failed [%s].\n", __FUNCTION__);
        return;
    }
    ret = sgx_ecc256_close_context(ecc_handle);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_ecc256_close_context failed [%s].\n", __FUNCTION__);
        return;
    }
    printf("verify signature success\n");
}

// convert 64 bit uint to 8 bytes
void uint64_to_bytes(uint64_t num, uint8_t * bytes)
{
    for (int i = 0; i < 8; i++)
    {
        bytes[i] = (num >> (8 * i)) & 0xff;
    }
}

void uint32_to_bytes(uint32_t num, uint8_t * bytes)
{
    for (int i = 0; i < 4; i++)
    {
        bytes[i] = (num >> (8 * i)) & 0xff;
    }
}


void hash_message(uint8_t * p_src, uint32_t src_len, sgx_sha256_hash_t * p_hash)
{
sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_sha256_msg(p_src, src_len, p_hash);
    if (ret != SGX_SUCCESS)
    {
        printf("sgx_sha256_msg failed [%s].\n", __FUNCTION__);
        return;
    }
    printf("hash message success\n");
}