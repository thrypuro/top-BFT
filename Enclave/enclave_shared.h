//
// Created by thrypuro on 23/07/23.
//

#ifndef TOP_BFT_DISS_ENCLAVE_SHARED_H
#define TOP_BFT_DISS_ENCLAVE_SHARED_H


#include <stdlib.h>
#include <assert.h>
#include "Enclave_t.h"  /* print_string */
#include <sgx_tcrypto.h>
#include "sgx_trts.h"

#if defined(__cplusplus)
extern "C" {
#endif


int decrypt_message(uint8_t * p_src, uint32_t src_len, uint8_t * p_dst, uint8_t * p_key,
                     uint8_t * p_iv,const uint8_t *p_aad,const uint8_t* p_add_len, uint8_t * p_dst_tag);
void encrypt_message(uint8_t * p_src, uint32_t src_len, uint8_t * p_dst,
                     uint8_t * p_key, uint8_t * p_iv,
                     const uint8_t *p_aad, const uint8_t* p_add_len,
                     uint8_t * p_dst_tag
);
void printf(const char *fmt, ...);

void generate_key_pair(sgx_ec256_private_t * private_key, sgx_ec256_public_t * public_key);

void sign_message(sgx_ec256_private_t * private_key, uint8_t * p_src, uint32_t src_len, sgx_ec256_signature_t * signature);
void verify_signature(sgx_ec256_public_t * public_key, uint8_t * p_src, uint32_t src_len, sgx_ec256_signature_t * signature);

void uint64_to_bytes(uint64_t num, uint8_t * bytes);
void uint32_to_bytes(uint32_t num, uint8_t * bytes);
void hash_message(uint8_t * p_src, uint32_t src_len, sgx_sha256_hash_t * p_hash);

#if defined(__cplusplus)
}



#endif

#endif //TOP_BFT_DISS_ENCLAVE_SHARED_H
