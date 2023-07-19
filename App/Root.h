//
// Created by thrypuro on 17/07/23.
//

#ifndef TOP_BFT_DISS_ROOT_H
#define TOP_BFT_DISS_ROOT_H


#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include <iostream>
#include <fstream>
#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"


#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif


class Root {
public:
    Root();
    ~Root();
    Root(int total_primary, int total_replica, int total_passive, int total_node_address,sgx_enclave_id_t global_eid);

    void start();

private:
    int total_primary, total_replica, total_passive,total_node_address;



};


#endif //TOP_BFT_DISS_ROOT_H
