//
// Created by thrypuro on 17/07/23.
//

#ifndef TOP_BFT_DISS_LEADER_H
#define TOP_BFT_DISS_LEADER_H

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
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



class Leader {
public:
    Leader();

    ~Leader();

    Leader(int node_index, int total_replica_nodes, int total_passive_nodes, sgx_enclave_id_t global_eid);

    void run();

private:
    int node_index,total_replica_nodes, total_passive_nodes;

};


#endif //TOP_BFT_DISS_LEADER_H
