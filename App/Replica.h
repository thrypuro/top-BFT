//
// Created by thrypuro on 17/07/23.
//

#ifndef TOP_BFT_DISS_REPLICA_H
#define TOP_BFT_DISS_REPLICA_H

#include "utils.h"

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

class Replica {

public:
    Replica();
    ~Replica();

    Replica(int node_index,int partition_num, int view_num, int leader_index, sgx_enclave_id_t eid);

    void run();
private:

    void Initialisation();
    void Prepare();

    int partition_num, view_num,node_index,leader_index;
    int leader_address, port;

};


#endif //TOP_BFT_DISS_REPLICA_H
