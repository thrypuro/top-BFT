//
// Created by thrypuro on 17/07/23.
//

#ifndef TOP_BFT_DISS_LEADER_H
#define TOP_BFT_DISS_LEADER_H

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "json.hpp"

#include<vector>

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

    Leader(int node_index,int serial_number, int total_replica_nodes, int total_passive_nodes, sgx_enclave_id_t global_eid);

    void run();

    void wait_for_request();

private:
    int node_index,total_replica_nodes, total_passive_nodes,serial_number;
    int root_address;
    std::vector<int> replica_address;

    void Initialise();


    void Pre_prepare(nlohmann::basic_json<> request);

    void Prepare();

    void Commit();
};


#endif //TOP_BFT_DISS_LEADER_H
