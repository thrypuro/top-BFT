//
// Created by thrypuro on 17/07/23.
//

#ifndef TOP_BFT_DISS_ROOT_H
#define TOP_BFT_DISS_ROOT_H


class Root {
public:
    Root();
    ~Root();
    Root(int total_primary, int total_replica, int total_passive, int total_node_address);

    void start();

private:
    int total_primary, total_replica, total_passive,total_node_address;



};


#endif //TOP_BFT_DISS_ROOT_H
