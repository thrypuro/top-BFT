//
// Created by thrypuro on 21/07/23.
//

#ifndef TOP_BFT_DISS_SHAMIR_H
#define TOP_BFT_DISS_SHAMIR_H

#include<iostream>
#include <vector>

typedef struct point{
    long long x;
    long long y;
}point;



using namespace std;
class Shamir {
public:
    Shamir();
    ~Shamir();

    Shamir(int64_t prime);
    vector<point> split_secret(int64_t secret, int n);
    int64_t reconstruct_secret(vector<point> share);


private:
    int64_t prime;

};


#endif //TOP_BFT_DISS_SHAMIR_H
