//
// Created by thrypuro on 21/07/23.
//

#include "Shamir.h"
#include<cmath>
#include <sgx_tcrypto.h>
#include "sgx_trts.h"

Shamir::Shamir() {

}


Shamir::~Shamir() {

}


Shamir :: Shamir(int64_t prime) {
    this -> prime = prime;
}

uint64_t getRandomNumber() {

    unsigned char temp [7] = {0};
    sgx_read_rand(temp, 7);
    uint64_t random = 0;
    for(int i = 0; i < 7; i++) {
        random = random << 8;
        random += temp[i];
    }
    return random;
}

int64_t mod (int64_t a, int64_t b) {
    int64_t res = a % b;
    if(res < 0) {
        res += b;
    }
    return res;
}
// mod multiplication of two numbers and make sure it does not overflow
int64_t mod_mul(int64_t a, int64_t b, int64_t prime) {
    int64_t res = 0;
    a = a % prime;
    while(b > 0) {
        if(b % 2 == 1) {
            res = (res + a) % prime;
        }
        a = (a * 2) % prime;
        b = b / 2;
    }
    return res % prime;
}
int64_t xGCD(int64_t a, int64_t b, int64_t * x, int64_t * y) {
    if(b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    int64_t x1, y1;
    int64_t a_b = mod (a, b);
    int64_t gcd = xGCD(b, a_b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return gcd;
}
int64_t modInverse(int64_t a, int64_t m) {

    int64_t x, y;
    int64_t g = xGCD(a, m, &x, &y);
    if(g != 1) {
        return 0;
    }
    else {
        int64_t res = mod(x, m);
        return res;
    }
}

// pow mod function but use mod_mul to avoid overflow
int64_t pow(int64_t base, int64_t exp, int64_t prime) {
    int64_t res = 1;
    base = base % prime;
    while(exp > 0) {
        if(exp % 2 == 1) {
            res = mod_mul(res, base, prime);
        }
        base = mod_mul(base, base, prime);
        exp = exp / 2;
    }
    return res % prime;
}

// There is no minimum shares because for our case we need all the nodes combined in order to reconstruct the secret
vector< point> Shamir :: split_secret(int64_t secret, int n) {

    vector<point> share;
    int64_t coeff[n];

    coeff[0] = secret;


    for(int i = 1; i < n; i++) {
        int64_t temp = getRandomNumber();
        coeff[i] = temp% prime;
    }

    for(int i = 1; i <= n; i++) {
        point p;


        p.x = i % prime;
        p.y = 0;
        for(int j = 0; j < n; j++) {

//            p.y +=  coeff[j] * pow(p.x, j, prime); rewrite with mod_mul and pow
            p.y +=  mod_mul(coeff[j], pow(p.x, j, prime), prime);
            p.y = mod(p.y, prime);
        }
        share.push_back(p);
    }
    return share;
}





int64_t _lagrange_interpolate(int64_t x, vector<int64_t> x_s, vector<int64_t> y_s, int64_t p) {
    int k = x_s.size();

    int64_t ret = 0;
    for(int j = 0; j < k; j++) {
        vector<int64_t> others = x_s;
        int64_t cur = others[j];
        vector<int64_t> temp,temp1;
        int64_t temp2 = 1;
        for (int m = 0; m < others.size(); m++) {
            if( m != j) {
                int64_t nume = others[m];
                int64_t deno = nume - cur;
                deno = mod(deno, p);
                int64_t inv = modInverse(deno, p);
                temp2 = mod_mul(temp2, nume, p);
                temp2 = mod_mul(temp2, inv, p);
//                    temp2 = temp2 * nume * inv;
                temp2 = mod(temp2, p);
            }

        }
        temp2 = mod_mul(temp2, y_s[j], p);
        ret = mod(ret + temp2, p);
    }

    return ret;
}


int64_t Shamir :: reconstruct_secret(vector<point> share) {

    vector<int64_t> x_s;
    vector<int64_t> y_s;
    for(int i = 0; i < share.size(); i++) {
        x_s.push_back(share[i].x);
        y_s.push_back(share[i].y);
    }
    return _lagrange_interpolate(0, x_s, y_s, prime);

}