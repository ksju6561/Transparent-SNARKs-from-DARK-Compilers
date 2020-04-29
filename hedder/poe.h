#ifndef _POE_H
    int verify_pk(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, BIGNUM *pk);
    int eval_pk(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, const BIGNUM *pk);
    int eval_pk_faster(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, BIGNUM *pk);
    
    #define _POE_H
#endif
