#ifndef _UTIL_H

	typedef struct{
		int security_level;
		BIGNUM* G;
		BIGNUM* g;
		BIGNUM* q;
		BIGNUM* p;
	}_struct_pp_;

	typedef struct{
		BIGNUM* C;
		BIGNUM* Fhat;
	}_struct_commit_;

	typedef struct{
		BIGNUM** Fx;
		BIGNUM* input;
		int d;
	}_struct_poly_;

    int Read_pp(_struct_pp_* pp); 

	int make_poly(int d);
    int Read_poly(_struct_poly_* poly);
    int Write_Commit(const _struct_commit_* cm);
    int Read_Commit( _struct_commit_* cm);
	int Write_proof(_struct_poly_* poly, BIGNUM* alpha );
	int Read_proof(BIGNUM **bn_tmp);
    #define _UTIL_H
#endif

