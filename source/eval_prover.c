#include "../hedder/global_param.h"
#include "../hedder/util.h"
#include "../hedder/poe.h"
#include <time.h>

unsigned int RunTime_file_IO = 0;
unsigned int RunTime_eval = 0;
unsigned int RunTime_poe = 0;

int commit_new(_struct_commit_* cm, const _struct_pp_ pp, const _struct_poly_ poly)
{
	int flag = 1, i = 0;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bn_tmp1 = BN_new();
	BIGNUM* bn_tmp2 = BN_new();

	BN_set_word(bn_tmp1,1);
	BN_set_word(bn_tmp2,0);
	BN_set_word(cm->Fhat,0);
	BN_set_word(cm->C,1);

	//clock_t startTime = clock();

	for(i = poly.d; i >= 0; i--)
	{
		BN_mod_exp( cm->C, cm->C, pp.q, pp.G, ctx);
		BN_mod_exp( bn_tmp1, pp.g, poly.Fx[i], pp.G, ctx);
		BN_mod_mul( cm->C, cm->C, bn_tmp1, pp.G, ctx);
	}

	//clock_t endTime = clock();
	//printf("encode time = %f\n", ((float)endTime-startTime)/CLOCKS_PER_SEC);

	BN_CTX_free(ctx);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);

	return flag;
}

int encode(_struct_commit_* cm, const _struct_pp_ pp, const _struct_poly_ poly)
{
	int flag = 1, i = 0;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* tmp1 = BN_new();
	BIGNUM* tmp2 = BN_new();
	
	BN_set_word(tmp1,0);
	BN_set_word(tmp2,0);
	BN_set_word(cm->Fhat,0);
	//printf("\n");
	clock_t startTime = clock();

	for(i = poly.d; i >= 0; i--)
	{
		BN_mul(cm->Fhat, pp.q, cm->Fhat, ctx);
		BN_add(cm->Fhat, cm->Fhat, poly.Fx[i]);
	}

	// do{		
	// 	//printf("d : %d i : %d index : %d\n", poly.d, i, poly.d-i);
	// 	BN_mul(tmp2,tmp1,poly.Fx[i],ctx);
	// 	printf("Fx[%d] : %s\n", poly.d-i, BN_bn2hex(poly.Fx[poly.d-i]));
	// 	BN_add(cm->Fhat, cm->Fhat, tmp2);
	// 	BN_mul(tmp1,tmp1, pp.q, ctx);
	// 	i++;
	// }while(i <= poly.d);
	clock_t endTime = clock();
	printf("encode time = %f\n", ((float)endTime-startTime)/CLOCKS_PER_SEC);
	//printf("encode : %s\n\n", BN_bn2hex(cm->Fhat));

	BN_CTX_free(ctx);
	BN_free(tmp1);
	BN_free(tmp2);

	return flag;
}

int commit(_struct_commit_ *cm, const _struct_pp_ pp)
{
	BN_CTX* ctx = BN_CTX_new();
	int flag = 1;

	clock_t startTime = clock();
	
	flag &= BN_mod_exp(cm->C, pp.g, cm->Fhat, pp.G, ctx);

	clock_t endTime = clock();
	printf("commit time = %f\n", ((float)endTime-startTime)/CLOCKS_PER_SEC);

	//printf("commit : %d\n", flag);
	//flag &= BN_exp(cm->C, pp.g, cm->Fhat, ctx);

	BN_CTX_free(ctx);
	return flag;
}


int get_alpha_SHA256(BIGNUM *output, const BIGNUM *p, const BIGNUM *yL, const BIGNUM *yR, const BIGNUM *CL, const BIGNUM *CR)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* bn_tmp = BN_new();
	BIGNUM* bn_cmp = BN_new();
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
	unsigned char *output_string;

	unsigned char *str_yL = BN_bn2hex(yL);
	unsigned char *str_yR = BN_bn2hex(yR);
	unsigned char *str_CL = BN_bn2hex(CL);
	unsigned char *str_CR = BN_bn2hex(CR);

	unsigned char *str_concat = (unsigned char*)malloc( sizeof(unsigned char) * (1 + strlen(str_yL)+strlen(str_yR)+strlen(str_CL)+strlen(str_CR)) );
	unsigned char concat_len = 0;

	memcpy(str_concat, str_yL, sizeof(unsigned char) * (strlen(str_yL)));
	concat_len += sizeof(unsigned char) * (strlen(str_yL));

	memcpy(str_concat + concat_len, str_yR, sizeof(unsigned char) * (strlen(str_yR)));
	concat_len += sizeof(unsigned char) * (strlen(str_yR));

	memcpy(str_concat + concat_len, str_CL, sizeof(unsigned char) * (strlen(str_CL)));
	concat_len += sizeof(unsigned char) * (strlen(str_CL));

	memcpy(str_concat + concat_len, str_CR, sizeof(unsigned char) * (strlen(str_CR)));
	concat_len += sizeof(unsigned char) * (strlen(str_CR));
	*(str_concat + concat_len) = '\0';

	// printf("yL : %s\n", str_yL);
	// printf("yR : %s\n", str_yR);
	// printf("CL : %s\n", str_CL);
	// printf("CR : %s\n", str_CR);
	// printf("concat : %s\n", str_concat);

	SHA256(str_concat, concat_len, digest);  
	// for(int i = 0; i < SHA256_DIGEST_LENGTH/2; i+=2)
    //     digest[i] = digest[i]^digest[SHA256_DIGEST_LENGTH/2+i];
	 for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	//printf("hash2 : %s\n", mdString);
	BN_hex2bn(&output, mdString);
	
	
	BN_mod(output, output, p, ctx);
	BN_copy(bn_cmp, p);
	BN_sub_word(bn_cmp, 1);
	BN_rshift1(bn_cmp, bn_cmp);
	
	//BN_rshift(output, output, BN_num_bits(output)/2);
	//BN_rshift(output, output, BN_num_bits(output)/2);
	BN_rshift(output, output, 1);

	// if(BN_cmp(output, bn_cmp) == 1)
	// {
	// 	BN_sub(output, output, p);
	// 	if(BN_cmp(output, bn_cmp) == 1)
	// 	{
	// 		printf("alpha range fail\n");			
	// 	}
	// }

	BN_CTX_free(ctx);
	BN_free(bn_tmp);
	free(str_yL);
	free(str_yR);
	free(str_CL);
	free(str_CR);
	free(str_concat);

    return 1;
}

int EvalBounded(_struct_pp_ *pp, BIGNUM **C, const BIGNUM *z, BIGNUM **y, BIGNUM** b, _struct_poly_* poly) 
{
	static int isfirst = 0;
	static BN_CTX* ctx;
	static BIGNUM* yL;
	static BIGNUM* yR;
	static BIGNUM* z_tmp;
	static BIGNUM* y_tmp;
	static BIGNUM* alpha;
	static BIGNUM* POE_proof;
	static _struct_poly_ fL, fR;
	static _struct_commit_ CL, CR;	
	static BIGNUM* poe_w;
	static BIGNUM* poe_u;
	static BIGNUM* poe_x;
	if(isfirst == 0)
	{
		//printf("d : %d\n", poly->d);
		TimerOn();
		ctx = BN_CTX_new();
		yL = BN_new();
		yR = BN_new();
		y_tmp = BN_new();
		z_tmp = BN_new();
		CL.C = BN_new();
		CL.Fhat = BN_new();
		CR.C = BN_new();
		CR.Fhat = BN_new();	

		alpha = BN_new();
		POE_proof = BN_new();
		poe_w = BN_new();
		poe_u = BN_new();
		poe_x = BN_new();

		//
		fL.Fx = (BIGNUM**)calloc(sizeof(BIGNUM*), 1048575+10);
		fR.Fx = (BIGNUM**)calloc(sizeof(BIGNUM*), 1048575+10);
		
		isfirst = 1;
		RunTime_eval += TimerOff();
	}

	if(poly->d == 0)
	{		
		//printf("d is zero... record f\n");
		TimerOn();
		RunTime_eval += TimerOff();

		TimerOn();
		Write_proof(NULL, poly->Fx[0]);
		RunTime_file_IO += TimerOff();

		BN_free(yL);
		BN_free(yR);
		BN_free(z_tmp);
		BN_free(y_tmp);
		BN_free(CL.C);
		BN_free(CL.Fhat);
		BN_free(CR.C);
		BN_free(CR.Fhat);
		BN_free(alpha);
		BN_free(POE_proof);
		BN_free(poe_w);
		BN_free(poe_u);
		BN_free(poe_x);
		BN_CTX_free(ctx);
	}
	
	else if( ((1+poly->d)%2) == 1 )
	{
		printf("d+1 is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		TimerOn();

		BN_mod_exp(*C,*C,pp->q,pp->G,ctx);	// C' = C^q
		BN_mod_mul(*y,*y,z,pp->p,ctx);		// y=y*z mod p
		BN_set_word(y_tmp, poly->d);
		BN_mul(*b, *b, y_tmp, ctx);			// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		if( poly->Fx[poly->d] == NULL)
			poly->Fx[poly->d] = BN_new();
	
		for(int i = poly->d-1; i >= 0; i--){// f'(X) = Xf(X);
			BN_copy(poly->Fx[i+1], poly->Fx[i]);
		}
		BN_set_word(poly->Fx[0],0);	
		RunTime_eval += TimerOff();

		EvalBounded(pp, C, z, y, b, poly);
	}
	else
	{
		int i;
		int d_ = ((1+poly->d)/2) - 1; //*d = ((*d+1)>>1)-1;		// P,V compute
		printf("d+1 is even [d : %d -> d' : %d]\n", poly->d, d_);
		TimerOn();

		//printf("P computes fL\n");
		for(i = 0; i <= d_; i++){	//fL.Fx[i] = poly->Fx[i];
			if(fL.Fx[i] == NULL){
				fL.Fx[i] = BN_new();
			}
			BN_copy(fL.Fx[i], poly->Fx[i]);
		}
		fL.d = d_;

		//printf("P computes fR\n");
		for(i = 0; i <= d_; i++){	//fR.Fx[i] = poly->Fx[d_ + i + 1];
			if(fR.Fx[i] == NULL){
				fR.Fx[i] = BN_new();
			}
			BN_copy(fR.Fx[i] , poly->Fx[d_ + i + 1]);
		}
		fR.d = d_;

		//printf("P computes yL\n");		
		BN_set_word(z_tmp, 1);
		BN_set_word(y_tmp, 0);
		BN_set_word(yL, 0);
		i=0;
		do{
			BN_mod_mul(y_tmp, fL.Fx[i], z_tmp, pp->p, ctx);
			BN_mod_add(yL, yL, y_tmp, pp->p, ctx);
			BN_mod_mul(z_tmp,z_tmp,z, pp->p, ctx);
			i++;
		}while(i<= fL.d);
		//printf("yL : %s\n", BN_bn2dec(yL));

		//printf("P computes yR\n");	
		BN_set_word(z_tmp, 1);
		BN_set_word(y_tmp, 0);
		BN_set_word(yR, 0);
		i=0;
		do{
			BN_mod_mul(y_tmp, fR.Fx[i], z_tmp, pp->p, ctx);
			BN_mod_add(yR, yR, y_tmp, pp->p, ctx);
			BN_mod_mul(z_tmp,z_tmp,z, pp->p, ctx);
			i++;
		}while(i<= fR.d);
		//printf("yR : %s\n", BN_bn2dec(yR));

		//printf("P computes CL\n");
		commit_new(&CL, *pp, fL);
		
		//printf("P computes CR\n");
		commit_new(&CR, *pp, fR);

		//printf("P computes alpha(hash)\n");
		get_alpha_SHA256(alpha, pp->p, yL, yR, CL.C, CR.C);
		//BN_set_word(alpha,19);			

		//POE(CR, C/CL, q^(d'+1)) run	
		BN_copy(poe_u, CR.C);
		BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		//printf("run POE\n");
		eval_pk(POE_proof, poe_w, poe_u, pp->q, d_+1, pp->G);

		//printf("y' <- (a*yL + yR) mod p \n");
		BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		BN_mod_exp(*C, CL.C, alpha, pp->G, ctx);
		BN_mod_mul(*C, *C, CR.C, pp->G, ctx);

		//printf("b' <- b((p+1)/2)\n");
		BN_copy(y_tmp,pp->p);
		BN_add_word(y_tmp,1);
		BN_rshift1(y_tmp,y_tmp);
		BN_mul(*b,*b,y_tmp,ctx);
		
		//printf("f' <- a*fL + fR\n");
		i=0;
		do{
			BN_mod_mul(y_tmp, alpha, fL.Fx[i], *b, ctx);
			BN_mod_add(poly->Fx[i], y_tmp, fR.Fx[i], *b, ctx);
			//poly->Fx[i]  = alpha*fL.Fx[i] + fR.Fx[i];			
			BN_free(fR.Fx[i]);	fR.Fx[i]=NULL;	
			BN_free(fL.Fx[i]);	fL.Fx[i]=NULL;	
			i++;
		}while(i <= d_);

		do{
			BN_free(poly->Fx[i]);
			poly->Fx[i] = NULL;
			i++;
		}while(i <= poly->d);
		poly->d = d_;
		RunTime_eval += TimerOff();
		//printf("P run EvalBounded(pp, C', z, y', d', b', f'(X))\n\n");

		TimerOn();
		Write_proof(NULL, alpha);		
		Write_proof(NULL, yL);		
		Write_proof(NULL, yR);		
		Write_proof(NULL, CL.C);		
		Write_proof(NULL, CR.C);		
		Write_proof(NULL, POE_proof);	
		RunTime_file_IO += TimerOff();

		EvalBounded(pp, C, z, y, b, poly);
	}

	return 1;
}


int Eval(_struct_pp_* pp, _struct_commit_* cm, _struct_poly_* poly) // ( pp, z, y, d, f~(X) )
{
	int i;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* zero = BN_new();
	BIGNUM* p = BN_new();
	BIGNUM* C = BN_new();
	BIGNUM* z = BN_new();
	BIGNUM* z_tmp = BN_new();
	BIGNUM* y = BN_new();
	
	BN_copy(C, cm->C);	
	BN_copy(p, pp->p);	
	BN_sub_word(p,1);
	BN_rshift1(p,p);

	BN_set_word(zero,0);
	BN_set_word(y,0);
	BN_set_word(z,100);
	BN_set_word(z_tmp, 1);

	i=0;
	do{
		//BN_mod_inverse(poly->Fx[i], poly->Fx[i], pp->p, ctx);
		i++;
	}while(i<= poly->d);

	i = 0;
	do{
		BN_mod_mul(zero, poly->Fx[i], z_tmp, pp->p, ctx);
		BN_mod_add(y, y, zero, pp->p, ctx);
		BN_mod_mul(z_tmp,z_tmp,z, pp->p, ctx);
		i++;
	}while(i<= poly->d);


	BN_free(zero);
	BN_CTX_free(ctx);
	
	//printf("EvalBounded Start\n");
	EvalBounded(pp, &C, z, &y, &p, poly);

	BN_free(C);
	BN_free(z);
	BN_free(y);
	BN_free(p);

	return 1;
}

int main()
{
	FILE *fp;
  	_struct_pp_ pp;
	_struct_commit_ cm;
	_struct_poly_ poly;

	BN_CTX* ctx = BN_CTX_new();
	
	TimerOn();
	Read_pp( &pp );
	Read_Commit( &cm );
	Read_poly(&poly);
	RunTime_file_IO += TimerOff();

	Eval(&pp, &cm, &poly);
	printf("EVAL_PROVER_ %12u [us]\n", RunTime_eval);
	printf("EVAL___I/O__ %12u [us]\n", RunTime_file_IO);

	fp = fopen("record/eval_prove.txt", "a+");
	fprintf(fp, "%d ", RunTime_file_IO);			
	fprintf(fp, "%d\n", RunTime_eval);
	fclose(fp);


	return 0;
}
