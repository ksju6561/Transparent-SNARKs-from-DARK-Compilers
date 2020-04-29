#include "../hedder/global_param.h"
#include "../hedder/util.h"
#include "../hedder/poe.h"

unsigned int RunTime_file_IO = 0;
unsigned int RunTime_eval = 0;
unsigned int RunTime_poe = 0;

int get_alpha_SHA256(BIGNUM *output, const BIGNUM *p, const BIGNUM *yL, const BIGNUM *yR, const BIGNUM *CL, const BIGNUM *CR)
{
	BN_CTX *ctx = BN_CTX_new();
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
	for(int i = 0; i < SHA256_DIGEST_LENGTH/2; i+=2)
        digest[i] = digest[i]^digest[SHA256_DIGEST_LENGTH/2+i];
	for(int i = 0; i < SHA256_DIGEST_LENGTH/2; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	BN_hex2bn(&output, mdString);
	//BN_mod(output, output, p, ctx);
	//printf("hash2 : %s\n", BN_bn2hex(output));

	BN_CTX_free(ctx);
	free(str_yL);
	free(str_yR);
	free(str_CL);
	free(str_CR);
	free(str_concat);

    return 1;
}

int Spd(BIGNUM* output, BIGNUM* p, unsigned int d)
{
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bn_tmp = BN_new();

	int nbit = 0;
	d++;
	for(nbit=0; d != 0; (d >>= 1), nbit++);
	//printf("%d\n", nbit);
	BN_set_word(bn_tmp, nbit);
	BN_exp(output, p, bn_tmp, ctx);
	//printf("Spd : %s\n", BN_bn2hex(output));
	BN_CTX_free(ctx);
	BN_free(bn_tmp);
	
	return 1;
}

int EvalBounded(_struct_pp_ *pp, BIGNUM **C, const BIGNUM *z, BIGNUM **y, BIGNUM** b, _struct_poly_* poly) 
{
	static FILE *fp;
	static unsigned char buffer[1000]={0};
	static int isfirst = 0, flag = 1;
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
	static BIGNUM* spd;

	if(isfirst == 0)
	{
		TimerOn();
		fp = fopen("./Txt/proof.txt", "a+");
		RunTime_file_IO += TimerOff();

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
		spd = BN_new();

		TimerOn();
		Spd(spd, pp->p, poly->d);
		RunTime_eval += TimerOff();
		isfirst = 1;
	}

	if(poly->d == 0)
	{
		TimerOn();
		fscanf(fp, "%s", buffer);
		BN_hex2bn(&poly->Fx[0], buffer);
		RunTime_file_IO += TimerOff();

		TimerOn();
		BN_mul(z_tmp, *b, spd, ctx);
		if(BN_cmp(*b, pp->q) != -1 || BN_cmp(spd, pp->q) != -1){
			printf("bounded fail!! [ b * spd > q]\n");
			flag = 0;
		}
		
		if(BN_cmp(poly->Fx[0], *b) != -1){
			printf("bounded fail!! [ |f| > b ]\n");
			printf("f : %s\n", BN_bn2hex(poly->Fx[0]));
			printf("b : %s\n", BN_bn2hex(*b));
			flag = 0;
		}

		BN_mod(z_tmp, *y, pp->p, ctx);
		BN_mod(y_tmp, poly->Fx[0], pp->p, ctx);
		if(BN_cmp(z_tmp, y_tmp) != 0){
			printf("ERROR : f mod p != y mod p\n");
			printf("f : %s\n", BN_bn2hex(y_tmp));
			printf("y : %s\n", BN_bn2hex(z_tmp));
			flag = 0;
		}

		BN_mod_exp(z_tmp, pp->g, poly->Fx[0],pp->G, ctx);
		if(BN_cmp(z_tmp, *C) != 0){
			printf("ERROR : g^f != C\n");
			printf("g^f : %s\n", BN_bn2hex(z_tmp));
			printf("  C : %s\n", BN_bn2hex(*C));
			flag = 0;
		}
		RunTime_eval += TimerOff();

		if(	flag == 1 )
			printf("Verify Success!!\n");
		else
			printf("Verify Fail.....\n");
		

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
		fclose(fp);
	}
	else if( ((1+poly->d)%2) == 1 )
	{
		printf("d+1 is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		TimerOn();
		BN_mod_exp(*C,*C,pp->q,pp->G,ctx);	// C' = C^q
		BN_mod_mul(*y,*y,z,pp->p,ctx);		// y=y*z mod p
		BN_set_word(y_tmp, poly->d);
		BN_mul(*b, *b, y_tmp, ctx);			// b =  bd
		
		poly->d = poly->d + 1;				//*d = *d + 1;
		RunTime_eval += TimerOff();
		EvalBounded(pp, C, z, y, b, poly);
	}
	else
	{
		int i;
		int d_ = ((1+poly->d)/2) - 1; //*d = ((*d+1)>>1)-1;		// P,V compute
		printf("d+1 is even [d : %d -> d' : %d]\n", poly->d, d_);
		TimerOn();
		fscanf(fp, "%s", buffer);
		BN_hex2bn(&alpha, buffer);

		fscanf(fp, "%s", buffer);
		BN_hex2bn(&yL, buffer);

		fscanf(fp, "%s", buffer);
		BN_hex2bn(&yR, buffer);

		fscanf(fp, "%s", buffer);
		BN_hex2bn(&CL.C, buffer);

		fscanf(fp, "%s", buffer);
		BN_hex2bn(&CR.C, buffer);
		
		fscanf(fp, "%s", buffer);
		BN_hex2bn(&POE_proof, buffer);
		RunTime_file_IO += TimerOff();

		TimerOn();
		BN_copy(poe_u, CR.C);

		BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);
		////
		
		BN_set_word(z_tmp, d_+1);
		BN_mod_exp(z_tmp, z, z_tmp, pp->p, ctx);
		BN_mod_mul(z_tmp, z_tmp, yR, pp->p, ctx);
		BN_mod_add(y_tmp, z_tmp, yL, pp->p, ctx);
		if(BN_cmp(y_tmp, *y) != 0)
		{
			RunTime_eval += TimerOff();
			printf("Fail Compare y..\n");
			TimerOn();
		}
		//printf("cmp y : %d ", BN_cmp(y_tmp, *y) == 0 ? 1 : 0 );
		
		if( verify_pk(POE_proof, poe_w, poe_u, pp->q, d_+1, pp->G) != 1)
		{
			RunTime_eval += TimerOff();
			printf("Fail POE\n");
			TimerOn();
		}	

		//printf("y' <- (a*yL + yR) mod p \n");
		BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		BN_mod_exp(*C, CL.C, alpha, pp->G, ctx);
		BN_mod_mul(*C, *C, CR.C, pp->G, ctx);

		//printf("b' <- b(p+1)/2\n");
		BN_copy(y_tmp,pp->p);
		BN_add_word(y_tmp,1);
		BN_rshift1(y_tmp,y_tmp);
		BN_mul(*b,*b,y_tmp,ctx);
		//printf("b : %s\n", BN_bn2hex(*b));

		//printf("f' <- a*fL + fR\n");
		poly->d = d_;
		//printf("V run EvalBounded(pp, C', z, y', d', b', f'(X))\n\n");
		RunTime_eval += TimerOff();
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


	// TimerOn();
	// RunTime_eval += TimerOff();
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
	//printf("EvalBounded Start\n");
	EvalBounded(pp, &C, z, &y, &p, poly);

	BN_free(C);
	BN_free(z);
	BN_free(y);
	BN_free(p);
	BN_free(zero);
	BN_CTX_free(ctx);

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

	// printf("file IO : %u\n", RunTime_file_IO);
	printf("EVAL_VERIFY_ %12u [us]\n", RunTime_eval);
	printf("VERIFY_I/O__ %12u [us]\n", RunTime_file_IO);

	fp = fopen("record/eval_verify.txt", "a+");
	fprintf(fp, "%d ", RunTime_file_IO);			
	fprintf(fp, "%d\n", RunTime_eval);
	fclose(fp);

	return 0;
}
