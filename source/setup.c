#include "../hedder/global_param.h"
#include "../hedder/util.h"
//////////////////
#define D 14
int DD;

int KeyGen_RSAsetup( BIGNUM *pk,  BIGNUM *sk, BIGNUM *g, BIGNUM *qq, BIGNUM *pp, const int k)
{
	BIGNUM* one = BN_new();
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* tmp = BN_new();
	BN_CTX* ctx = BN_CTX_new();

	do{
		BN_generate_prime_ex(p,(k>>1),1,NULL,NULL,NULL);
		BN_generate_prime_ex(q,(k>>1),1,NULL,NULL,NULL);
		BN_mul(pk,p,q, ctx);
	}while(BN_num_bits(pk) != k);

	//printf("%d\n", BN_num_bits(pk));
	if(sk != NULL){		
		BN_sub_word(p,1);
		BN_sub_word(q,1);
		BN_mul(sk,p,q,ctx);
	}

	BN_set_word(one,1);
	do{
		BN_rand_range(g, pk);
		BN_gcd(tmp, g, pk, ctx);
	}while(BN_cmp(tmp,one) != 0);

	BN_generate_prime_ex(pp,128,1,NULL,NULL,NULL);
	BN_set_word(qq,0);
	BN_set_bit(qq,128*(2*DD+1));

	BN_free(p);
	BN_free(q);
	BN_free(one);
	BN_free(tmp);
	BN_CTX_free(ctx);
	return 1;
}

int main(int argc, char *argv[])
{
	FILE *fp;
	int security_level = 512;
	unsigned int RunTime = 0;

	BIGNUM* pk = BN_new();
	BIGNUM* g = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* p = BN_new();

	if(argc == 2)
		DD = atoi(argv[1]);
	else
		DD = D;
	printf("log(d) %d d-%d\n", DD, 1<<(DD-1));
	
	TimerOn();
	KeyGen_RSAsetup(pk, NULL, g, q, p, security_level);
	RunTime = TimerOff();
	printf("KeyGen_Time_ %12u [us]\n", RunTime);

	TimerOn();
	fp = fopen("./Txt/pp.txt","w");
	fprintf(fp,"%x\n", security_level);
	fprintf(fp,"%s\n", BN_bn2hex(pk));
	fprintf(fp,"%s\n", BN_bn2hex(g));
	fprintf(fp,"%s\n", BN_bn2hex(q));
	fprintf(fp,"%s\n", BN_bn2hex(p));
	fclose(fp);
	RunTime = TimerOff();
	printf("KeyGen_I/O__ %12u [us]\n", RunTime);

	make_poly((1<<(DD-1)));

	BN_free(pk);
	BN_free(g);
	BN_free(q);
	return 0;
}
