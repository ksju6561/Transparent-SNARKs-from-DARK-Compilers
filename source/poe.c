#include "../hedder/global_param.h"
#include "../hedder/poe.h"

unsigned int RunTime_poe1 = 0;
unsigned int RunTime_poe2 = 0;
unsigned int RunTime_poe3 = 0;
unsigned int RunTime_poe4 = 0;
unsigned int RunTime_poe5 = 0;

extern int primetable[];


int pre_computation(BIGNUM** Ci[], const int t, const BIGNUM* g, const BIGNUM* pk, const int k, const int r)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* bn_tmp1 = BN_new();
	BIGNUM* bn_tmp2 = BN_new();
	BIGNUM* bn_two = BN_new();
	int size = ceil((double)t/((double)k*r))+1;
	*Ci = (BIGNUM**)malloc(sizeof(BIGNUM*)*size);
	
	BN_set_word(bn_tmp2, 2);
	BN_set_word(bn_two, 2);
	
	BN_set_word(bn_tmp1, k*r);	
	BN_exp(bn_tmp2, bn_two, bn_tmp1, ctx);	
	BN_set_word(bn_tmp1, 1);	
	//printf("k : %d\nr : %d\n", k, r);

	(*Ci)[0] = BN_new();
	BN_mod((*Ci)[0], g, pk, ctx);
	//printf("%s\n", BN_bn2dec((*Ci)[0]));
	for(int i=1; i < size; i++)
	{
		(*Ci)[i] = BN_new();
		BN_mod_exp((*Ci)[i], (*Ci)[i-1], bn_tmp2, pk, ctx);
	}

	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_free(bn_two);
	BN_CTX_free(ctx);

	return size;
}

int HG_func(BIGNUM *output, const BIGNUM *input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
    unsigned char *tmp_str = BN_bn2hex(input);
   
   	//BN_copy(output,input);
     SHA256(tmp_str, strlen(tmp_str), digest);   
	 BN_zero(output);
	 for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	 BN_hex2bn(&output, mdString);

	//printf("HG len : %d\n", BN_num_bits(output));
	//printf("HG input : %s\n", BN_bn2hex(input));
	//printf("HG : %s\n", mdString);
	//printf("HG : %s\n", BN_bn2hex(output));

	free(tmp_str);
    return 1;
}

int Hprime_func(BIGNUM *output, const BIGNUM *input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
    unsigned char *tmp_str = BN_bn2hex(input);
	unsigned char *output_string;

	SHA256(tmp_str, strlen(tmp_str), digest);   
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);


	mpz_t u, w;
	mpz_init_set_str(u,(char*)mdString,16);
	mpz_init(w);
	mpz_nextprime(w,u);	

	output_string = mpz_get_str(NULL,16,w);
	BN_hex2bn(&output, output_string);

    //printf("hp : %s\n", output_string);
	//printf("hp : %d\n", BN_num_bits(output));
    //printf(">> %s\n", BN_bn2hex(output));

	mpz_clear(u);
	mpz_clear(w);
	free(output_string);
	free(tmp_str);
    return 1;
}

//(const BIGNUM *pf, const BIGNUM *w, const BIGNUM *u, const BIGNUM *x_pow, const BIGNUM *x, const BIGNUM *pk)
int verify_pk(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, BIGNUM *pk)
{	// pf^l * u^r = w ?
	int i, flag = 1;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *g = BN_new();
	BIGNUM *l = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *x = BN_new();

	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	
	//flag &= HG_func(g,u);
	BN_copy(g,u);										//printf("	poe verify g : %s\n", BN_bn2hex(g));// u -> g
	flag &= BN_lshift(bn_tmp1, w, BN_num_bits(g));		//printf("	poe verify w : %s\n", BN_bn2hex(w));// g^x -> w
	flag &= BN_add(bn_tmp1, bn_tmp1, g);		
	flag &= Hprime_func(l,bn_tmp1);						//printf("	poe verify l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l	

	//printf("l : %s\n", BN_bn2hex(l));
	//printf("x : %d\n", BN_num_bits(x_pow));

	int num = BN_num_bits(q);
	int t = (num - 1) * d;
	flag &= BN_set_word(x, 1);
	//printf("BN_set_word flag : %d\n", BN_set_word(x, 1) );
	//int cnt = 0;
	BN_lshift(x, x, t);
	//if(cnt > 0)
	//printf("final shift cnt : %d\n", BN_lshift(x, x, cnt));

	flag &= BN_div(NULL, r, x, l, ctx);
	flag &= BN_mod_exp(bn_tmp1, pf, l, pk, ctx);
	flag &= BN_mod_exp(bn_tmp2, g, r, pk, ctx);
	flag &= BN_mod_mul(r, bn_tmp1, bn_tmp2, pk, ctx);
	
	//printf("pf : %s\n", BN_bn2hex(pf));
	//printf("r : %s\n", BN_bn2hex(r));
	//printf("w : %s\n", BN_bn2hex(w));

	if( BN_cmp(r,w) == 0)
		flag &= 1;
	else 
		flag = 0;

	BN_free(g);
	BN_free(l);
	BN_free(r);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_CTX_free(ctx);

	return (flag);
}

//////////////////
//get_block(i) =  (int)[ 2^k * (2^(t - k(i+1)) mod l)/l ]
int get_block(BIGNUM *out, int in1, int in2, BIGNUM* modular )
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* two = BN_new();
	BIGNUM* bn_tmp1 = BN_new();
	BIGNUM* bn_tmp2 = BN_new();
	BIGNUM* bn_tmp3 = BN_new();
	BIGNUM* bn_tmp_l = BN_new();

	BN_copy(bn_tmp_l, modular);
	BN_sub_word(bn_tmp_l, 1);
	
	BN_set_word(two, 2);		
	BN_set_word(bn_tmp1, in1);	
	if(in2 < 0)
	{	
		//printf("minus\n");
		BN_copy(bn_tmp2, modular);
		BN_sub_word(bn_tmp2, in2 - 1);
	}
	else
		BN_set_word(bn_tmp2, in2 ); 

	//printf("(%d %d) ", in1, in2);

	BN_exp(bn_tmp1, two, bn_tmp1, ctx);	// 2^k
	BN_mod(bn_tmp2, bn_tmp2, bn_tmp_l, ctx);
	//printf("%s ", BN_bn2dec(bn_tmp2));
	BN_mod_exp(bn_tmp2, two, bn_tmp2, modular, ctx);	// 2^( (t - k*(in+1)) ) mod l

	BN_mul(bn_tmp3, bn_tmp1, bn_tmp2, ctx);		// 바꿀 예정
	BN_div(out, NULL, bn_tmp3, modular, ctx);

	BN_CTX_free(ctx);
	BN_free(two);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_free(bn_tmp3);
}

int eval_pk_faster(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, BIGNUM *pk)
{
	int i, flag = 1;
	int num = BN_num_bits(q);
	//printf("%d\n",num);
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *g = BN_new();
	BIGNUM *l = BN_new();
	BIGNUM *z = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BIGNUM *bn_tmp3 = BN_new();

	BN_copy(g,u);								
	flag &= BN_lshift(bn_tmp1, w, BN_num_bits(g));	
	flag &= BN_add(bn_tmp1, bn_tmp1, g);
	flag &= Hprime_func(l,bn_tmp1);					//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l

	int t = (num - 1) * d;
	int int_tmp, cnt = 0, factor = 1;
	
	int_tmp = t;
	i = 0;
	while(1){
		if(int_tmp % primetable[i] == 0 ){
			int_tmp /= primetable[i];
			cnt++;
		}
		else{
			if(cnt%2 == 1)
				factor *= primetable[i];
			i++;
			cnt = 0;
			if(int_tmp == 1)
				break;
		}
	}

	int r = sqrt((double)t*factor);
	int k = 4;
	printf("f %d, r %d, k %d\n", factor, r, k);

	int k1 = k/2;
	int k0 = k-k1;
	static int Ci_size, yb_size, is_first=0;
	static BIGNUM **Ci;
	static BIGNUM **yb;
	double double_tmp;
	int get_block_cnt;
	double_tmp = (double)t/(k*r);
	get_block_cnt = (int)ceil(double_tmp);
	if(k<=0 || r <= 0){
		printf("parameter error\n");
		//continue;
	}

	if(is_first == 0){
		TimerOn();
		Ci_size = pre_computation(&Ci, t, g, pk, k, r);
		yb_size = (1<<k);
		//printf("yb_size : %d\n", yb_size);
		yb = (BIGNUM**)malloc(sizeof(BIGNUM*)*(yb_size)); 

		for(int i = 0; i< yb_size; i++)
			yb[i] = BN_new();


	//printf("%d %d\n", Ci_size, (int)((double)t/((double)k*r)+0.5));
	//printf("pf = %s ^ { [2^%d / %s ] } = ", BN_bn2dec(g), t, BN_bn2dec(l));

	BN_set_word(x,1);
	for(int j = r-1; j >= 0; j--)
	{
		BN_set_word(bn_tmp1,1<<k);
		BN_mod_exp(x,x,bn_tmp1, pk, ctx);
		//printf("x0 : %s\n", BN_bn2dec(x));

		for(int index = 0; index < yb_size; index++)
			BN_set_word(yb[index], 1);

		for(int i = 0; i < get_block_cnt; i++)
		{
			get_block(b, k, t - k*(i*r + j+1), l);
			int_tmp = atoi(BN_bn2dec(b));
			BN_mod_mul(yb[int_tmp], yb[int_tmp], Ci[i], pk, ctx);
		}


		for(int b1 = 0; b1 < (1<<k1); b1++)
		{
			BN_set_word(z,1);			
			for(int b0 = 0; b0 < (1<<k0); b0++){
				BN_mod_mul(z, yb[b0 + (b1<<k0)], z, pk, ctx);
			}
			BN_set_word(bn_tmp2, (b1<<k0));
			BN_mod_exp(z, z, bn_tmp2, pk, ctx);
			BN_mod_mul(x, x, z, pk, ctx);
		}

		for(int b0 = 0; b0 < (1<<k0); b0++)
		{
			BN_set_word(z,1);
			for(int b1 = 0; b1 < (1<<k1); b1++){
				BN_mod_mul(z, yb[b0 + (b1<<k0)], z, pk, ctx);				
			}
			BN_set_word(bn_tmp2, b0);
			BN_mod_exp(z, z, bn_tmp2, pk, ctx);
			BN_mod_mul(x, x, z, pk, ctx);
		}
	}

	RunTime_poe2 = TimerOff();
	if(BN_cmp(pf,x)==0)
		printf("%3d %3d %3d %3d %9u %9u\n", t, k, r, get_block_cnt, RunTime_poe1, RunTime_poe2);//BN_bn2hex(pf), BN_bn2hex(x));
	else{
		printf("fail %s %s\n", BN_bn2hex(pf), BN_bn2hex(x));
	}
	BN_copy(pf,x);	

	for(int i = 0; i<Ci_size; i++)
		BN_free(Ci[i]);

	for(int i = 0; i<yb_size; i++)
		BN_free(yb[i]);
	}
	return 1;
}

//////////////////
int eval_pk_on_the_fly(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, const BIGNUM *pk)
{
	int i, flag = 1;
	int num = BN_num_bits(q);
	int cnt = 0;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *two = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *l = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *g = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *tmp1 = BN_new();

	BN_set_word(two,2);	
	BN_set_word(r,1);	
	BN_set_word(x,1);

	for(i=0; i < (num-1)*d; i++)
	{
		TimerOn();
		BN_lshift1(tmp1, r);				//printf("r %s\n", BN_bn2dec(tmp1));
		//BN_mul(tmp1, r, two, ctx);
		
		if(BN_cmp(tmp1, l) == 1)
		{
			BN_set_word(b,1);
			BN_sub(r,tmp1,l);
		}
		else{
			BN_set_word(b,0);
			BN_copy(r,tmp1);
		}		
		
		RunTime_poe2 += TimerOff();

		TimerOn();		
		BN_mod_sqr(tmp1, x, pk, ctx);
		RunTime_poe3 += TimerOff();

		TimerOn();
		if(BN_is_zero(b))
			BN_copy(x, tmp1);
		else{
			BN_mod_mul(x, tmp1, g, pk, ctx);	//printf("x %s\n\n", BN_bn2dec(x));
		}
		//BN_mod_exp(tmp2, g, b, pk, ctx);		
		RunTime_poe4 += TimerOff();
	}
	
	BN_copy(pf,x);	
	printf("pf2 : %s\n", BN_bn2hex(pf));
}

int eval_pk(BIGNUM *pf, BIGNUM *w, const BIGNUM *u, const BIGNUM *q, const int d, const BIGNUM *pk)
{	//eval_pk(POE_proof, poe_w, poe_u, poe_x, d_+1, pp->G, NULL);								
	// u^x mod G = w mod G
	int i, flag = 1, flag2 = 1;	
	int num = BN_num_bits(q);
	int t = (num - 1) * d;

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *g = BN_new();
	BIGNUM *l = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();

	//  u^x = w --> CR^(q^d'+1)  = C/CL
	// pf^l * u^r = w ?	-->		CR^r

	//flag &= HG_func(g,u);								
	BN_copy(g,u);								
	BN_lshift(bn_tmp1, w, BN_num_bits(g));	
	BN_add(bn_tmp1, bn_tmp1, g);
	Hprime_func(l,bn_tmp1);	
	//printf("t: %d\n", t);				
	//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l
	//printf("l : %s\n", BN_bn2hex(l));

	//TimerOn();
	//BN_set_word(x, d);
	//BN_exp(x, q, x, ctx);
	int cnt = 1;
	BN_set_word(x, 0);
	flag2 = BN_set_bit(x, t);
	//printf("num bit1 : %d\n", BN_num_bits(x));
	// 	if(flag2 == 1)
	// 		break;
	// 	t >>= 1;
	// 	cnt <<= 1;
	// 	printf("cnt : %d\n", cnt);
	// }
	//while(cnt != 0)

	BN_div(bn_tmp1, bn_tmp2, x, l, ctx);
	BN_mod_exp(pf, g, bn_tmp1, pk, ctx);

	//flag &= BN_mod_exp(bn_tmp1, pf, l, pk, ctx);
	//flag &= BN_mod_exp(bn_tmp2, g, r, pk, ctx);
	//flag &= BN_mod_mul(r, bn_tmp1, bn_tmp2, pk, ctx);
	
	//printf("pf : %s\n", BN_bn2hex(pf));
	//printf("r : %s\n", BN_bn2hex(r));
	//printf("w : %s\n", BN_bn2hex(w));

	if( BN_cmp(r,w) == 0)
		flag &= 1;
	else 
		flag = 0;



	RunTime_poe1 = TimerOff();
	//RunTime_poe1 += TimerOff();
	//printf("%s ", BN_bn2hex(pf));

	BN_free(b);
	BN_free(r);
	BN_free(x);

	BN_free(g);
	BN_free(l);
	BN_free(bn_tmp1);
	BN_CTX_free(ctx);
	//if(flag == 0)
	//	printf("fail generate Poe proof.\n");
	return flag;
}

