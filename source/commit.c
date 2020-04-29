#include "../hedder/global_param.h"
#include "../hedder/util.h"

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

	for(i = poly.d; i >= 0; i--)
	{
		BN_mod_exp( cm->C, cm->C, pp.q, pp.G, ctx);
		BN_mod_exp( bn_tmp1, pp.g, poly.Fx[i], pp.G, ctx);
		BN_mod_mul( cm->C, cm->C, bn_tmp1, pp.G, ctx);
	}

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
	
	BN_set_word(tmp1,1);
	BN_set_word(tmp2,0);
	BN_set_word(cm->Fhat,0);
	do{
		BN_mul(tmp2,tmp1,poly.Fx[i],ctx);
		BN_add(cm->Fhat, cm->Fhat, tmp2);
		BN_mul(tmp1,tmp1, pp.q, ctx);
		i++;
	}while(i <= poly.d);

	BN_CTX_free(ctx);
	BN_free(tmp1);
	BN_free(tmp2);

	return flag;
}

int commit(_struct_commit_ *cm, const _struct_pp_ pp)
{
	BN_CTX* ctx = BN_CTX_new();
	int flag = 1;

	flag &= BN_mod_exp(cm->C, pp.g, cm->Fhat, pp.G, ctx);

	BN_CTX_free(ctx);
	return flag;
}

int main()
{
	FILE *fp;
	unsigned int RunTime_file_IO = 0, RunTime_commit = 0;
	_struct_pp_ pp;
	_struct_commit_ cm;
	_struct_poly_ poly;
 
	cm.C = BN_new();
	cm.Fhat = BN_new();

	TimerOn();
	Read_pp( &pp );
	Read_poly(&poly);
	RunTime_file_IO += TimerOff();
	
	TimerOn();
	commit_new(&cm, pp, poly);
	//encode(&cm, pp, poly);
	//commit(&cm, pp);
	RunTime_commit = TimerOff();

	TimerOn();
	Write_Commit(&cm);
	RunTime_file_IO += TimerOff();

	printf("Commit_TIME_ %12u [us]\n", RunTime_commit);
	printf("Commit_I/O__ %12u [us]\n", RunTime_file_IO);

	fp = fopen("record/commit.txt", "a+");
	fprintf(fp, "%d ", RunTime_file_IO);			
	fprintf(fp, "%d\n", RunTime_commit);
	fclose(fp);

	BN_free(cm.C);
	BN_free(cm.Fhat);
	return 0;
}
