#include "../hedder/global_param.h"
#include "../hedder/util.h"

int Read_pp(_struct_pp_* pp)
{
	FILE *fp;
	int i = 0, flag = 1;
	unsigned char *str;//[100000] = {0};

	str = (unsigned char *)calloc(sizeof(unsigned char),(10000000+2));  
	fp = fopen("./Txt/pp.txt", "r");
	fscanf(fp, "%x", &(pp->security_level));

	//printf("N : %s\n",str);
	fscanf(fp, "%s", str);
	pp->G = BN_new();
	flag &= BN_hex2bn(&(pp->G), str);

	fscanf(fp, "%s", str);
	pp->g = BN_new();
	flag &= BN_hex2bn(&(pp->g), str);

	fscanf(fp, "%s", str);
	pp->q = BN_new();
	flag &= BN_hex2bn(&(pp->q), str);

	fscanf(fp, "%s", str);
	pp->p = BN_new();
	flag &= BN_hex2bn(&(pp->p), str);

	fclose(fp);
	return flag;
}

int Read_poly(_struct_poly_* poly)
{
	FILE *fp;
	int i = 0, flag = 1;
	unsigned char *str;//[10000] = {0};
	str = (unsigned char *)calloc(sizeof(unsigned char),(10000000+2));    

	fp = fopen("./Txt/poly.txt", "r");
	poly->Fx = (BIGNUM**)calloc(sizeof(BIGNUM*), 10000000+2);
	while(1){								     
		poly->Fx[i] = BN_new();
		fscanf(fp, "%s", str);
		i++;
		if(feof(fp) != 0)
			break;
	}
	fseek(fp, 0, SEEK_SET ); 	
	poly->d = i-1;
	i=0;
	while(1){
		fscanf(fp, "%s", str);
		//printf("F[%d] : %s\n", i, str);
		flag &= BN_dec2bn(&(poly->Fx[poly->d-i]), str);
		i++;
		if(feof(fp) != 0)
			break;
	}

	poly->input = BN_new();

	fscanf(fp, "%s", str);
	flag &= BN_dec2bn(&(poly->input), str);

	fclose(fp);
	return flag;
}

int Read_Commit( _struct_commit_* cm)
{
	FILE *fp;
	int cnt = 0, flag = 1;
	unsigned char *buffer;

	fp = fopen("./Txt/commit.txt", "r");
    fseek(fp, 0, SEEK_END); 
    cnt = ftell(fp);      
	fseek(fp, 0, SEEK_SET ); 
	cm->C = BN_new();
	cm->Fhat = BN_new();
	
	buffer = (unsigned char *)malloc(sizeof(unsigned char)*cnt + 1);    
	buffer[cnt]=0;
	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&(cm->C), buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&(cm->Fhat), buffer);
	//flag &= BN_dec2bn(&(cm->Fhat), str);

	fclose(fp);
	free(buffer);
	return (flag > 0 ? 1 : 0);
}

int Write_Commit(const _struct_commit_* cm)
{
	FILE *fp;
	int i = 0, flag = 1;
	unsigned char *str;
	fp = fopen("./Txt/commit.txt", "w");

	str = BN_bn2hex(cm->C);
	flag *= fprintf(fp, "%s\n", str);

	
	str = BN_bn2hex(cm->Fhat);
	flag *= fprintf(fp, "%s\n", str);

	free(str);
	fclose(fp);
	return (flag > 0 ? 1 : 0);
}

int Write_proof(_struct_poly_* poly, BIGNUM* alpha )
{
	FILE *fp;
	int i = 0, flag = 1;
	unsigned char *str;

	fp = fopen("./Txt/proof.txt", "a+");
	if(poly != NULL)
	{
		for(int i = poly->d; i>= 0; i--)
		{
			str = BN_bn2hex(poly->Fx[i]);
			flag *= fprintf(fp, "%s\n", str);
		}
		free(str);
	}
	
	if(alpha != NULL)
	{
		str = BN_bn2hex(alpha);
		flag *= fprintf(fp, "%s\n", str);
		free(str);
	}

	fclose(fp);
	return (flag > 0 ? 1 : 0);	
}

int Read_proof(BIGNUM **bn_tmp )
{
	static FILE *fp = NULL;
	unsigned char *buffer;// [10000]={0};
	int i = 0, flag = 1;

	buffer = (unsigned char *)calloc(sizeof(unsigned char),(10000000+2));    

	if(fp == NULL)
		fp = fopen("./Txt/proof.txt", "a+");

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[0], buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[1], buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[2], buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[3], buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[4], buffer);

	fscanf(fp, "%s", buffer);
	flag &= BN_hex2bn(&bn_tmp[5], buffer);

	fclose(fp);
	free(buffer);
	fp = NULL;
	return (flag > 0 ? 1 : 0);	
}

int make_poly(int d)
{
	BIGNUM* bn_tmp = BN_new();
	FILE *fp;
	int i = 0, flag = 1;
	unsigned char* str;

	fp = fopen("./Txt/poly.txt", "w");

	for(int i =0; i<d; i++)
	{
		flag *= BN_set_word(bn_tmp, 1+i); // random 
		str = BN_bn2dec(bn_tmp);
		flag *= fprintf(fp, "%s ", str);
	}

	fclose(fp);
	BN_free(bn_tmp);

	return flag;
}


// 1000
// ->002003004001
//              1
//           4000
//        3000000
//     2000000000