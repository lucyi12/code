#include <stdio.h>
#include <tchar.h>
#include <tomcrypt.h>
#include <math.h>


int aes_cbc(){

	int error=0;//返回值
	int index=0;//加解密器索引
	unsigned char IV[16]={0};//初始化向量
	unsigned char key[16]= {""};//对称密匙
	unsigned char pwd[16]={""};//初始化口令
	symmetric_CBC cbcAES={0};//对称加解密内部结构
	FILE *filepwd=0,*filePlainText=0,*fileCipherText=0,*decryptFile=0;//文件
	unsigned char ct[256]={0},pt[256]={0};//加解密数据块
	size_t len=0;//长度



	//注册加解密器
	if(-1==register_cipher(&aes_desc)){
		printf("register_cipher(&aes_desc) failed");
		return -1;
	}

	//查找对应索引
	index = find_cipher("aes");
	if(index==-1){

		printf("find_cipher(\"aes\") failed");
		goto EndOfCrypt;
	}

	printf("请选择加密操作或解密操作\n0:加密文件\n1:解密文件\n");
	char x[2];
	scanf("%s", &x);
	if(x[0]=='0'){
		printf("请设置口令:");
		scanf("%s", pwd);

		//随机初始化IV向量
		sprintf((char*)IV,"%ld",((long)rand())%((long)1<<15));
		//随机初始化密钥
		sprintf((char*)key,"%ld",((long)rand())%((long)1<<15));

		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "wb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}

		//依次写入口令、密钥、初始向量
		fwrite(pwd, sizeof(pwd[0]), 16, filepwd);
		fwrite(key, sizeof(pwd[0]), 16, filepwd);
		fwrite(IV, sizeof(pwd[0]), 16, filepwd);

		//加密流程
		//开始CBC模式加解密
		error = cbc_start(index,IV,key,sizeof(key),0,&cbcAES);
		if(error != CRYPT_OK){
			printf("cbc_start error:%s"),error_to_string(error);
			goto EndOfCrypt;
		}
		//打开要加密的文件

		char str[1024];
		printf("请输入你选择加密的文件位置：");
		scanf("%s",str);
		filePlainText=fopen(str,"r");

		//filePlainText=fopen("D:\\VS\\code\\Crypt\\plaintext.txt","r");
		if(filePlainText == 0){
			printf("fopen(\"str\",\"r\") failed");
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}
		//创建加密后的文件
		fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","wb");
		if(filePlainText==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"wb\") failed");
			fclose(filePlainText);
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}

		//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，我这里简单置零了
		while(!feof(filePlainText)){
			memset(pt,0,sizeof(pt));
			memset(ct,0,sizeof(ct));
			len = fread(pt,sizeof(pt[0]),256,filePlainText);
			if(len < 1)//没有读成功
				break;
			//加密
			error = cbc_encrypt(pt,ct,256,&cbcAES);
			if(error != CRYPT_OK){
				printf(("cbc_encrypt error:%s"),error_to_string(error));
				break;
			}
			fwrite(ct,sizeof(ct[0]),256,fileCipherText);
		}


		//关闭文件
		fclose(filepwd);
		fclose(filePlainText);
		fclose(fileCipherText);
		//完成流加解密

		cbc_done(&cbcAES);

		//end 加密流程
		printf("加密成功 \n");
	}

	else if(x[0]=='1'){
		printf("请设置口令：");
		scanf("%s", pwd);
		unsigned char pwd1[16] = { "" };
		unsigned char key1[16] = { "" };
		unsigned char IV1[16] = { "" };

		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "rb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}

		int flag = 0;//判断在口令文件中是否找到输入的口令
		while (!feof(filepwd)) {
			memset(pwd1, 0, sizeof(pwd1));
			len = fread(pwd1, sizeof(pwd1[0]), 16, filepwd);
			if (len < 1)	//没有读成功
				break;
			if (*(pwd1) == *(pwd))
			{
				flag = 1;
				fread(key, sizeof(key[0]), 16, filepwd);
				fread(IV, sizeof(IV[0]), 16, filepwd);
			}
		}

		//输入口令不存在
		if (flag==0)
		{
			printf("口令错误");
			goto EndOfCrypt;
		}


		//解密流程
		//开始CBC模式加解密
		error=cbc_start(index,IV,key,sizeof(key),0,&cbcAES);
		if(error!=CRYPT_OK){
			printf("cbc_start error:%s"),error_to_string(error);
			goto EndOfCrypt;
		}
		//打开要解密的文件
		fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","rb");
		if(fileCipherText==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"rb\") failed");
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}
		//创建解密后的文件
		decryptFile=fopen("D:\\VS\\code\\Crypt\\decrypttext.txt","wb");
		if(decryptFile==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\decrypttext.txt\",\"wb\") failed");

			fclose(fileCipherText);
			cbc_done(&cbcAES);
			goto EndOfCrypt;
		}
		//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，前面简单置零，所以可以正常写文件
		while(!feof(fileCipherText)){
			memset(pt,0,sizeof(pt));
			memset(ct,0,sizeof(ct));
			len=fread(ct,sizeof(ct[0]),256,fileCipherText);
			if(len<1)
				//没有读成功
					break;
			//解密
			error=cbc_decrypt(ct,pt,256,&cbcAES);
			if(error!=CRYPT_OK){
				printf("cbc_decrypt error:%s"),error_to_string(error);
				break;
			}
			fwrite(pt,sizeof(pt[0]),256,decryptFile);
		}
		//关闭文件
		fclose(filepwd);
		fclose(fileCipherText);
		fclose(decryptFile);
		//完成流加解密
		cbc_done(&cbcAES);
		//end 解密流程
		printf("解密成功 \n");
	}

EndOfCrypt:
	//注销加解密器
	error=unregister_cipher(&aes_desc);
	if(error!=CRYPT_OK){
		printf("unregister_cipher(&aes_desc) error:%s"),error_to_string(error);
		return (-1);
	}

	return 0;
}

int twofish_cbc(){
	int error=0;//返回值
	int index=0;//加解密器索引
	unsigned char IV[16]={0};//初始化向量
	unsigned char key[16]= {""};//对称密匙
	unsigned char pwd[16]={""};//初始化口令
	symmetric_CBC cbcTWOFISH={0};//对称加解密内部结构
	FILE *filepwd=0,*filePlainText=0,*fileCipherText=0,*decryptFile=0;//文件
	unsigned char ct[256]={0},pt[256]={0};//加解密数据块
	size_t len=0;//长度



	//注册加解密器
	if(-1==register_cipher(&twofish_desc)){
		printf("register_cipher(&twofish_desc) failed");
		return -1;
	}

	//查找对应索引
	index = find_cipher("twofish");
	if(index==-1){

		printf("find_cipher(\"twofish\") failed");
		goto EndOfCrypt;
	}

	printf("请选择加密操作或解密操作\n0:加密文件\n1:解密文件\n");
	char x[2];
	scanf("%s", &x);
	if(x[0]=='0'){
		printf("请设置口令:");
		scanf("%s", pwd);

		//随机初始化IV向量
		sprintf((char*)IV,"%ld",((long)rand())%((long)1<<15));
		//随机初始化密钥
		sprintf((char*)key,"%ld",((long)rand())%((long)1<<15));

		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "wb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}

		//依次写入口令、密钥、初始向量
		fwrite(pwd, sizeof(pwd[0]), 16, filepwd);
		fwrite(key, sizeof(pwd[0]), 16, filepwd);
		fwrite(IV, sizeof(pwd[0]), 16, filepwd);

		//加密流程
		//开始CBC模式加解密
		error = cbc_start(index,IV,key,sizeof(key),0,&cbcTWOFISH);
		if(error != CRYPT_OK){
			printf("cbc_start error:%s"),error_to_string(error);
			goto EndOfCrypt;
		}
		//打开要加密的文件

		char str[1024];
		printf("请输入你选择加密的文件位置：");
		scanf("%s",str);
		filePlainText=fopen(str,"r");

		//filePlainText=fopen("D:\\VS\\code\\Crypt\\plaintext.txt","r");
		if(filePlainText == 0){
			printf("fopen(\"str\",\"r\") failed");
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}
		//创建加密后的文件
		fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","wb");
		if(filePlainText==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"wb\") failed");
			fclose(filePlainText);
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}

		//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，我这里简单置零了
		while(!feof(filePlainText)){
			memset(pt,0,sizeof(pt));
			memset(ct,0,sizeof(ct));
			len = fread(pt,sizeof(pt[0]),256,filePlainText);
			if(len < 1)//没有读成功
				break;
			//加密
			error = cbc_encrypt(pt,ct,256,&cbcTWOFISH);
			if(error != CRYPT_OK){
				printf(("cbc_encrypt error:%s"),error_to_string(error));
				break;
			}
			fwrite(ct,sizeof(ct[0]),256,fileCipherText);
		}


		//关闭文件
		fclose(filepwd);
		fclose(filePlainText);
		fclose(fileCipherText);
		//完成流加解密

		cbc_done(&cbcTWOFISH);

		//end 加密流程
		printf("加密成功 \n");
	}

	else if(x[0]=='1'){
		printf("请设置口令：");
		scanf("%s", pwd);
		unsigned char pwd1[16] = { "" };
		unsigned char key1[16] = { "" };
		unsigned char IV1[16] = { "" };

		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "rb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}

		int flag = 0;//判断在口令文件中是否找到输入的口令
		while (!feof(filepwd)) {
			memset(pwd1, 0, sizeof(pwd1));
			len = fread(pwd1, sizeof(pwd1[0]), 16, filepwd);
			if (len < 1)	//没有读成功
				break;
			if (*(pwd1) == *(pwd))
			{
				flag = 1;
				fread(key, sizeof(key[0]), 16, filepwd);
				fread(IV, sizeof(IV[0]), 16, filepwd);
			}
		}

		//输入口令不存在
		if (flag==0)
		{
			printf("口令错误");
			goto EndOfCrypt;
		}


		//解密流程
		//开始CBC模式加解密
		error=cbc_start(index,IV,key,sizeof(key),0,&cbcTWOFISH);
		if(error!=CRYPT_OK){
			printf("cbc_start error:%s"),error_to_string(error);
			goto EndOfCrypt;
		}
		//打开要解密的文件
		fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","rb");
		if(fileCipherText==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"rb\") failed");
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}
		//创建解密后的文件
		decryptFile=fopen("D:\\VS\\code\\Crypt\\decrypttext.txt","wb");
		if(decryptFile==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\decrypttext.txt\",\"wb\") failed");

			fclose(fileCipherText);
			cbc_done(&cbcTWOFISH);
			goto EndOfCrypt;
		}
		//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，前面简单置零，所以可以正常写文件
		while(!feof(fileCipherText)){
			memset(pt,0,sizeof(pt));
			memset(ct,0,sizeof(ct));
			len=fread(ct,sizeof(ct[0]),256,fileCipherText);
			if(len<1)
				//没有读成功
					break;
			//解密
			error=cbc_decrypt(ct,pt,256,&cbcTWOFISH);
			if(error!=CRYPT_OK){
				printf("cbc_decrypt error:%s"),error_to_string(error);
				break;
			}
			fwrite(pt,sizeof(pt[0]),256,decryptFile);
		}
		//关闭文件
		fclose(filepwd);
		fclose(fileCipherText);
		fclose(decryptFile);
		//完成流加解密
		cbc_done(&cbcTWOFISH);
		//end 解密流程
		printf("解密成功 \n");
	}

EndOfCrypt:
	//注销加解密器
	error=unregister_cipher(&twofish_desc);
	if(error!=CRYPT_OK){
		printf("unregister_cipher(&twofish_desc) error:%s"),error_to_string(error);
		return (-1);
	}

	return 0;
}

int aes_ecb(){

	int error=0;//返回值
	int index=0;//加解密器索引
	unsigned char pwd[16]={""};//初始化口令
	unsigned char key[16]= {""};//对称密匙
	symmetric_ECB ecbAES={0};//对称加解密内部结构
	FILE *filepwd=0,*filePlainText=0,*fileCipherText=0,*decryptFile=0;//文件
	unsigned char ct[256]={0},pt[256]={0};//加解密数据块
	size_t len=0;//长度
	//注册加解密器
	if(-1==register_cipher(&aes_desc)){
		printf("register_cipher(&aes_desc) failed");
		return -1;
	}
	
	//查找对应索引
	index = find_cipher("aes");
	if(index==-1){

		printf("find_cipher(\"aes\") failed");
		goto EndOfCrypt;
	}
	printf("请选择加密操作或解密操作\n0:加密文件\n1:解密文件\n");
	char x[2];
	scanf("%s", &x);
	if(x[0]=='0'){
		printf("请设置口令:");
		scanf("%s", pwd);

		//随机初始化密钥
		sprintf((char*)key,"%ld",((long)rand())%((long)1<<15));

		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "wb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			ecb_done(&ecbAES);
			goto EndOfCrypt;
		}

		//依次写入口令、密钥、初始向量
		fwrite(pwd, sizeof(pwd[0]), 16, filepwd);
		fwrite(key, sizeof(pwd[0]), 16, filepwd);
		


	//加密流程
	//开始CBC模式加解密
	error = ecb_start(index,key,sizeof(key),0,&ecbAES);
	if(error != CRYPT_OK){
		printf("cbc_start error:%s"),error_to_string(error);
		goto EndOfCrypt;
	}
	//打开要加密的文件

	char str[1024];
	printf("请输入你选择加密的文件位置：");
	scanf("%s",str);
	filePlainText=fopen(str,"r");

	//filePlainText=fopen("D:\\VS\\code\\Crypt\\plaintext.txt","r");
	if(filePlainText == 0){
		printf("fopen(\"str\",\"r\") failed");
		ecb_done(&ecbAES);
		goto EndOfCrypt;
	}
	//创建加密后的文件
	fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","wb");
	if(filePlainText==0){
		printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"wb\") failed");
		fclose(filePlainText);
		ecb_done(&ecbAES);
		goto EndOfCrypt;
	}

	//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，我这里简单置零了
	while(!feof(filePlainText)){
		memset(pt,0,sizeof(pt));
		memset(ct,0,sizeof(ct));
		len = fread(pt,sizeof(pt[0]),256,filePlainText);
		if(len < 1)//没有读成功
			break;
		//加密
		error = ecb_encrypt(pt,ct,256,&ecbAES);
		if(error != CRYPT_OK){
			printf(("cbc_encrypt error:%s"),error_to_string(error));
			break;
		}
		fwrite(ct,sizeof(ct[0]),256,fileCipherText);
	}

	//关闭文件
	fclose(filepwd);
	fclose(filePlainText);
	fclose(fileCipherText);
	//完成流加解密
	ecb_done(&ecbAES);
	//end 加密流程
	printf("加密成功 \n");
	}

	else if(x[0]=='1'){
		printf("请设置口令：");
		scanf("%s", pwd);
		unsigned char pwd1[16] = { "" };
		unsigned char key1[16] = { "" };
		//打开口令文件
		filepwd = fopen("D:\\VS\\code\\Crypt\\pwd.txt", "rb");
		if (filepwd == 0) {
			printf("can't open file");
			fclose(filepwd);
			ecb_done(&ecbAES);
			goto EndOfCrypt;
		}

		int flag = 0;//判断在口令文件中是否找到输入的口令
		while (!feof(filepwd)) {
			memset(pwd1, 0, sizeof(pwd1));
			len = fread(pwd1, sizeof(pwd1[0]), 16, filepwd);
			if (len < 1)	//没有读成功
				break;
			if (*(pwd1) == *(pwd))
			{
				flag = 1;
				fread(key, sizeof(key[0]), 16, filepwd);
			}
		}

		//输入口令不存在
		if (flag==0)
		{
			printf("口令错误");
			goto EndOfCrypt;
		}

		//解密流程
		//开始CBC模式加解密
		error=ecb_start(index,key,sizeof(key),0,&ecbAES);
		if(error!=CRYPT_OK){
			printf("cbc_start error:%s"),error_to_string(error);
			goto EndOfCrypt;
		}
		//打开要解密的文件
		fileCipherText=fopen("D:\\VS\\code\\Crypt\\ciphertext.txt","rb");
		if(fileCipherText==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\ciphertext.txt\",\"rb\") failed");
			ecb_done(&ecbAES);
			goto EndOfCrypt;
		}
		//创建解密后的文件
		decryptFile=fopen("D:\\VS\\code\\Crypt\\decrypttext.txt","wb");
		if(decryptFile==0){
			printf("fopen(\"D:\\VS\\code\\Crypt\\decrypttext.txt\",\"wb\") failed");
			fclose(fileCipherText);
			ecb_done(&ecbAES);
			goto EndOfCrypt;
		}
		//CBC模式要求是块大小的倍数，末尾可以pad上自己的消息，前面简单置零，所以可以正常写文件
		while(!feof(fileCipherText)){
			memset(pt,0,sizeof(pt));
			memset(ct,0,sizeof(ct));
			len=fread(ct,sizeof(ct[0]),256,fileCipherText);
			if(len<1)
				//没有读成功
					break;
			//解密
			error=ecb_decrypt(ct,pt,256,&ecbAES);
			if(error!=CRYPT_OK){
				printf("ecb_decrypt error:%s"),error_to_string(error);
				break;
			}
			fwrite(pt,sizeof(pt[0]),256,decryptFile);
		}
		//关闭文件
		fclose(filepwd);
		fclose(fileCipherText);
		fclose(decryptFile);
		//完成流加解密
		ecb_done(&ecbAES);
		//end 解密流程
		printf("解密成功 \n");
	}

EndOfCrypt:
	//注销加解密器
	error=unregister_cipher(&aes_desc);
	if(error!=CRYPT_OK){
		printf("unregister_cipher(&aes_desc) error:%s"),error_to_string(error);
		return (-1);
	}

	return 0;
}

int _tmain() {
	while(true){

		char al[100],mode[100];
		printf("请输入选择的加密算法：");
		scanf("%s", &al);
		printf("请输入选择的加密模式：");
		scanf("%s", &mode);

		if(strcmp(al, "aes")==0 && strcmp(mode,"cbc")==0){
			aes_cbc();

		}
		else if(strcmp(al, "twofish")==0 && strcmp(mode,"cbc")==0){
			twofish_cbc();

		}
		else if(strcmp(al, "aes")==0 && strcmp(mode,"ecb")==0){
			aes_ecb();

		}
		else{
			printf("选择的加密算法或加密模式错误");
		}

	}

}