#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "prototypes.h"

int IDt = 111;
int SIZE_OF_KEY = 16;

char* getCertificate(char* publicKey){
	//not sure how to generate the certificate or what the paper is even saying for this part
	return "random_key";
}

void verifyLog(int IDu, char* PKEsessionKey, char* encryptedLog){
	FILE *tpriv;
	tpriv = fopen("T_Priv.pem", "r");
	RSA *tpriv_key = PEM_read_RSAPrivateKey(tpriv,NULL,NULL,NULL);

	//----------- Decrypt PKE session key -----------
	setKey(publicKeyDecrypt(tpriv_key, PKEsessionKey));
	// printf("Decrypted: %s\n", sessionKeyU);

	//----------- Decrypt encryptedLog using session key ----------- 
	char* logfile = decrypt(encryptedLog);
	printf("%s\n", logfile);

	//----------- Verify X0 is correct ----------- 
	char* hashedLogfile = hash(logfile);
	// if(hashedLogfile != getUHash()){
	// 	fprintf(stderr, "X values do not match!");
	// 	exit(0);
	// }

	//----------- Verify SIGN(X0) is correct ----------

	//----------- Create X1 = IDu, hash(X0) ----------- 
	char IDu_string[15];
	sprintf(IDu_string, "%d", IDu);
	char* X = malloc(strlen(IDu_string) + strlen(hashedLogfile) + 1); 
	X = strcat(IDu_string, hashedLogfile);

	//----------- Generate random session key K1 ----------- 
	char* sessionKey = createKey(SIZE_OF_KEY);

	//----------- Encrypt session info ----------
	//encrypt key using PKEu 
	FILE *upub;
	upub = fopen("U_Pub.pub", "r");
	char *upub_key = fileToBuffer(upub);
	char* PKEu = publicKeyEncrypt(upub_key, sessionKey);

	//encrypt X using session key
	setKey(sessionKey);
	char* E = encrypt(X);

	//----------- Create M1 = IDt, PKE(K1), E(X1, SIGN(X1)) ----------- 
	response(IDt, PKEu, E);
}