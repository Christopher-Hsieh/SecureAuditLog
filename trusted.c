#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Libs for certificate
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>

#include "prototypes.h"

int IDt = 111;
int SIZE_OF_KEY = 16;

int mkcert(X509 **, EVP_PKEY **, int , int , int );

char* getCertificate(char* publicKey){

	// X509 *cert;
	// EVP_PKEY *pubkey;

	// d2i_x509(&cert, publicKey, strlen(publicKey));
	// pubkey = X509_get_pubkey(cert);

	// RSA *rsa;
	// rsa = EVP_PKEY_get1_RSA(pubkey);

	// mkcert(&x509, &publicKey, 512, 0, 365);

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

	//----------- Verify X0 is correct ----------- 
	char* hashedLogfile = hash(logfile);
	printf("%s\n", hashedLogfile);
	if(strcmp(hashedLogfile, getUHash())){
		fprintf(stderr, "X0 values do not match!\n");
		return;
	}

	//----------- Verify SIGN(X0) is correct ----------

	//----------- Create X1 = IDlog, hash(X0) ----------- 
	char *IDlog_string = malloc(15 * sizeof(char));
	addMemBlock(IDlog_string);
	sprintf(IDlog_string, "%d", getLogId());
	char* X = malloc((strlen(IDlog_string) + strlen(hashedLogfile)) * sizeof(char));
	addMemBlock(X);
	strcpy(X, IDlog_string);
	strcat(X, hashedLogfile);

	//----------- Generate random session key K1 ----------- 
	char* sessionKey = hash(createKey(SIZE_OF_KEY));

	//----------- Encrypt session info ----------
	//encrypt key using PKEu 
	FILE *upub;
	upub = fopen("U_Pub.pub", "r");
	char *upub_key = fileToBuffer(upub);
	char* PKEu = publicKeyEncrypt(upub_key, sessionKey);

	//encrypt X using session key
	setKey(sessionKey);
	char* E = malloc((strlen(X) + 1) * sizeof(char));
	addMemBlock(E);
	E = encrypt(X);

	//----------- Create M1 = IDt, PKE(K1), E(X1, SIGN(X1)) ----------- 
	response(IDt, PKEu, E);
}

void getEntryKeys_Trusted(char** entries, char** keys, int line_count) {

}