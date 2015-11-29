#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "prototypes.h"

char* getCertificate(char* publicKey){
	//not sure how to generate the certificate or what the paper is even saying for this part
	return "random_key";
}

char* verifyLog(char* IDu, char* PKEsessionKey, char* encryptedLog){
	//Decrypt PKE session key
	//Decrpyt encryptedLog using session key
	//Verify X0 and SIGN(X0) are correct
	//Create X1 = IDu, hash(X0)
	//Generate random session key K1
	//Create M1 = IDt, PKE(K1), E(X1, SIGN(X1))
}