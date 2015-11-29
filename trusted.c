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

char* verifyLog(char* log){
	
}