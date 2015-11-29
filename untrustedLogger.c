#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/blowfish.h>

#include "prototypes.h"

char *sessionKey = NULL;

char *createKey(int length) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";        

    char *currentKey = NULL;
     currentKey = malloc(sizeof(char) * (length +1));

    if (currentKey) {    
      	int n;        
        for (n = 0; n < length; n++) {            
            int key = rand() % (int)(sizeof(charset) -1);
            currentKey[n] = charset[key];
        }

        currentKey[length] = '\0';
    }

    return currentKey;
}

RSA * createRSA(unsigned char* key) {
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	return rsa;
}

char * fileToBuffer(FILE *fp) {
	fseek(fp, 0L, SEEK_END);

	// Get the size of the file
	int size = ftell(fp);
	rewind(fp);

	// Now read into a buffer
	char *buffer;
	buffer = malloc((size + 1) * sizeof(*buffer));
	fread(buffer, size, 1, fp);
	buffer[size] = '\0';
	return buffer;
}

// TODO, Add SIGNsku(X0) to this function
char * toCharPointHelper(char Cu[], char A0[]) {
	return strcat(Cu, A0);
}

/*
 * The logger creates and opens a new log file with the specified name. The logger
 * should create a file with the given name in the current directory. According to
 * the protocol, this operation should add a log entry about the creation of the log
 * file
 */
void createLog(char fileName[]) {
	// Create new file with specified name
	FILE *fp;
	fp = fopen(fileName, "w+");
		// FOR LATER USE: fputs(char *s, FILE *fp);

	// Form first log entry L0
		// L0 contains:
		// 	W0 - Log file initialization type
		//	D0 - IDlog, M0
			// IDlog - Unique string identifier for this log
			// M0 (Message 0) - IDu, PKEpkT(K0), Ek0(X0, SIGNsku(X0))
				// IDu - Unique String for entity u
				// PKEpkT(K0) - public key enc. where K is a random session key. 
					// RSA
			// hash(X)
			// SHA-1
			// Hash the authentication key Aj immediately after a log entry is written
				

	// W0 - Log file initialization type
	char w0[] = "LogfileInitializationType";

	// IDlog - Unique string identifier for this log
	char IDlog[strlen(fileName)];
	strcpy(IDlog, fileName);

	// IDu - Unique String for entity u
	char IDu = 'c';

	// PKEpkT(K0) - public key enc. under t's public key K. Use RSA.
		// data length
		// from (U's priv key K0)
		// To String PKEpkTK0
		// RSA, T's public key
		// int padding

	// Get U's private key
	// FILE *upriv;
	// upriv = fopen("U_Priv.pem", "r");
	// char *privbuffer = fileToBuffer(upriv);

	FILE *upub;
	upub = fopen("U_Pub.pub", "r");
	char *upub_key = fileToBuffer(upub);

	FILE *tpub;
	tpub = fopen("T_Pub.pub", "r");
	char *tpub_key = fileToBuffer(tpub);

	RSA *rsa = createRSA(tpub_key);

	// Where we send the key to 
	char *encrypted = malloc((RSA_size(rsa) + 1) * sizeof(*encrypted));

	// ------------- generate random session key K0 -------------
	sessionKey = createKey(RSA_size(rsa));

	int result = RSA_public_encrypt(strlen(sessionKey), sessionKey, encrypted, rsa, RSA_NO_PADDING);
	encrypted[result] = '\0';

	// printf("RESULT:%i\n", result);
	if (result == -1) {
		char * err = malloc(130);;
   		ERR_load_crypto_strings();
    	ERR_error_string(ERR_get_error(), err);
   	 	printf("ERROR: %s\n", err);
    	free(err);
	}
	// printf("%s\n",tpub_key);
	// printf("%s\n", privbuffer);
	// printf("HERE IS ENCRYPTED: %s\n", encrypted);

	// ------------- get time stamp d and d+ -------------
	struct timeval timeStamp;
	struct timeval timeStamp_expire;

	gettimeofday(&timeStamp,NULL);
	gettimeofday(&timeStamp_expire,NULL);
	// add 10 minutes to expire time
	timeStamp_expire.tv_sec += 600;

	// ------------- get certificate from T -------------
	char *certificate = getCertificate(upub_key); //this call currently just returns static string

	// ------------- generate authentication key A0 -------------
	char *authKey = createKey(RSA_size(rsa));

	// ------------- ignore protocol step identifier p (according to TA) -------------

	// ------------- create X0 from existing variables -------------
	struct X {
	   	struct timeval d;
	   	char  Cu[strlen(certificate) + 1];
	   	char  A0[strlen(authKey) + 1];
	} X0;

	X0.d = timeStamp;
	strcpy(X0.Cu, certificate);
	strcpy(X0.A0, authKey); 

	// printf ("d: %d.%06d\n", (int)X0.d.tv_sec, (int)X0.d.tv_usec);
	// printf("Cu: %s\n", X0.Cu);
	// printf("A0: %s\n", X0.A0);


	//Ek0(X0, SIGNsku(X0)) 
		// Blowfish
		// Symmetric encrption of X0, use key K0
		// Symmetric enc. of digital signature under u's private key, of X, use RSA.

		// X0 = Cu, A0
			// Cu - U's certificate from T
			// A0 - random start point

	// ------------- Turn K0 into BF key for symmetric enc -------------
	int bfSize = strlen(toCharPointHelper(X0.Cu, X0.A0));

	BF_KEY *bf_key = malloc((bfSize + 1) * sizeof(*bf_key));

	BF_set_key(bf_key, bfSize, sessionKey);

	//printf("Session Key: %s\n", sessionKey);

	char *Ek0 = malloc((bfSize + 1) * sizeof(*Ek0));

	//printf("X0:  %s | Len: %i\n", toCharPointHelper(X0.Cu, X0.A0), bfSize);

	char * ivec = malloc((bfSize + 1) * sizeof(*Ek0));
	BF_cbc_encrypt(toCharPointHelper(X0.Cu, X0.A0), Ek0, bfSize, bf_key, ivec, BF_ENCRYPT);

	//printf("Ek0: %s | Len: %i\n", Ek0, (int)strlen(Ek0));

	unsigned char *out = malloc((bfSize + 1) * sizeof(*Ek0));
	//BF_ecb_encrypt(Ek0, out, bf_key, BF_DECRYPT);
	char * ivec2 = malloc((bfSize + 1) * sizeof(*Ek0));

	BF_cbc_encrypt(Ek0, out, bfSize, bf_key, ivec2, BF_DECRYPT);

	//printf("BF_DECRYPT: %s | Len: %i\n", out, (int)strlen(out));

	// ------------- EK0 done & created -------------


}

