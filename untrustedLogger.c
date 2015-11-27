#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
// #include <openssl/evp.h>
#include <openssl/bio.h>
// #include <openssl/err.h>
// untrustedLogger.c
// This file basically acts as "U", otherwise known as Untrusted Machine/Logger

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
				// PKEpkT(K0) - public key enc. under t's public key K. Use RSA.
				// Ek0(X0, SIGNsku(X0)) 
					// Symmetric encrption of X0, use key K0
					// Symmetric enc. of digital signature under u's private key, of X, use RSA.

				// X0 = Cu, A0
					// Cu - U's certificate from T
					// A0 - random start point

	// W0 - Log file initialization type
	char w0[5] = "admin";

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
	FILE *upriv;
	upriv = fopen("U_Priv.pem", "r");
	char *privbuffer = fileToBuffer(upriv);

	FILE *tpub;
	tpub = fopen("T_Pub.pub", "r");
	char *tpub_key = fileToBuffer(tpub);

	RSA *rsa = createRSA(tpub_key);
	//printf("%i\n", RSA_size(rsa));

	// Where we send the key to 
	char *encrypted = malloc((RSA_size(rsa) + 1) * sizeof(*encrypted));

	int result = RSA_public_encrypt(strlen(privbuffer), privbuffer, encrypted, rsa, RSA_PKCS1_PADDING);

	encrypted[result] = '\0';

	printf("RESULT:%i\n", result);
	printf("%s\n",tpub_key);
	printf("%s\n", privbuffer);
	printf("HERE IS ENCRYPTED: %s\n", encrypted);

}
