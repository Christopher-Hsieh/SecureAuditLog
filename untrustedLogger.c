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
int SIZE_OF_RSA = 16;


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
U forms the first log entry, L0:
	W0 = LogFileInitializationType
	D0 = d; d+; IDlog; M0
		M0 = IDu, PKEpkt(K0), Ek0(X0, SIGNsku(X0))
*/
void createFirstLogEntry(char* filename, char* w0, struct timeval d, 
						 int IDu, char* PKEpkt, char* Ek0) {
	FILE *fp;
	fp = fopen(filename, "w+");

	// Make IDlog - Unique identifier for this log
	fputs("LOGIDENTIFIER:1\n\n", fp);
	//fputs((const char*)getLogNumber(), fp);

	fputs("Entry:0\n", fp);

	fputs("LogFileInitializationType:", fp);
	fputs(w0, fp);
	fputs("\n", fp);

	// d or timestamp
	// fputs("Time:", fp);
	// fputs(d, fp);
	// fputs("\n", fp);

	// //IDu
	// fputs("IDu:", fp);
	// fputs(IDu, fp);
	// fputs("\n", fp);

	//PKEpkt
	fputs("PKEpkt:", fp);
	fputs(PKEpkt, fp);
	fputs("\n", fp);

	//Ek0
	fputs("Ek0:", fp);
	fputs(Ek0, fp);
	fputs("\n", fp);


	fclose(fp);

}

/*
 * The logger creates and opens a new log file with the specified name. The logger
 * should create a file with the given name in the current directory. According to
 * the protocol, this operation should add a log entry about the creation of the log
 * file
 */
void createLog(char fileName[]) {
	// Create new file with specified name

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

	// IDu - Unique ID for entity u
	int IDu = 101;

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

	// ------------- generate random session key K0 -------------
	sessionKey = createKey(SIZE_OF_RSA);


	// ------------- Encrypt using PKE --------------
	char *pke = publicKeyEncrypt(tpub_key, sessionKey);

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
	char *authKey = createKey(SIZE_OF_RSA);

	// ------------- ignore protocol step identifier p (according to TA) -------------

	// ------------- create X0 from existing variables -------------
	//Ek0(X0, SIGNsku(X0)) 
		// Blowfish
		// Symmetric encrption of X0, use key K0
		// Symmetric enc. of digital signature under u's private key, of X, use RSA.

		// X0 = Cu, A0
			// Cu - U's certificate from T
			// A0 - random start point
	char* message = malloc((strlen(certificate) + strlen(authKey)) * sizeof(*message));
	strcpy(message, certificate);
	strcat(message, authKey);

	// ------------- Turn K0 into BF key for symmetric enc -------------
	char *Ek0 = malloc((strlen(message) + 1) * sizeof(*Ek0));
	Ek0 = encrypt(message, sessionKey);


	// ------------- EK0 done & created -------------

	verifyLog(IDu, pke, Ek0);
	//createFirstLogEntry(fileName, w0, X0.d, IDu, pke, Ek0);
}

