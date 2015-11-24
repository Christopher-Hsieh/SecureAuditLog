#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// untrustedLogger.c
// This file basically acts as "U", otherwise known as Untrusted Machine/Logger

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

}