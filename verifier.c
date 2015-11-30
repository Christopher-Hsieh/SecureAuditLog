#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>


void verifyEntryNum(int line_num) {
	// Scan until we find line_num
	int currLineNo = 0;

	// char* filename = malloc((strlen(getFileName())+1)*sizeof(filename)); 
	// file= getFileName();

	FILE *fp;
	fp = fopen(getFileName(), "r");

	char * line = NULL;
    size_t len = 0;
    ssize_t read;
	
	while ((read = getline(&line, &len, fp)) != -1) {
		if (currLineNo == line_num) break;
		//printf("Retrieved line of length %zu :\n", read);
		//printf("Line Num:%i, %s\n", currLineNo, line);

		currLineNo++;
    }

    // File ended before we found the entry print error
    if (currLineNo != line_num) {
    	//printf("Failed Verification\n");
    }
    // Else we process the line we hit
    else {
    	//TODO
    	//printf("Found our line: %s\n", line);
    }

    fclose(fp);
}

void verifyAll(char* logFile, char* outFile) {
	FILE *fp;
	fp = fopen(logFile, "r");
}

// Takes in a line to verify
// Returns: NULL for failure or The decrypted message
char* verifyLine(char* line) {

	/*
	 Types of messages to verify
		LogFileInitializationType
		ResponseMessageType
		AbnormalCloseType
		NormalCloseMessage
		AddMessageType
	 */

	/* 
		Create Message to send to T it contains:
		IDlog - ID of the log we are working with
		f - index of last entry in the log
		Yf - Hash chain
		Zf  = MACaj(Yj)

	*/

	// Recieve Decryption key for that record
	return NULL;
}