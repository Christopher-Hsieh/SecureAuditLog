#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Prototypes for verifier only
void getEntries(char*, char**);


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

	// Get the file in an array of strings
	int line_count = getNumOfLinesInFile(getFileName());
	char* entries[line_count];
	
	getEntries(getFileName(), &entries);

	int i = 0;
	while(1) {
		printf("%s\n", entries[i++]);
		if (i >= line_count) break;
	}

	// Recieve Decryption key for that record
	return NULL;
}


/*
 * Get an array of pointers.
 * Each index is a line corresponding to an entry in the log.
 */
void getEntries(char* fileName, char** entries) {
	int line_count = getNumOfLinesInFile(fileName);

	//char* entries[line_count];// = (char **)malloc((getLengthOfFile(fileName)+16)*sizeof(char*));

	// Set up to read the file
	FILE *fp;
	fp = fopen(fileName, "r");

	char * line = NULL;
    size_t len = 0;
    ssize_t read;

    int index = 0;

    // Read file line by line into our array
    while ((read = getline(&line, &len, fp)) != -1) {
    	entries[index] = malloc((strlen(line)+1)*sizeof(entries[index]));
		strcpy(entries[index], line);
		//printf("%s\n", entries[index]);
		index++;
    }

	return entries;
}

int getNumOfLinesInFile(char* fileName) {
	FILE *fp;
	fp = fopen(fileName, "r");

	char * line = NULL;
    size_t len = 0;
    ssize_t read;

    int count = 0;
	
	while ((read = getline(&line, &len, fp)) != -1) {
		count++;
    }

    rewind(fp);
    fclose(fp);
    return count;
}

int getLengthOfFile(char* fileName){
	FILE *fp;
	fp = fopen(fileName, "r");

	fseek(fp, 0L, SEEK_END);

	int size = ftell(fp);

	fseek(fp, 0L, SEEK_SET);

	fclose(fp);

	return size;
}


void verifyTest() {
	//printf("%i\n", getNumOfLinesInFile(getFileName()));
	//getEntries(getFileName());
	verifyLine(2);
}