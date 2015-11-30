#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Prototypes for verifier only
void getEntries(char*, char**);

void verifyAll(char* logFile, char* outFile) {
	FILE *fp;
	fp = fopen(logFile, "r");
}

/*
	Read file into array of strings, each index is a line.
	Send this list to T, which returns a list of keys.
	If T returns NULL, it failed.
 */
void getEntryKeys_Verifier(int line_num, char** entryKeys) {

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

	// Recieve Keys, from T, for each entry
	getEntryKeys_Trusted(&entries, &entryKeys, line_count);
	// TODO: Do something with the entry KEys
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
	//verifyEntryNum(2);
	char* entries[10];
	getEntryKeys_Verifier(1, entries);
}