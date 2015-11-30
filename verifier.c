#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Prototype for verifier only
void getEntries(char*, char**, char**);

void verifyEntryNum(int entrynum) {

	closeLogfp();
	int linecount = getNumOfLinesInFile(getFileName());
	//printf("linecount%d\n", linecount);
	char* entryKeys[linecount];
	char* entryData[linecount];
	getEntryKeys_Verifier(entryData, entryKeys, linecount);

	if (entryKeys == NULL || linecount < entrynum) {
		printf("Failed Verification\n");
	} else {
		setKey(entryKeys[entrynum]);
		printf("%s\n", decrypt(entryData[entrynum]));
	}

	int i = 0;
	for(; i < linecount; i++) {
		if (entryKeys[i] != NULL)
			free(entryKeys[i]);
		if(entryData[i] != NULL)
			free(entryData[i]);
	}

};

void verifyAll(char* logFile, char* outFile) {
	setFileName(logFile);

	int linecount = getNumOfLinesInFile(logFile);
	char* entryKeys[linecount];
	char* entryData[linecount];
	getEntryKeys_Verifier(entryData, entryKeys);

	if (entryKeys == NULL) {
		printf("Failed Verification\n");
		return;
	}
		printf("You wanna verify this but you cant yet\n");


}

/*
	Read file into array of strings, each index is a line.
	Send this list to T, which returns a list of keys.
	If T returns NULL, it failed.
 */
void getEntryKeys_Verifier(char** entryData, char** entryKeys, int line_count) {

	/*
	 Types of messages to verify
		LogFileInitializationType
		ResponseMessageType
		AbnormalCloseType
		NormalCloseMessage
		AddMessageType
	 */

	// Get the file in an array of strings
	//int line_count = getNumOfLinesInFile(getFileName());
	char* entries[line_count];
	
	printf("Getting the Entries\n------------\n");
	getEntries(getFileName(), entries, entryData);

	// Recieve Keys, from T, for each entry
	getEntryKeys_Trusted(entries, entryKeys, line_count);
}


/*
 * Get an array of pointers.
 * Each index is a line corresponding to an entry in the log.
 */
void getEntries(char* fileName, char** entries, char **entryData) {
	int line_count = getNumOfLinesInFile(fileName);

	//char* entries[line_count];// = (char **)malloc((getLengthOfFile(fileName)+16)*sizeof(char*));

	// Set up to read the file
	//closeLogfp();

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
		printf("Entry[%d]: %s\n",index, entries[index] );

    	entryData[index] = malloc((strlen(line)+1)*sizeof(entryData[index]));

		char *strtok_ctx;
		char *s = strdup(line);

		strtok_r(s, "\t", &strtok_ctx);

		strtok_r(NULL, "||", &strtok_ctx); //Yj
		strtok_r(NULL, "||", &strtok_ctx); //Zj

		char* data = strtok_r(NULL, "||", &strtok_ctx);

		if (data != NULL) {
			strcpy(entryData[index], data);
			printf("Data[%d]: %s\n", index, data);
		}


		index++;
    }

    fclose(fp);
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
	//char* entries[10];
	//getEntryKeys_Verifier(entries);
	//printf("Added message\n");
	char message[5] = "Msg\0";
	char message2[6] = "Msg2\0";

	addMessage(message);
	//addMessage(message2);
	//printf("Added message\n");
	verifyEntryNum(1);
}