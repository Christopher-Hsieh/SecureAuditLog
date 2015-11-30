#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "prototypes.h"

int LogNumber = 0;

void incLogNum() {
	LogNumber++;
}

int getLogNum() {
	return LogNumber;
}


void main (int argc, char *argv[]) {
	char buffer[256];

	while(1) {
		// Get the next command to run
		scanf("%s", buffer);

		// Create log cmd
		if (strcmp(buffer, "createlog") == 0) {
			scanf("%s", buffer);	// Get the name of the Log
			createLog(buffer);
		} 

		// Add log message cmd
		else if (strncmp(buffer, "add", 3) == 0) {
			//TODO
		}

		// Close log cmd
		else if (strcmp(buffer, "closelog") == 0) {
			//TODO
		}

		// Verify entry_no cmd
		else if (strncmp(buffer, "verify", 6) == 0) {
			//TODO
		}

		// Verify all cmd
		else if (strncmp(buffer, "verifyall", 9) == 0) {
			//TODO
		}

		else if (strcmp(buffer, "exit") == 0) {
			exit(0);
		}

		// Clean the buffer for new input
		memset(buffer,0,sizeof(buffer));
	}

 }