#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "prototypes.h"


void main (int argc, char *argv[]) {
	char buffer[256];

	// Initialize memory for holding the key for enc/dec
	initRealKey();

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
			scanf("%[^\n]s", buffer);
			addMessage(buffer+1+'\0');
		}

		// Close log cmd
		else if (strcmp(buffer, "closelog") == 0) {
			closeLog();
		}

		// Verify entry_no cmd
		else if (strncmp(buffer, "verify", 6) == 0) {
			int *line_no;
			scanf("%i", line_no);
			//verifyEntryNum(line_no);
		}

		// Verify all cmd
		else if (strncmp(buffer, "verifyall", 9) == 0) {
			char log_file_name[128];
			char out_file_name[128];
			scanf("%s", log_file_name);
			scanf("%s", out_file_name);
			verifyAll(log_file_name, out_file_name);
		}

		else if (strcmp(buffer, "exit") == 0) {
			exit(0);
		}

		// Clean the buffer for new input
		memset(buffer,0,sizeof(buffer));
	}

 }