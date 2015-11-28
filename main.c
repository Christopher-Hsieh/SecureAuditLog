#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "prototypes.h"

char *sessionKey = NULL;

 char *createSessionKey() {
 	static int length = 16;
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";        

     sessionKey = malloc(sizeof(char) * (length +1));

    if (sessionKey) {    
      	int n;        
        for (n = 0; n < length; n++) {            
            int key = rand() % (int)(sizeof(charset) -1);
            sessionKey[n] = charset[key];
        }

        sessionKey[length] = '\0';
    }
}

char *getSessionKey(){
	return sessionKey;
}

void main (int argc, char *argv[]) {
 	createSessionKey();
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