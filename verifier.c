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
		printf("Line Num:%i, %s\n", currLineNo, line);

		currLineNo++;
    }

    // File ended before we found the entry print error
    if (currLineNo != line_num) {
    	printf("Failed Verification\n");
    }
    // Else we process the line we hit
    else {
    	printf("Found our line: %s\n", line);
    }

    fclose(fp);
}