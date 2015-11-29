#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/blowfish.h>

/*
    functions that are shared b/t trusted & untrusted
*/

char *createKey(int length) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";        

    char *currentKey = NULL;
     currentKey = malloc(sizeof(char) * (length +1));

    if (currentKey) {    
      	int n;        
        for (n = 0; n < length; n++) {            
            int key = rand() % (int)(sizeof(charset) -1);
            currentKey[n] = charset[key];
        }

        currentKey[length] = '\0';
    }

    return currentKey;
}


char* encrypt(char *strToEncypt, char* key) {
    int bfSize = strlen(strToEncypt);
    BF_KEY *bf_key = malloc((bfSize + 1) * sizeof(*bf_key));

    // Turn key into BF key
    BF_set_key(bf_key, bfSize, key);

    char *encryptedStr = malloc((bfSize + 1) * sizeof(*encryptedStr));

    char * ivec = malloc((bfSize + 1) * sizeof(*encryptedStr));
    BF_cbc_encrypt(strToEncypt, encryptedStr, bfSize, bf_key, ivec, BF_ENCRYPT);

    return encryptedStr;
}

char* decrypt(char* in, char* key) {
    int bfSize = strlen(in);

    BF_KEY *bf_key = malloc((bfSize + 1) * sizeof(*bf_key));
    // Turn key into BF key
    BF_set_key(bf_key, bfSize, key);

    unsigned char *out = malloc((bfSize + 1) * sizeof(*out));
    
    char * ivec = malloc((bfSize + 1) * sizeof(*ivec));

    BF_cbc_encrypt(in, out, bfSize, bf_key, ivec, BF_DECRYPT);
    return out;
}
