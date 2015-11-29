#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
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

RSA * createRSA(unsigned char* key) {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}

char* publicKeyEncrypt(char* pub_key, char* sessionKey){
    // Where we send the key to 
    RSA *rsa = createRSA(pub_key);
    char *encrypted = malloc((RSA_size(rsa) + 1) * sizeof(*encrypted));
    int result = RSA_public_encrypt(strlen(sessionKey), sessionKey, encrypted, rsa, RSA_NO_PADDING);
    encrypted[result] = '\0';

    // printf("RESULT:%i\n", result);
    if (result == -1) {
        char * err = malloc(130);;
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        printf("ERROR: %s\n", err);
        free(err);
    }
    // printf("%s\n",pub_key);
    // printf("%s\n", privbuffer);
    // printf("HERE IS ENCRYPTED: %s\n", encrypted);

    return encrypted;
}

char* encrypt(char *strToEncypt, char* key) {
    int bfSize = strlen(strToEncypt);

    BF_KEY *bf_key = malloc((bfSize*2 + 1) * sizeof(*bf_key));
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
