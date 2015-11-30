#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>



int LogNumber = 0;
int currEntry = 0;


int getCurrEntry() {
    return currEntry++;
}

void incLogNum() {
    LogNumber++;
}

int getLogNum() {
    return LogNumber;
}



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
        char * err = malloc(130);
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

char* publicKeyDecrypt(RSA* priv_key, char* encrypted){
    char *decrypted = malloc((RSA_size(priv_key) + 1) * sizeof(*decrypted));
    if(RSA_private_decrypt(strlen(encrypted), (unsigned char*)encrypted, (unsigned char*)decrypted,
                           priv_key, RSA_NO_PADDING) == -1) {
        char * err = malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
    return decrypted;
}

char* realKey = NULL;

void initRealKey() {
    realKey = malloc(256*sizeof(realKey));
    memset(realKey, 0, 256*sizeof(realKey) - 1); 
}

void setKey(char* str) {
    memcpy(realKey, str, sizeof(str));
}


char* encrypt(char *strToEncypt) {
    int bfSize = strlen(strToEncypt);

    BF_KEY *bf_key = malloc((bfSize + 1) * sizeof(*bf_key));
    // Turn key into BF key
    BF_set_key(bf_key, bfSize, realKey);

    char *encryptedStr = malloc((bfSize + 1) * sizeof(*encryptedStr));

    int n = 0;
    char ivec[8];
    memset(ivec, 0, 8);

    BF_cfb64_encrypt(strToEncypt, encryptedStr, bfSize, bf_key, ivec, &n, BF_ENCRYPT);

    return encryptedStr;
}

char* decrypt(char* in) {

    int bfSize = strlen(in);

    BF_KEY *bf_key = malloc((bfSize + 1) * sizeof(*bf_key));
    // Turn key into BF key
    BF_set_key(bf_key, bfSize, realKey);

    char *out = malloc((bfSize + 1) * sizeof(*out));

    int n = 0;
    char ivec[8];
    memset(ivec, 0, 8);

    BF_cfb64_encrypt(in, out, bfSize, bf_key, ivec, &n, BF_DECRYPT);

    return out;
}

char* hash(char* in){
    size_t length = sizeof(in);

    unsigned char hash[SHA_DIGEST_LENGTH];
    return SHA1(in, length, hash);
}

/*  Three things to do here:
    1. Add close entry. EntryCode: NormalCloseMessage; Timestamp
    2. Delete all data (Af, Kf)
    3. Close the file 
 */
void closeLog() {
    // 1. Add close entry. EntryCode: NormalCloseMessage; Timestamp
    /* 
        Below code to get the time copied from:
        http://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
     */
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

    //tmbuf
    //char* finalEntry = malloc((19+strlen(tmbuf))*sizeof(finalEntry));
   
    char finalEntry[256+strlen(tmbuf)];

    strcat(finalEntry, "EntryCode:NormalCloseMessage");
    strcat(finalEntry, "\nTime:");
    strcat(finalEntry, tmbuf);

    //printf("%s\n", finalEntry);
    addCloseEntry(finalEntry);

    // 2. Delete all data (Af, Kf)
    memset(realKey, 0, 256*sizeof(realKey) - 1); 
    free(realKey);

    freeSessionKey();

    //resetLogAndEntry();

    // 3. Close the file 
    closeLogfp();
}

