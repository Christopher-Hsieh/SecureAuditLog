#ifndef PROTOTYPES
#define PROTOTYPES

void createLog(char[]);
char *getCertificate(char*);
char *createKey(int);
char *encrypt(char*, char*);
char* publicKeyEncrypt(char*, char*);
char* publicKeyDecrypt(RSA*, char*);
RSA* createRSA(unsigned char*);
char *decrypt(char*, char*);
char * fileToBuffer(FILE*);
char* verifyLog(char*, char*, char*);

#endif