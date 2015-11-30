#ifndef PROTOTYPES_H
#define PROTOTYPES_H

// FUNCTIONS ONLY PARTIALLY ORGANIZED

void createLog(char[]);
char* getCertificate(char*);
char* createKey(int);
char* publicKeyEncrypt(char*, char*);
char* publicKeyDecrypt(RSA*, char*);
RSA* createRSA(unsigned char*);
char* fileToBuffer(FILE*);
void verifyLog(int, char*, char*);
char* hash(char*);
char* hashTogether(char*, char*);
void response(int, char*, char*);
char* getLogName(void);
void addMessage(char[]);
char* getCertificate(char*);

/* main.c */
int getLogId(void);
char* getUHash(void);

/* helper.c */
char* encrypt(char*);
char* decrypt(char*);
void setKey(char*);
void initRealKey();
void closeLog();
void freeRealKey();

int getCurrEntry();
void incLogNum();
int getLogNum();

/* untrustedLogger.c */
void freeSessionKey();
void closeLogfp();
char* getFileName();

/* verifier.c */
void verifyAll(char*, char*);

#endif