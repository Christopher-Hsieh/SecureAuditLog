#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// untrustedLogger.c
// This file basically acts as "U", otherwise known as Untrusted Machine/Logger

/*
 * The logger creates and opens a new log file with the specified name. The logger
 * should create a file with the given name in the current directory. According to
 * the protocol, this operation should add a log entry about the creation of the log
 * file
 */
void createLog(char fileName[]) {
	// Create new file with specified name
	FILE *fp;
	fp = fopen(fileName, "w+");

	//fputs(char *s, FILE *fp);


	/* Add log entry about the creation
	 * To create the first log entry we must form a new:
	 *	1. Ko - Random session key.
	 *  (Skip time stamps)
	 *	2. IDlog - Unique identifier for this logfile.
	 *	3. Cu - U's certificate from T.
	 *	4. Ao - Random starting point.
	 *	5. Xo - Cu, Ao.
	 * 	
	 * We will send to T:
	 *	1. Mo - Message with IDu, PKEpkT(Ko), Eko(Xo, SIGNsku(Xo))
	 */

}