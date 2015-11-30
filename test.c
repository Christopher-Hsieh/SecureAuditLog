#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main (int argc, char *argv[]) {
	initRealKey();
	createLog("testLog");

	closeLog();

	verifyEntryNum(0);
 }