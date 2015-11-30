# Creates the main file and the test
all: run_me test

# Make the main file
run_me: main.o untrustedLogger.o trusted.o verifier.o helper.o memManager.o
	gcc main.o untrustedLogger.o trusted.o verifier.o helper.o memManager.o -o run_me -lssl -lcrypto

# Make the test file
test: test.o untrustedLogger.o trusted.o verifier.o helper.o memManager.o
	gcc test.o untrustedLogger.o trusted.o verifier.o helper.o memManager.o -o test -lssl -lcrypto

main.o: main.c
	gcc -g -c main.c

untrustedLogger.o: untrustedLogger.c
	gcc -g -c untrustedLogger.c -lssl -lcrypto

trusted.o: trusted.c
	gcc -g -c trusted.c -lssl -lcrypto

verifier.o: verifier.c
	gcc -g -c -w verifier.c -lssl -lcrypto

helper.o: helper.c
	gcc -g -c helper.c -lssl -lcrypto

memManager.o: memManager.c
	gcc -g -c memManager.c

# Clean everything
clean: 
	rm testLog *.o run_me test

# Clean the tests
cleantest:
	rm testLog test.o test

# Clean only the main files
cleanmain: 
	rm *.o run_me