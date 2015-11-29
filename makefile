# Creates the main file and the test
all: run_me test

# Make the main file
run_me: main.o untrustedLogger.o trusted.o verifier.o helper.o
	gcc main.o untrustedLogger.o trusted.o verifier.o helper.o -o run_me -lssl -lcrypto

# Make the test file
test: test.o untrustedLogger.o trusted.o verifier.o helper.o
	gcc test.o untrustedLogger.o trusted.o verifier.o helper.o -o test -lssl -lcrypto


main.o: main.c
	gcc -c main.c

untrustedLogger.o: untrustedLogger.c
	gcc -c untrustedLogger.c -lssl -lcrypto

trusted.o: trusted.c
	gcc -c trusted.c -lssl -lcrypto

verifier.o: verifier.c
	gcc -c verifier.c -lssl -lcrypto

helper.o: helper.c
	gcc -c helper.c -lssl -lcrypto

# Clean everything
clean: 
	rm testLog *.o run_me test

# Clean the tests
cleantest:
	rm testLog test.o test

# Clean only the main files
cleanmain: 
	rm *.o run_me