# Creates the main file and the test
all: run_me test

# Make the main file
run_me: main.o untrustedLogger.o
	gcc main.o untrustedLogger.o -o run_me -lssl -lcrypto

# Make the test file
test: test.o untrustedLogger.o 
	gcc test.o untrustedLogger.o -o test -lssl -lcrypto


main.o: main.c
	gcc -c main.c

untrustedLogger.o: untrustedLogger.c
	gcc -c untrustedLogger.c -lssl -lcrypto

# Clean everything
clean: 
	rm testLog *.o run_me test

# Clean the tests
cleantest:
	rm testLog test.o test

# Clean only the main files
cleanmain: 
	rm *.o run_me