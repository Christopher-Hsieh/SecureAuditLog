# Creates the main file and the test
all: run_me test

# Make the main file
run_me: main.o untrustedLogger.o
	gcc main.o untrustedLogger.o -o run_me

# Make the test file
test: test.o untrustedLogger.o
	gcc test.o untrustedLogger.o -o test


main.o: main.c
	gcc -c main.c

untrustedLogger.o: untrustedLogger.c
	gcc -c untrustedLogger.c

# Clean everything
clean: 
	rm testLog *.o run_me test

# Clean the tests
cleantest:
	rm testLog test.o test

# Clean only the main files
cleanmain: 
	rm *.o run_me