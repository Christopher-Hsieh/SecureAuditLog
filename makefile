run_me: main.o untrustedLogger.o
	gcc main.o untrustedLogger.o -o run_me

main.o: main.c
	gcc -c main.c

untrustedLogger.o: untrustedLogger.c
	gcc -c untrustedLogger.c



clean: 
	rm *.o run_me