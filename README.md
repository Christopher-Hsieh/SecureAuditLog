# SecureAuditLog

This is our Secure Audit Log

Current Status:
For some reason the function prototypes in prototypes.h are not being recognized.
The make says that it is attempting to convert an int into a string.

Something to note is that K0 needs to be a random generated session key of length 16
to match the length of the RSA key (16). Before we were trying to use the private key
which was length 201 resulting in the error.