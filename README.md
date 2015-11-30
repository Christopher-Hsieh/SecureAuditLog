# SecureAuditLog

This is our Secure Audit Log

Project Owners: Christopher Hsieh & Samuel Presnal

Steps to run the project
--------------------------------------------
1. Run the file gen_keys.sh by typing "./gen_keys.sh"
2. Run the make file by typing "make"
3. Run the program by typing "./run_me"


Notes & Special Conditions
--------------------------------------------
Our project was not completely finished. You are able to run all of the commands except "verifyall". The commands that work everytime are: "createlog file_name", "add message_string", "exit". "verify entry_no" works only some of the time, this is due to mismatches in our keys and memory leaks which cause erroneous behaviour in our code.