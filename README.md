To test this program, execute the "make clean" then "make test4" command in the terminal. 

This will send five messages using the Needham-Schroeder Key-Exchange protocol and demonstrates how each the two user processes (Amal and Basim) authenticates both eachother and the KDC through their keys, nonces, and tickets. This specific scenario has pre-defined keys and nonces such that the three process pipes can compare their logs with the expected outputs of each process to ensure correctness of the protocol. 

This project utilizes the cryptographic functions created in my EncrDecr repository. 
