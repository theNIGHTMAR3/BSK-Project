# BSK-Project
Project from BSK (Security of Computer Systems)

## This project is currently in development. Some features and solutions may change in future!!!

The goal of this project is to create a Client-Server application allowing one to encrypt various files and send them to other running instance. Encryption and decryption must be handled by RSA public-private key system. After receiving the file it can be decrypted after providing the correct password. The application need to have a secure chat where users can communicate with each other.


### Starting the application
To run this application 2, instances must be started. It is recommended to use IDE in deploying the application. 
1. To start the Server, run the program with this launch parameter: -s SERVER
2. To start the Client, run the program with this launch parameter: -c CLIENT

#### Current features:
- CLient-Server socket connection
- Implementation of CBC and CFB algorithms
- Encrypting and decrypting various files
- RSA keys generation
- Decryption protected by a password set during the generation of keys
- Sending and receiving files
- Progress bar for sending files

#### TODO:
- Secure chat implementation
- Full progress bar functionality
- Significant  GUI improvements
- Improved bidirectional communication
- Disconnection handling
