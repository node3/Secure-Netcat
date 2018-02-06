## Overview of the application

Secure netcat is a simple python 2.7 implementation of netcat with added benefit of confidentiality and integrity.
The application can be used as secure tool for file sharing or messaging over the terminal.
Some of the highlights of the implementation include:

1. Communication between client and server occurs using TCP sockets. The input can be piped-in to the client and the output can be piped-out at server.
2. Messages are encrypted using AES-256 encryption for confidentiality and HMAC for integrity using the Pycryptodome library (version 3.4.7). Galois/Counter Mode (GCM) is used to combine encryption and MAC into the construction itself.
3. Two way pipe between client and server implemented using select statement. This means that once the client is connected to the server, any input to STDIN of server will be securely transmitted to client's STDOUT and input to client's STDIN will go to STDOUT of the server.
4. Message objects are serialised before encapsulating into transport layer datagram using pickle library.

## How to Run
#### File sharing mode
Start the application on client and server as follows.
###### Client
```
python secure_netcat.py --key <KeyForAESEncrpytion> <Server IP> <Server port> < <Input File>
```
###### Server
```
python secure_netcat.py --key <KeyForAESEncrpytion> -l <Server Port> > <Output File>
```

#### Messaging mode
Start the application with following commands. Type in the messages and hit Ctrl+C to exit.
###### Client
```
python secure_netcat.py --key <KeyForAESEncrpytion> <Server IP> <Server port>
```
###### Server
```
python secure_netcat.py --key <KeyForAESEncrpytion> -l <Server Port>
```
