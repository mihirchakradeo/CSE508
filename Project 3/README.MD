CSE508: Network Security, Fall 2017
SBU ID: 111462188
Homework 3: Plugboard Proxy
-------------------------------------------------------------------------------
In this assignment I developed a plugboard proxy which adds an extra layer of protection
to publicly accessible network services.

How it works:

- Client sends encrypted data to the plugboard proxy
- pbproxy decrypts the data with a shared key
- Then pbproxy forwards the data to the target service eg, SSH
- SSH sends back a response, which is encrypted by the pbproxy server and sends it back to the client

If the client does not have the shared key, then after decryption the data which is sent to the target
service is garbage. Attackers who might want to exploit a zero day vulnerability in the protected
service will first have to know the secret key for having a chance to successfully deliver their attack
vector to the server.

Libraries used:
  1. OpenSSL - Encryption/Decryption (AES 128 CTR Mode)
  2. pthread - threading to support multiple clients


Test Environment:
- Ubuntu 16.04.3 LTS, Linux 4.10.0-37-generic x86_64
- gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.5)

Execution commands:
  Server:
    $make
    $./pbproxy -l 2222 -k myKey localhost 22

  Client:
    $make
    $ssh -o "ProxyCommand ./pbproxy -k myKey localhost 2222" localhost

Design Description:
I made use of threads at client and server as follows:
  Client:
    Read Thread: For reading the data sent by pbproxy server
    Write Thread: For encrypting data and sending to pbproxy

  Server:
    Read Thread: For reading the data sent by service (SSH), encrypting it and writing it to client
    Write Thread: For decrypting data received from client and sending to service (SSH)

Test:
I tested with multiple clients, worked properly.
Also tried connecting to device not on localhost - used sshdroid to set up ssh server on android, and tested on that

Sample output:
--------------------------------------------------------------------------------------------
USE CASE: SSH
  SERVER SIDE:
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ makegcc pbproxy.c -o pbproxy -lssl -lcrypto -lpthread
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ ./pbproxy -l 2222 -k myKey localhost 22

  CLIENT SIDE:
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ ssh -o "ProxyCommand ./pbproxy -k myKey localhost 2222" localhost
    Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.10.0-37-generic x86_64)

     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage

    50 packages can be updated.
    1 update is a security update.

    *** System restart required ***
    Last login: Fri Nov 10 21:58:48 2017 from 127.0.0.1
    mihir@mihir-Inspiron-15-7000-Gaming:~$ ls
    Android                Downloads         Pictures         universe
    AndroidStudioProjects  examples.desktop  Public           Videos
    Desktop                IdeaProjects      PycharmProjects
    Documents              Music             Templates
    mihir@mihir-Inspiron-15-7000-Gaming:~$ exit
    logout
    Connection to localhost closed.
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$

--------------------------------------------------------------------------------------------
USE CASE: Echo Server
  PBPROXY SERVER SIDE:
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ ./pbproxy -l 2221 -k myKey localhost 5555

  CLIENT SIDE:
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ ./pbproxy -k myKey localhost 2221
    test
    test
    echo server
    echo server

  ECHO SERVER SIDE:
    mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW3$ nc -l localhost -p 5555 -c "/bin/cat"


References:
https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
https://stackoverflow.com/questions/174531/easiest-way-to-get-files-contents-in-c
http://www.geeksforgeeks.org/socket-programming-cc/
http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
