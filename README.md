# P2P instant messenger

`unencryptedim.py` is a simple unencrypted instant messenger. The program reads from standard input and sends input messages to another instance of the
program running on a different machine; received messages are sent to standard output. This is an intro to network programming and use of python sockets.<br />
The program reads from standard input and send all input data to the other instance of application (running on the other host), via TCP/IP over port 9999.
Unencrypted.py supports the following command line argument options:<br />
<space>python unencryptedim.py --s|--c hostname

# Added the encryption layer
Extended the previou program with encryption -> `encryptedim.py`<br />
The program encrypts messages using AES-256 in CBC mode, and uses HMAC with SHA256 for message authentication. IVs are generated randomly, and the scheme
the program used is the encrypt-then-MAC scheme.<br />
Updated new command line argument options:<br />
<space>python encryptedim.py [--s|--c hostname] [--confkey K1] [--authkey K2]<br /><br />

The sending protocal has the following form:<br />
iv + Ek1(len(m)) + HMACk2(iv + Ek1(len(m))) + Ek1(m) + HMACk2(Ek1(m))
