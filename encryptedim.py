###########################################################################
# CS114 HW1 Pt2
# Encrypted Instant Messenger
# Ella (Yixin) Guo (yguo10)
#
# This program reads from standard input and sends input messages to another
# instance of the program running on a different machine; received messages
# are sent to standard output.
# 
# edited for pt2: Add the encryption layer using CBC mode so that no people
# in the middle can read the text. The encryption also provides authenticity
# by using MAC.
###########################################################################

# included libraries
import sys
import socket
import select
import argparse
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# constants
BLOCK_SIZE = AES.block_size

def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--s",       action="store_true")
    parser.add_argument("--c",       action="store")
    parser.add_argument("--confkey", action="store")
    parser.add_argument("--authkey", action="store")
    args = parser.parse_args()

    # make the keys 32 bytes long
    confkey = SHA256.new(args.confkey.encode()).digest()
    authkey = SHA256.new(args.authkey.encode()).digest()

    # call the corresponding function
    if args.s:
        server('localhost', 9999, confkey, authkey)
    elif args.c:
        client(args.c, 9999, confkey, authkey)
    

# server
def server(host, port, confkey, authkey):
    # create a server socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((host, port)) 
    serverSocket.listen(1)

    # get the connection socket
    connection, address = serverSocket.accept()
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # start messaging 
    Message(connection, confkey, authkey)

    # close the sockets
    serverSocket.close()
    connection.close()

# client
def client(host, port, confkey, authkey):
    # create a client socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.connect((host, port))

    # start messaging 
    Message(clientSocket, confkey, authkey)

    # close the socket
    clientSocket.close()

# Message
def Message(clientSocket, confkey, authkey):
    socket_list = [sys.stdin, clientSocket]
    try:
        # keep executing until reached ctrl c / EOF
        while True:
            # Get the list sockets which are readable
            readSockets, writeSockets, errorSockets = select.select(socket_list, 
                                                                    [], [])
            for sock in readSockets:

                # incoming message from remote server
                if sock == clientSocket:
                    # unpack the received message
                    decrypt_msg = unpack(clientSocket, confkey, authkey)

                    # print the message decrypted
                    sys.stdout.write(decrypt_msg.decode())
                    sys.stdout.flush()
                else:
                    # send the message
                    message = sys.stdin.readline()
                    concat_msg = encrypt_then_MAC(message, confkey, authkey)
                    clientSocket.send(concat_msg)
    except KeyboardInterrupt:
        return 

# encryption using CBC mode and then MAC
def encrypt_then_MAC(message, confkey, authkey):
    # random generated initialization vector
    iv = get_random_bytes(BLOCK_SIZE)

    # create the cipher based on confkey and iv
    cipher = AES.new(confkey, AES.MODE_CBC, iv)

    # encrypt the message length
    msg_len = len(message).to_bytes(BLOCK_SIZE, 'big')
    padded_len = pad(msg_len, BLOCK_SIZE)
    cipher_len = cipher.encrypt(padded_len)
    
    # encrypt the message
    padded_msg = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_msg)

    # MAC iv and cipherlen
    hmac1 = HMAC.new(authkey, digestmod=SHA256)
    len_tag = hmac1.update(iv + cipher_len).digest()

    # MAC the ciphetext
    hmac2 = HMAC.new(authkey, digestmod=SHA256)
    msg_tag = hmac2.update(ciphertext).digest()
    concat_msg = iv + cipher_len + len_tag + ciphertext + msg_tag

    return concat_msg

# unpack function unpacks the concat_msg into different components and return
# the plaintext
def unpack(socket, confkey, authkey):
    data = socket.recv(4096)

    # get the iv
    iv = data[0 : BLOCK_SIZE]

    # get the encrypted len
    cipher_len = data[BLOCK_SIZE : 3 * BLOCK_SIZE]

    # get the MACed (iv + cipher_len) to verify authentication
    len_tag = data[3 * BLOCK_SIZE : 5 * BLOCK_SIZE]

    # get the real message length and the cipher
    msg_len, cipher = verify_then_decrypt(iv, cipher_len, len_tag, confkey, 
                                          authkey, socket)
    msg_len = int.from_bytes(msg_len, "big")

    # the calculation to find encrypted msg length on byte array
    encrypted_msg_len = (int(msg_len / BLOCK_SIZE) + 1) * BLOCK_SIZE

    # get the ciphertext
    ciphertext = data[5 * BLOCK_SIZE : 5 * BLOCK_SIZE + encrypted_msg_len]

    # decrypt the ciphertext
    message = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    return message


# This function verifies if the authkeys that the client and server provided
# are the same. If yes, it then decrypts the the length of the message.
def verify_then_decrypt(iv, cipher_len, len_tag, confkey, authkey, socket):
    # verify HMAC
    try:
        hmac = HMAC.new(authkey, digestmod=SHA256)
        len_tag = hmac.update(iv + cipher_len).verify(len_tag)

    except ValueError:
        sys.stdout.write("ERROR: HMAC verification failed")
        sys.stdout.flush()
        sys.exit(1)
        socket.close()

    # decrypt to get the message length
    cipher = AES.new(confkey, AES.MODE_CBC, iv)
    msg_len = unpad(cipher.decrypt(cipher_len), BLOCK_SIZE)

    return msg_len, cipher

# calling main
if __name__ == "__main__":
    main()
