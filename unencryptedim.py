###########################################################################
# CS114 HW1 Pt1
# Unencrypted Instant Messenger
# Ella (Yixin) Guo (yguo10)
#
# This program reads from standard input and sends input messages to another
# instance of the program running on a different machine; received messages
# are sent to standard output.
###########################################################################

# included libraries
import sys
import socket
import select
import argparse

# server
def server(host, port):
    # create a server socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((host, port)) 
    serverSocket.listen(1)

    # get the connection socket
    connection, address = serverSocket.accept()
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # start messaging 
    message(connection)

    # close the sockets
    serverSocket.close()
    connection.close()

# client
def client(host, port):
    # create a client socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.connect((host, port))

    # start messaging 
    message(clientSocket)

    # close the socket
    clientSocket.close()

# message
def message(clientSocket):
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
                    # print the message received
                    message = clientSocket.recv(1024)
                    sys.stdout.write(message.decode())
                    sys.stdout.flush()
                else:
                    # send the message
                    message = sys.stdin.readline()
                    clientSocket.send(message.encode())
    except KeyboardInterrupt:
        return 

# parse the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--s", action="store_true")
parser.add_argument("--c", action="store")
args = parser.parse_args()

# call the corresponding function
if args.s:
    server('localhost', 9999)
elif args.c:
    client(args.c, 9999)

