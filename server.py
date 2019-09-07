import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import ssl

HOST_NAME = "127.0.0.1" 
PORT_NUMBER = 8080
print("Hello world!")

peer_list = set()
peer_list.add('test.test.test.test')    

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)   # Inititalize encryption system
context.load_cert_chain('server.pem', 'server.key') # Set up public and private keys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:  
    sock.bind((HOST_NAME, PORT_NUMBER)) # Set up listening for socket
    sock.listen(5)  # Limit num. of connections simultaneously possible?
    with context.wrap_socket(sock, server_side=True) as ssock:
        for i in range(5): 
            conn, addr = ssock.accept() # Begin listening for sender and msg?
            print(conn, addr) 
            print(conn.recv(1024).decode())


    
    