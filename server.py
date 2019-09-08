import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import ssl
from collections import OrderedDict
import threading
from certauth.certauth import *
import threading

HOST_NAME = "0.0.0.0" 
PORT_NUMBER = 8080
REG_PORT = 8083
print("Hello world!")

messages = OrderedDict()
messages.__setitem__("A"*60, ["1.1.1.1"]) # This is such a big hack



context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)   # Inititalize encryption system
#context.load_cert_chain('server.pem', 'server.key') # Set up public and private keys (self signed here, TODO actual PKI infrasturcture)

ca = CertificateAuthority('Hacky Hack Hack', 'server.pem', cert_cache='./')
filename = ca.cert_for_host(socket.gethostbyname(socket.gethostname()))
context.load_cert_chain(filename)

'''def BcryptToBytes(bcrypt_string: str):
    bcrypt_string = base64.b64decode(str(bcrypt_string) + '=' * (-len(s) % 4))
    _, __, cost, hash = bcrypt_string.split("$")
    if not 0 < int(cost) < 256:
        raise ValueError("0 < cost < 256")
    return bytes([int(cost)]) + base64.b64decode(hash.replace('.','+').replace('/','='))

def BytesToBcrypt(bcrypt_bytes: bytes):
    """I have no idea why indexing bytes gives an int but okay"""
    cost = str(bcrypt_bytes[0])
    bcrypt_string = base64.b64encode(bytearray(bcrypt_bytes)[1:]).decode()
    return "$2b$" + cost + "$" + bcrypt_string'''


def CommandHandler(command: str, sender_ip):
    """Handles the command, NOT including magic number"""
    global messages
    if command:
        if command[0] == '2': # Query message command
            messages[command[1:]].append(sender_ip)
            temp2 = ",".join(messages[command[1:]])
            print(type(temp2))
            
            return bytes(temp2, "utf-8")
        elif command[0] == '1': # Get message command
            return bytes("".join(messages.keys()), "utf-8")
        else:
            raise NotImplemented(command[0])
    else:
        return

def RegisterConn(conn, addr):
    print("Registered {addr} to 8083!")
    while True:
        conn.send(HandleRegister(conn.recv(1024).decode(), addr[0]))
        print(f"Registered a message from {addr}!")
        

def HandleRegister(message_id, sender_ip):
    global messages
    messages.__setitem__(message_id, [sender_ip])
    return b"1"

def RegisterMessages():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:  
        sock.bind((HOST_NAME, REG_PORT)) # Set up listening for socket
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            try:
                while True:
                    conn, addr = ssock.accept()
                    print(f"8083: Conn {addr}")
                    threading.Thread(target=RegisterConn, args=(conn,addr,)).start()
            except KeyboardInterrupt:
                pass 

threading.Thread(target=RegisterMessages).start()

def HandleNewConn(conn, addr):
     print(f"New conn! {addr}")
     while True:
         temp = conn.recv(1024).decode()
         print(f"Received {temp} from {addr}")
         temp1 = CommandHandler(temp, addr[0])
         print(temp1)
         conn.send(temp1)
         print(f"New packet from {addr}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:  
    sock.bind((HOST_NAME, PORT_NUMBER)) # Set up listening for socket
    sock.listen(5)  # Limit num. of connections simultaneously possible?
    with context.wrap_socket(sock, server_side=True) as ssock:
        try:
            while True:
                conn, addr = ssock.accept()
                print(f"Accepted {addr}")
                threading.Thread(target=HandleNewConn, args=(conn,addr,)).start()
                    
        except KeyboardInterrupt:
            pass
