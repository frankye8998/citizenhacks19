import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import ssl
from collections import OrderedDict
import threading
import certauth
from certauth.certauth import *

HOST_NAME = "0.0.0.0" 
PORT_NUMBER = 8080
REG_PORT = 8083
print("Hello world!")

messages = OrderedDict()
#messages.__setitem__("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["1.1.1.1"])
#messages["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].append("2.2.2.2")
#messages.__setitem__("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", [])
#messages["BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"].append("3.3.3.3")
#messages["BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"].append("4.4.4.4")



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


def CommandHandler(command: str, send):
    """Handles the command, NOT including magic number"""
    global messages
    command = str(command)
    if command:
        if command[0] == '2': # Query message command
            messages[command[1:]].append(sender_ip)
            return "".join(map(socket.inet_aton, messages[command[1:]]))
        elif command[0] == '1': # Get message command
            return bytes.fromhex("".join(messages.keys()))
        else:
            raise NotImplemented(command[0])
    else:
        return

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
                conn, addr = ssock.accept()
                print(conn, addr)
                while True:
                    temp = conn.recv(1024)
                    print(temp)
                    conn.send(HandleRegister(temp.decode(), addr[0]))
            except KeyboardInterrupt:
                pass 

threading.Thread(target=RegisterMessages).start()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:  
    sock.bind((HOST_NAME, PORT_NUMBER)) # Set up listening for socket
    sock.listen(5)  # Limit num. of connections simultaneously possible?
    with context.wrap_socket(sock, server_side=True) as ssock:
        try:
            conn, addr = ssock.accept()
            print(conn, addr)
            while True:
                conn.send(CommandHandler(conn.recv(1024).decode(), addr[0]))
        except KeyboardInterrupt:
            pass
