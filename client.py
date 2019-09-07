import requests
import socket
import struct
import ssl
import json
from threading import Event
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import threading
import base64
import bcrypt
import random
import hashlib
import gnupg
import os

POLL_INTERVAL = 1000  # time between check-ins at the tracker
SERVER = "localhost"  # testing tracker server, can't really do other trackers with 
MSG_HASH_SIZE = 40  # Bytes
P2P_PORT_NUMBER = 8081  # port for 

message_dispatch_event = Event()
queued_message_ids = []
messages_list = dict()

def PrepareGPG():
    if not os.path.exists("./keys_client/"):
        os.makedirs("./keys_client/")

    gpg = gnupg.GPG(gnupghome="./keys_client/")
    keys = gpg.list_keys(True)
    if not len(keys):
        print("No keys! Generating new ones...")
        new_key = gpg.gen_key(gpg.gen_key_input(key_type="RSA", key_length=2048, name_email="anon@nowhere"))
        gpg.export_keys(new_key.fingerprint, True)
        client_private_key = gpg.list_keys(True)[0]
    else:
        client_private_key = keys[0]

    print("Signing key fingerprint:", client_private_key["fingerprint"], "\nLength:", len(client_private_key["fingerprint"]))

ssl_context = ssl.create_default_context()  # Initalize the ssl wrapper to attach to the sock
ssl_context.load_verify_locations('server.pem')  # Load the server cert bundle, TODO: proper PKI

print("Hello world!")

def BcryptToBytes(bcrypt_string: str):
    bcrypt_string = str(bcrypt_string)
    _, __, cost, hash = bcrypt_string.split("$")
    if not 0 < int(cost) < 256:
        raise ValueError("0 < cost < 256")
    return bytes([int(cost)]) + base64.b64decode(hash.replace('.','+').replace('/','='))

def BytesToBcrypt(bcrypt_bytes: bytes):
    """I have no idea why indexing bytes gives an int but okay"""
    cost = str(bcrypt_bytes[0])
    bcrypt_string = base64.b64encode(bytearray(bcrypt_bytes)[1:]).decode()
    return "$2b$" + cost + "$" + bcrypt_string

class TrackerHandler(BaseHTTPRequestHandler): # Handle requests from other peers
    global messages_list
    def handle_http(self, status_code, path):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/x-citizenhacks') # Hey, custom MIME type!
        self.end_headers()
        content = messages_list[self.rfile.read(int(self.headers['Content-Length'])).hex()]
        return bytes(content, 'UTF-8')
    
    def do_GET(self):
        response = self.handle_http(200, self.path)
        self.wfile.write(response)


def RegisterMessage(secure_sock: ssl.SSLSocket, message_id: str):
    message_id = str(message_id)
    secure_sock.send(b"3" + BcryptToBytes(message_id)) # Command ID 3
    if secure_sock.recv(1).hex() == 0x0:
        raise ValueError


def QueryMessage(secure_sock: ssl.SSLSocket, message_id: str, buffer_size=1048576):
    message_id = str(message_id)
    secure_sock.send(b"2" + BcryptToBytes(message_id)) # Command ID 2
    return list(map(socket.inet_ntoa, re.findall('....', secure_sock.recv(buffer_size).hex())))


def GetMessages(secure_sock: ssl.SSLSocket, buffer_size=1048576, hash_size=MSG_HASH_SIZE):
    secure_sock.send(b"1") # Command ID 1
    return re.findall('.'*hash_size, secure_sock.recv(buffer_size).hex())


def CreateSocket(server = SERVER, port=8080):
    try:
        connection_sock = socket.create_connection((server, port))
        return ssl_context.wrap_socket(connection_sock, server_hostname=server)
    except ConnectionRefusedError:
        print(f"Connection refused by {server}")

def GenerateID(message: str):
    message = message
    return bcrypt.hashpw(hashlib.sha256(bytes(message, 'utf-8')).digest(), bcrypt.gensalt())


def SignMessage(message: str):
    message = message
    return str(gpg.sign(message, keyid = client_private_key["fingerprint"]))


def QueueMessage(message: str):
    message = str(message)
    global messages_list
    signed_message, msg_id = SignMessage(message)
    messages_list[msg_id] = signed_message
    queued_message_ids += msg_id
    client.message_dispatch_event.set()


def main():
    global messages_list
    try:
        secure_sock = CreateSocket()
        temp = GetMessages(secure_sock)
        print(temp)
        messages_list = {msg_id: "" for msg_id in temp}
        print(f"messages_list: {messages_list}")
        #secure_sock.close()
        #print(messages_list)
        while True:
            if message_dispatch_event.is_set():
                RegisterMessage(SignMessage("message")[1])
                message_dispatch_event.clear()
            upd_messages = GetMessages(secure_sock)
            #print(f"upd_messages: {upd_messages}")
            new_messages_ids = list(set(upd_messages) ^ set(messages_list.keys()))
            print(f"new_messages_ids: {new_messages_ids}")
            for message_id in new_messages_ids:
                peer_list = QueryMessage(secure_sock, message_id)
                chosen_peer = random.choice(peer_list)
                print("Hash verifying")
                message_content = requests.get(chosen_peer, data=message_id).content
                while not bcrypt.checkpw(hashlib.sha256(message_content).digest(), message_id):
                    chosen_peer = random.choice(peer_list)
                    print("Hash verifying")
                    # message_content = requests.get(chosen_peer, data=message_id).text
                    
                messages_list[message_id] = message_content
            message_dispatch_event.wait(POLL_INTERVAL)
    except KeyboardInterrupt:
        return

if __name__ == '__main__' and False:
    httpd = HTTPServer((SERVER, P2P_PORT_NUMBER), TrackerHandler)
    http_thread = threading.Thread(target=httpd.serve_forever)
    http_thread.start()
    main()
    http_thread
