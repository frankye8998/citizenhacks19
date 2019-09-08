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
import time

POLL_INTERVAL = 1000  # time between check-ins at the tracker
SERVER = "192.168.49.127"  # testing tracker server, can't really do other trackers with 
MSG_HASH_SIZE = 60  # Bytes
P2P_PORT_NUMBER = 8081  # port for 

message_dispatch_event = Event()
queued_message_ids = []
messages_list = dict()

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

# HACKY HACK HACK
ssl_context = ssl.create_default_context()  # Initalize the ssl wrapper to attach to the sock
ssl_context.load_verify_locations('server.pem')  # Load the server cert bundle, TODO: proper PKI

#TODO FIX
#ssl_context.load_cert_chain('server.pem', 'server.key')

print("Hello world!")

def BcryptToBytes(bcrypt_string: str):
    '''
    bcrypt_string = str(bcrypt_string)
    _, __, cost, hash = bcrypt_string.split("$")
    if not 0 < int(cost) < 256:
        raise ValueError("0 < cost < 256")
    return bytes([int(cost)]) + base64.b64decode(hash.replace('.','+').replace('/','=') + '=' * (-len(hash.replace('.','+').replace('/','=')) % 4))
    '''
    return bcrypt_string

def BytesToBcrypt(bcrypt_bytes: bytes):
    '''
    """I have no idea why indexing bytes gives an int but okay"""
    cost = str(bcrypt_bytes[0])
    bcrypt_string = base64.b64encode(bytearray(bcrypt_bytes)[1:]).decode()
    return "$2b$" + cost + "$" + bcrypt_string
    '''
    return bcrypt_bytes

class TrackerHandler(BaseHTTPRequestHandler): # Handle requests from other peers
    global messages_list
    def handle_http(self, status_code, path):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/x-citizenhacks') # Hey, custom MIME type!
        self.end_headers()
        message_id = self.rfile.read(int(self.headers['Content-Length']))
        content = json.dumps({"message": messages_list[message_id]["message_content"], "message_id": message_id.decode(), "signature": messages_list[message_id]["signature"], "protocol_version": "1", "fingerprint": messages_list[message_id]["fingerprint"]})
        return bytes(content, 'UTF-8')
    
    def do_GET(self):
        response = self.handle_http(200, self.path)
        self.wfile.write(response)


httpd = HTTPServer(("0.0.0.0", P2P_PORT_NUMBER), TrackerHandler)
httpd.socket = ssl.wrap_socket (httpd.socket,
    keyfile="server.key",
    certfile='server.pem',
    server_side=True)
http_thread = threading.Thread(target=httpd.serve_forever)
http_thread.start()

def RegisterMessage(secure_sock: ssl.SSLSocket, message_id: bytes):
    #message_id = str(message_id)
    secure_sock.send(message_id) # Command ID 3 but not w/ "3"
    #if secure_sock.recv(1).hex() == 0x0: # TODO Implement on the server side
    #    raise ValueError


def QueryMessage(secure_sock: ssl.SSLSocket, message_id: str, buffer_size=1048576):
    message_id = str(message_id)
    secure_sock.send(b"2" + bytes(message_id, "utf-8")) # Command ID 2
    return secure_sock.recv(buffer_size).decode().split(",")


def GetMessages(secure_sock: ssl.SSLSocket, buffer_size=1048576, hash_size=MSG_HASH_SIZE):
    print("Getting messages")
    secure_sock.send(b"1") # Command ID 1
    return re.findall('.'*hash_size, secure_sock.recv(buffer_size).decode())


def CreateSocket(server = SERVER, port=8080):
    try:
        connection_sock = socket.create_connection((server, port))
        return ssl_context.wrap_socket(connection_sock, server_hostname=server)
    except ConnectionRefusedError:
        print(f"Connection refused by {server}")


def GenerateID(message: str, signature: str):
    temp = bcrypt.hashpw(hashlib.sha256(bytes(message + signature, 'utf-8')).digest(), bcrypt.gensalt())
    print(temp)
    return temp    
    

def SignMessage(message: str):
    return str(gpg.sign(message, keyid = client_private_key["fingerprint"]))

'''
def QueueMessage(message: str):
    message = str(message)
    global messages_list
    signed_message, msg_id = SignMessage(message)
    messages_list[msg_id] = signed_message
    queued_message_ids += msg_id
    client.message_dispatch_event.set()
'''


def main():
    global messages_list
    try:
        secure_sock = CreateSocket()
        temp = GetMessages(secure_sock)
        print(temp)
        messages_list = {msg_id: dict() for msg_id in temp}
        print(f"messages_list: {messages_list}")
        #secure_sock.close()
        #print(messages_list)
        while True:
            #if message_dispatch_event.is_set():
            #    RegisterMessage(SignMessage("message")[1])
            #    message_dispatch_event.clear()
            upd_messages = GetMessages(secure_sock)
            #print(f"upd_messages: {upd_messages}")
            new_messages_ids = list(set(upd_messages) ^ set(messages_list.keys()))
            print(f"new_messages_ids: {new_messages_ids}")
            for message_id in new_messages_ids:
                peer_list = QueryMessage(secure_sock, message_id)
                chosen_peer = random.choice(peer_list)
                print("Hash verifying")
                message_json = requests.get(f"{chosen_peer}:8081", data=message_id).json() # XXX USE FORMATTING HERE
                while not bcrypt.checkpw(hashlib.sha256(bytes(message_json["message"] + message_json["signature"])).digest(), message_id):
                    chosen_peer = random.choice(peer_list)
                    print("Hash verifying")
                    
                messages_list[message_id] = {"message_content": message_json["message"], "pub_key": message_json['pub_key'], "signature": message_json['signature']}
            time.sleep(POLL_INTERVAL/1000)
    except KeyboardInterrupt:
        return

if __name__ == '__main__':
    print("Running client.py")
    #main()
