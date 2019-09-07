import requests
import socket
import struct
import ssl
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket

POLL_INTERVAL = 1000
SERVER = "localhost"

#HOST_NAME = "127.0.0.1"
P2P_PORT_NUMBER = 8081
print("Hello world!")

MAGIC_NUMBER_CLIENT = b"FRANK GAY"
MAGIC_NUMBER_SERVER = b"SEAN. GAY"


peer_list = set()
peer_list.add('test.test.test.test')

ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations('server.pem')

class TrackerHandler(BaseHTTPRequestHandler):
    def handle_http(self, status_code, path):
        global peer_list
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        content = ','.join(peer_list)
        return bytes(content, 'UTF-8')
    
    def do_GET(self):
        global peer_list
        response = self.handle_http(200, self.path)
        self.wfile.write(response)
        peer_list.add(self.client_address[0])

def QueryMessage(secure_sock: ssl.SSLSocket, message_id: str, buffer_size=1024):
    secure_sock.send(MAGIC_NUMBER_CLIENT + b"2" + bytes(message_id, "utf-8"))
    return list(map(socket.inet_ntoa, re.findall('....', secure_sock.recv(buffer_size).decode()[len(MAGIC_NUMBER_SERVER):])))


def GetMessages(secure_sock: ssl.SSLSocket, buffer_size=1024, hash_size=32):
    secure_sock.send(MAGIC_NUMBER_CLIENT + b"1")
    return list(map(lambda x:x.hex(), re.findall('.'*hash_size, secure_sock.recv(buffer_size).decode()[len(MAGIC_NUMBER_SERVER):])))

def main():
    while True:
        try:
            with socket.create_connection((SERVER, 8080)) as connection_sock:
                with ssl_context.wrap_socket(connection_sock, server_hostname=SERVER) as secure_sock:
                    print(secure_sock.version())
                    print(secure_sock.recv(1024).decode())
            #poll = requests.get()
            time.sleep(POLL_INTERVAL/1000)
        except KeyboardInterrupt:
            break

main()
