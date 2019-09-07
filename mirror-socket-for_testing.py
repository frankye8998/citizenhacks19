import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.pem', 'server.key')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:  
    sock.bind(("localhost", 8083)) # Set up listening for socket
    sock.listen(5)  # Limit num. of connections simultaneously possible?
    with context.wrap_socket(sock, server_side=True) as ssock:
        try:
            conn, addr = ssock.accept()
            print(conn, addr)
            while True:
                print(conn.recv(1024).decode())
        except KeyboardInterrupt:
            pass

    
    