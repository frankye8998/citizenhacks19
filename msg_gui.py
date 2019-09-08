# TODO: Integrate into client.py when both are stable
# TODO: Random art pfps

import client

import sys
import json
import time
from PySide2.QtWidgets import *
from PySide2.QtCore import *
import threading
import random_art.randomart
import random
import bcrypt
import hashlib
import requests

def fetch_new_data(data: dict):
    # TODO: fetch new msgs
    sender = str(data['sender'])
    msg = str(data['msg'])

class PingFive(QRunnable):
    def run(self):
        try:
            secure_sock = client.CreateSocket()
            messages_list = {msg_id: None for msg_id in client.GetMessages(secure_sock)}
            print("Entering loop")
            while True:
                upd_messages = client.GetMessages(secure_sock)
                new_messages_ids = list(set(upd_messages) ^ set(messages_list.keys()))
                for message_id in new_messages_ids:
                    peer_list = client.QueryMessage(secure_sock, message_id)
                    chosen_peer = random.choice(peer_list)
                    message_json = requests.get(f"{chosen_peer}:8081", data=message_id).json()
                    while not bcrypt.checkpw(hashlib.sha256(bytes(message_json["message"] + message_json["signature"])).digest(), message_id):
                        chosen_peer = random.choice(peer_list)

                    messages_list[message_id] = {"message_content": message_json["message"], "pub_key": message_json['pub_key'], "signature": message_json['signature']}
                time.sleep(client.POLL_INTERVAL/1000)
            
        except KeyboardInterrupt:
            return



class MyWidget(QWidget):
    @Slot()
    def button_clicked(self):
        if self.msg_textbox.text().strip():
            message_content = self.msg_textbox.text()
            message_id = client.GenerateID(message_content, client.SignMessage(message_content))
            print(message_id)
            client.RegisterMessage(self.secure_sock_send, message_id)

            self.msg_display.append(self.msg_textbox.text().strip())
            self.msg_textbox.setText("")
        

    def __init__(self):
        QWidget.__init__(self)

        self.threadpool = QThreadPool() # !!! MULTITHREADING THING FOR FRANK !!!1!
        self.threadpool.start(PingFive())
        self.secure_sock_send = client.CreateSocket(port=8083)
        print("Created 8083")
        # Create PySide2 Widgets
        self.setWindowTitle("Hail Mary")
        self.msg_display = QTextEdit()
        self.msg_textbox = QLineEdit(self)
        self.send_button = QPushButton("Send")

        # Add Settings to Widgets
        self.msg_display.setReadOnly(True)
        #self.msg_textbox.setText("example msg")

        # Create Layout, Add Widgets to Layout
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.msg_display)
        self.layout.addWidget(self.msg_textbox)
        self.layout.addWidget(self.send_button)
        self.setLayout(self.layout)

        # Button click functionality
        self.send_button.clicked.connect(self.button_clicked)
        self.msg_textbox.returnPressed.connect(self.button_clicked)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    widget = MyWidget()
    widget.resize(400, 200)
    widget.show()

    sys.exit(app.exec_())
    