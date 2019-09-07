# TODO: Integrate into client.py when both are stable
# TODO: Random art pfps

import client

import sys
import json
import time
from PySide2.QtWidgets import *
from PySide2.QtCore import *
import threading

def fetch_new_data(data: dict):
    # TODO: fetch new msgs
    sender = str(data['sender'])
    msg = str(data['msg'])

class PingFive(QRunnable):
    def run(self):
        try:
            pass
            
        except KeyboardInterrupt:
            return



class MyWidget(QWidget):
    @Slot()
    def button_clicked(self):
        if self.msg_textbox.text().strip():
            message_content = self.msg_textbox.text()
            message_id = client.GenerateID(message_content)
            print(message_id)
            client.RegisterMessage(self.secure_sock_send, message_id)

            self.msg_display.append(self.msg_textbox.text().strip())
            self.msg_textbox.setText("")
        

    def __init__(self):
        QWidget.__init__(self)

        self.threadpool = QThreadPool() # XXX MULTITHREADING THING FOR FRANK
        self.threadpool.start(PingFive())
        self.secure_sock_send = client.CreateSocket(port=8083)
        # Create PySide2 Widgets
        self.setWindowTitle("Hail Mary")
        self.msg_display = QTextEdit()
        self.msg_textbox = QLineEdit(self)
        self.send_button = QPushButton("Send")

        # Add Settings to Widgets
        self.msg_display.setReadOnly(True)
        self.msg_textbox.setText("example msg")

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
    