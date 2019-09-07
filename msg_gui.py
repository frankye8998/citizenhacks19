# TODO: Integrate into client.py when both are stable
# TODO: Random art pfps

import sys
import json
import time
from PySide2.QtWidgets import *
from PySide2.QtCore import *

def fetch_new_data(data: dict):
    # TODO: fetch new msgs
    sender = str(data['sender'])
    msg = str(data['msg'])

class MyWidget(QWidget):
    def __init__(self):
        QWidget.__init__(self)

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

        # Add Button click Functionality
        self.send_button.clicked.connect(self.button_clicked)
    
    @Slot()
    def button_clicked(self):
        self.msg_display.append(self.msg_textbox.text())


if __name__ == "__main__":
    app = QApplication(sys.argv)

    widget = MyWidget()
    widget.resize(400, 200)
    widget.show()

    sys.exit(app.exec_())