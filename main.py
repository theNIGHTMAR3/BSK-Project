import argparse
import socket
from threading import Thread
from Interface import Interface
from PyQt5.QtWidgets import QApplication, QMainWindow
import sys


def recv_message(cs):
    while True:
        data = cs.recv(1024)
        if not data:
            continue
        print("\nReceived Message:", data.decode())


if __name__ == "__main__":

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = QMainWindow()
    window.resize(300, 300)

    mode=''
    parser = argparse.ArgumentParser()
    parser.add_argument("-s","--server", help="run program as server")
    parser.add_argument("-c","--client", help="run program as client")

    args = parser.parse_args()

    if args.server:
        mode ="server"
        print("server mode")
    elif args.client:
        mode = "client"
        print("client mode")
    else:
        print("select a mode to run application")
        quit()


    # SERVER Mode
    if mode=="server":
        s = socket.socket()
        s.bind(('localhost', 2137))
        s.listen(3)
        print("Listening on port")
        c, addr = s.accept()
        print("Connected with ", addr)

        thread = Thread(target=recv_message, args=(c, ))
        thread.start()

        appInterface = Interface(window)

        # message = ''
        # while message.lower() != 'quit':
        #     message = input("Enter the msg:")
        #
        #     c.send(bytes(message, 'utf-8'))
        c.close()


    # CLIENT Mode
    if mode == "client":

        s = socket.socket()

        port = 2137
        s.connect(('localhost', port))

        thread = Thread(target=recv_message, args=(s,))
        thread.start()
        # message=''
        # while message.lower() != 'quit':
        #     message = input("Enter the msg:")
        #     s.send(bytes(message, 'utf-8'))
        appInterface = Interface(window)

        s.close()
    sys.exit(app.exec_())

