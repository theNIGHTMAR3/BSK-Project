import argparse
import socket

from Interface import Interface
from PyQt5.QtWidgets import QApplication, QMainWindow
import sys

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024
mode = ''

if __name__ == "__main__":

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = QMainWindow()
    window.setFixedSize(900, 600)

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", help="run program as server")
    parser.add_argument("-c", "--client", help="run program as client")

    args = parser.parse_args()

    if args.server:
        # SERVER Mode
        print("server mode")
        window.setWindowTitle("Server")

        files_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        files_socket.bind(('localhost', 9000))
        chat_socket.bind(('localhost', 9001))

        files_socket.listen(3)
        chat_socket.listen(3)

        print("Listening on ports 9000 and 9001")
        client_files_socket, addr1 = files_socket.accept()
        client_chat_socket, addr2 = chat_socket.accept()

        print("Connected with ", addr1)
        print("Connected with ", addr2)

        files_socket.settimeout(2)
        chat_socket.settimeout(2)
        try:
            appInterface = Interface(window, client_files_socket, client_chat_socket)
            appInterface.setStatus(True)
            appInterface.mode = "Server"
        except Exception as e:
            print(e)

        try:
            app.exec_()
        except Exception as e:
            print(e)

        client_files_socket.close()
        client_chat_socket.close()

    elif args.client:
        # CLIENT Mode
        print("Client mode")
        window.setWindowTitle("Client")
        files_socket = socket.socket()
        chat_socket = socket.socket()

        files_socket.connect(('localhost', 9000))
        chat_socket.connect(('localhost', 9001))
        try:
            appInterface = Interface(window, files_socket, chat_socket)
            appInterface.setStatus(True)
            appInterface.mode = "Client"
        except Exception as e:
            print(e)

        try:
            app.exec_()
        except Exception as e:
            print(e)

        files_socket.close()
        chat_socket.close()

    else:
        print("select a mode to run application")
        quit()

    sys.exit()
