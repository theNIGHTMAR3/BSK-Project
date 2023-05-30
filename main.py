import argparse
import os
import socket
from threading import Thread

import tqdm as tqdm

from Interface import Interface
from PyQt5.QtWidgets import QApplication, QMainWindow
import sys

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024
mode=''


def recv_message(cs):
    while True:
        print("recv")
        try:
            data = cs.recv(BUFFER_SIZE)
            if not data:
                continue
            print("\nReceived Message:", data.decode())
        except:
            print("\nConnection error")
            cs.close()
            exit()


def send_message(cs):
    while True:
        message = input("Enter the msg:")
        if message == "quit":
            return
        cs.send(bytes(message, 'utf-8'))


def recv_file(cs):
    while True:
        received = cs.recv(BUFFER_SIZE).decode()

        filename, filesize = received.split(SEPARATOR)
        # remove absolute path if there is
        filename = os.path.basename(filename)
        filename = mode + "Data/"+filename
        # convert to integer
        filesize = int(filesize)
        cs.settimeout(2)
        progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "wb") as f:
            while True:
                try:
                    # read 1024 bytes from the socket (receive)
                    bytes_read = cs.recv(BUFFER_SIZE)
                except socket.timeout as e:
                    print(e)
                    break
                if not bytes_read:
                    print("not bytes")
                    # nothing is received
                    # file transmitting is done
                    break
                # write to the file the bytes we just received
                f.write(bytes_read)
                # update the progress bar
                progress.update(len(bytes_read))
                # if len(bytes_read)<1024:
                #     print("break")
                #     break
        cs.settimeout(None)


# def sendFile(cs, filename):
#     filesize = os.path.getsize(filename)
#     cs.send(f"{filename}{SEPARATOR}{filesize}".encode())
#
#     progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
#     with open(filename, "rb") as f:
#         while True:
#             # read the bytes from the file
#             bytes_read = f.read(BUFFER_SIZE)
#             if not bytes_read:
#                 # file transmitting is done
#                 break
#             # we use sendall to assure transmission in
#             # busy networks
#             cs.sendall(bytes_read)
#             # update the progress bar
#             progress.update(len(bytes_read))


if __name__ == "__main__":

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = QMainWindow()
    window.resize(300, 300)

    #appInterface = Interface(window)
    #appInterface.setStatus(False)


    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", help="run program as server")
    parser.add_argument("-c", "--client", help="run program as client")

    args = parser.parse_args()

    if args.server:
        # SERVER Mode
        print("server mode")
        mode="Server"
        window.setWindowTitle("Server")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 2137))
        s.listen(3)
        print("Listening on port")
        c, addr = s.accept()
        print("Connected with ", addr)
        s.settimeout(2)


        appInterface = Interface(window, c)
        appInterface.setStatus(True)
        appInterface.mode = "Server"

        #appInterface.setSocket(c)
        #appInterface.setStatus(True)

        thread = Thread(target=recv_file, args=(c,))
        thread.start()



        app.exec_()

        # send_message(c)
        print("1")

        c.close()
        thread.join()
        print("2")



    elif args.client:
        # CLIENT Mode
        print("client mode")
        mode = "Client"
        window.setWindowTitle("Client")
        s = socket.socket()

        port = 2137
        s.connect(('localhost', port))



        appInterface = Interface(window, s)
        appInterface.setStatus(True)
        appInterface.mode = "Client"

        #appInterface.setSocket(s)
        #appInterface.setStatus(True)

        thread = Thread(target=recv_file, args=(s,))
        thread.start()

        # send_message(s)

        app.exec_()
        print("1")
        s.close()
        thread.join()
        print("2")

    else:
        print("select a mode to run application")
        quit()

    exit()





