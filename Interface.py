import os
import datetime
from threading import Thread

from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QRadioButton, QVBoxLayout, QPushButton,  \
    QMessageBox, QFileDialog, QLabel, QButtonGroup, QProgressBar, QInputDialog, QTextEdit, \
    QHBoxLayout, QGroupBox
from PyQt5 import QtCore
from wdc import encryptCFB, decryptCFB
from wdc import encryptCBC, decryptCBC, encrypt_key, decrypt_key, encrypt_message, decrypt_message
from Crypto.PublicKey import RSA

import tqdm as tqdm

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024


class Interface:

    # noinspection PyUnresolvedReferences
    def __init__(self, main_window, files_socket, chat_socket):
        self.is_encrypt = True
        self.input_filename = ""
        self.output_filename = ""
        self.sending_filename = ""

        self.public_key_path = ""
        self.private_key_path = ""
        self.public_key_in_memory = ""
        self.private_key_in_memory = ""

        self.files_socket = files_socket
        self.chat_socket = chat_socket
        self.is_CBC = True
        self.is_connected = False
        self.mode = None
        self.progress = ""
        self.chat = ""
        self.widget = QWidget(main_window)

        chat_widget = QWidget()
        settings_actions_widget = QWidget()

        # Chat layout
        self.chat = QTextEdit()
        self.chat.setReadOnly(True)
        message_send_button = QPushButton("Send message")
        self.message_input = QLineEdit()

        self.message_input.returnPressed.connect(lambda: self.send_message(self.message_input.text()))
        message_send_button.clicked.connect(lambda: self.send_message(self.message_input.text()))

        input_and_button_widget = QWidget()
        input_and_button = QHBoxLayout(input_and_button_widget)
        input_and_button.addWidget(self.message_input)
        input_and_button.addWidget(message_send_button)

        chat_layout = QVBoxLayout(chat_widget)
        chat_layout.addWidget(self.chat)
        chat_layout.addWidget(input_and_button_widget)
        chat_widget.setMinimumWidth(400)

        # settings layout
        settings_group = QGroupBox("Configuration")
        settings_group.setStyleSheet("QGroupBox {"
                                     "font-size: 20px; }"
                                     "QGroupBox::title {"
                                     "subcontrol-origin: margin;"
                                     "subcontrol-position: top center;"
                                     "padding: 10px;"
                                     "font-size: 20px}")
        settings_layout = QFormLayout(settings_group)

        self.status = QLabel()
        settings_layout.addRow("STATUS:", self.status)
        self.set_status(False)

        settings_layout.addRow(QLabel(""), QWidget().setMinimumHeight(70))

        self.button_group1 = QButtonGroup()
        self.button_group2 = QButtonGroup()

        self.cbc = QRadioButton("CBC Mode")
        self.cbc.setChecked(True)
        # noinspection PyUnresolvedReferences
        self.cbc.toggled.connect(lambda: self.set_is_CBC(self.cbc.isChecked()))
        self.cfb = QRadioButton("CFB Mode")
        self.button_group1.addButton(self.cbc, 1)
        self.button_group1.addButton(self.cfb, 2)

        layout1 = QVBoxLayout()
        layout1.addWidget(self.cbc)
        layout1.addWidget(self.cfb)
        settings_layout.addRow("Choose mode", layout1)

        self.encr = QRadioButton("Encrypt file")
        self.encr.setChecked(True)
        self.encr.toggled.connect(lambda: self.set_is_encrypt(self.encr.isChecked()))
        self.decr = QRadioButton("Decrypt file")
        self.button_group2.addButton(self.encr, 1)
        self.button_group2.addButton(self.decr, 2)
        layout2 = QVBoxLayout()
        layout2.addWidget(self.encr)
        layout2.addWidget(self.decr)

        settings_layout.addRow("Choose action", layout2)

        spacer2 = QWidget()
        spacer2.setMinimumHeight(20)
        settings_layout.addRow(spacer2)

        self.key_generator = QPushButton("Generate public and private keys")
        self.key_generator.clicked.connect(lambda: self.generate_keys())

        self.public_key = QPushButton("Choose public key file")
        self.public_key.clicked.connect(lambda: self.set_public_key())

        self.private_key = QPushButton("Choose private key file")
        self.private_key.clicked.connect(lambda: self.set_private_key())

        settings_layout.addRow("Key Generator:", self.key_generator)
        settings_layout.addRow("Public key:", self.public_key)
        settings_layout.addRow("Private key:", self.private_key)

        # actions layout
        actions_group = QGroupBox("Actions")
        actions_group.setStyleSheet("QGroupBox {"
                                    "font-size: 20px;}"
                                    "QGroupBox::title {"
                                    "subcontrol-origin: margin;"
                                    "subcontrol-position: top center;"
                                    "padding: 10px;"
                                    "font-size: 20px}")

        actions_layout = QFormLayout(actions_group)

        self.input_file = QPushButton("Choose input file")
        self.input_file.clicked.connect(lambda: self.set_input_filename())

        self.input_file = QPushButton("Choose input file")
        self.input_file.clicked.connect(lambda: self.set_input_filename())

        button = QPushButton("Perform action")
        button.clicked.connect(lambda: self.perform_action())

        actions_layout.addRow("Input filename:", self.input_file)
        actions_layout.addRow("", button)

        spacer3 = QWidget()
        spacer3.setMinimumHeight(30)
        actions_layout.addRow(spacer3)

        self.file_to_send = QPushButton("Choose file to send")
        self.file_to_send.clicked.connect(lambda: self.set_file_to_send())
        self.file_to_send_button = QPushButton("Send File")
        self.file_to_send_button.clicked.connect(lambda: self.send_file(self.sending_filename))

        actions_layout.addRow("File to send:", self.file_to_send)
        actions_layout.addRow("", self.file_to_send_button)

        spacer4 = QWidget()
        spacer4.setMinimumHeight(60)
        actions_layout.addRow(spacer4)

        self.progress = QProgressBar()
        self.progress.setAlignment(QtCore.Qt.AlignCenter)
        actions_layout.addRow("progress:", self.progress)

        settings_actions = QVBoxLayout(settings_actions_widget)
        settings_actions.addWidget(settings_group)
        settings_actions.addWidget(actions_group)

        other = QHBoxLayout(self.widget)
        other.addWidget(chat_widget)
        other.addWidget(settings_actions_widget)

        main_window.setCentralWidget(self.widget)
        main_window.show()

        thread1 = Thread(target=self.receive_file)
        thread2 = Thread(target=self.receive_message)

        thread1.start()
        thread2.start()

    def clear_form(self):
        self.input_file.setText("Choose input file")
        self.input_filename = ""
        self.output_filename = ""
        self.sending_filename = ""
        self.file_to_send.setText("Choose file to send")
        self.file_to_send_button.setText("Send File")
        self.progress.reset()
        self.message_input.setText("")

    def perform_action(self):
        if self.public_key_path != "" and self.private_key_path != "" and self.input_filename != "" and \
                self.output_filename != "":
            success = False
            if self.is_encrypt:
                if self.is_CBC:
                    encryptCBC(self.input_filename, self.output_filename, self.public_key_in_memory)
                else:
                    encryptCFB(self.input_filename, self.output_filename, self.public_key_in_memory)
                success = True
            else:
                try:
                    if self.is_CBC:
                        decryptCBC(self.input_filename, self.output_filename, self.private_key_in_memory)
                    else:
                        decryptCFB(self.input_filename, self.output_filename, self.private_key_in_memory)
                    success = True
                except Exception as e:
                    self.show_fail_dialog("Error", "Generic error")
                    print(e)
            if success:
                self.show_success_dialog("Encrypting" if self.is_encrypt else "Decrypting")
            self.clear_form()
        else:
            self.show_fail_dialog("Wrong input", "All fields must be filled")

    def send_message(self, message):
        if message != "" and self.public_key_path != "" and self.private_key_path != "":
            try:
                encrypted_message = encrypt_message(message, self.public_key_in_memory, self.is_CBC)
                self.chat_socket.send(encrypted_message)

                current_time = datetime.datetime.now()
                str_date_time = current_time.strftime("%H:%M:%S")

                if self.chat.toPlainText() != "":
                    self.chat.append('')
                self.chat.append(str_date_time)
                self.chat.append("You:\n" + message)
                self.chat.ensureCursorVisible()
                self.message_input.clear()
                print("Message sent")

            except Exception as e:
                self.show_fail_dialog("Error", "Error during sending message")
                print(e)

    def receive_message(self):
        print("Listening for messages")
        while True:
            try:
                received = self.chat_socket.recv(BUFFER_SIZE)
                if not received:
                    continue

                decrypted_message = decrypt_message(received, self.private_key_in_memory, self.is_CBC)
                print("\nReceived Message:", decrypted_message)

                current_time = datetime.datetime.now()
                str_date_time = current_time.strftime("%H:%M:%S")

                if self.chat.toPlainText() != "":
                    self.chat.append('')
                self.chat.append(str_date_time)
                self.chat.append("Other:\n" + decrypted_message)
                self.chat.ensureCursorVisible()
            except Exception as e:
                print("\nConnection error")
                print(e)
                self.chat_socket.close()
                exit()

    def send_file(self, filename):
        if filename != "":
            filesize = os.path.getsize(filename)
            self.files_socket.send(f"{filename}{SEPARATOR}{filesize}".encode())

            progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            reduced_filesize = filesize
            divider = 1
            r = 0

            # larger then int
            while reduced_filesize > 2_147_483_647:
                divider *= 10
                reduced_filesize = filesize / divider

            self.progress.setMaximum(int(reduced_filesize))
            with open(filename, "rb") as f:
                try:
                    while True:
                        # read the bytes from the file
                        bytes_read = f.read(BUFFER_SIZE)
                        if not bytes_read:
                            # file transmitting is done
                            break
                        # we use sendall to assure transmission in busy networks
                        self.files_socket.sendall(bytes_read)
                        # update the progress bar
                        r += 1
                        self.progress.setValue(int((r * BUFFER_SIZE) / divider))
                        progress.update(len(bytes_read))
                except Exception as e:
                    print(e)
                    self.show_fail_dialog("Error", "Error during sending file")
                    return
            # Sending done
            self.progress.setValue(self.progress.maximum())
            self.show_success_dialog("Sending complete")
            self.clear_form()

    def receive_file(self):
        print("Listening for files")
        while True:
            try:
                received = self.files_socket.recv(BUFFER_SIZE).decode()
            except Exception as e:
                print(e)
                self.set_status(False)
                break

            filename, filesize = received.split(SEPARATOR)
            # remove absolute path if there is
            filename = os.path.basename(filename)
            filename = self.mode + "Data/" + filename
            # convert to integer
            filesize = int(filesize)

            reduced_filesize = filesize
            divider = 1
            r = 0

            # larger then int
            while reduced_filesize > 2_147_483_647:
                divider *= 10
                reduced_filesize = filesize / divider

            success = False

            self.files_socket.settimeout(2)
            self.progress.setMaximum(int(reduced_filesize))

            progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(filename, "wb") as f:
                while True:
                    try:
                        # read 1024 bytes from the socket (receive)
                        bytes_read = self.files_socket.recv(BUFFER_SIZE)
                    except Exception as e:
                        print(e)
                        self.show_fail_dialog("Error", "Error during downloading the file")
                        break

                    # nothing is received, downloading done
                    if not bytes_read:
                        success = True
                        break

                    f.write(bytes_read)

                    # update the progress bar
                    r += 1
                    self.progress.setValue(int((r * BUFFER_SIZE) / divider))
                    progress.update(len(bytes_read))

                    if len(bytes_read) < BUFFER_SIZE:
                        success = True
                        break

            self.files_socket.settimeout(None)

            # Downloading done
            if success:
                self.progress.setValue(self.progress.maximum())
                self.show_success_dialog("Download complete")
                self.clear_form()

    def set_input_filename(self):
        filter = None
        prename = self.mode + "Data/"
        if not self.is_encrypt:
            filter = "(*.enc)"
            self.output_filename = prename
        else:
            self.output_filename = prename + "encrypted.enc"
        tmp = self.show_file_dialog(filter)
        if tmp != "":
            self.input_filename = tmp
        if self.input_filename != "":
            self.input_file.setText(self.input_filename)

    def set_file_to_send(self):
        filter = None
        tmp = self.show_file_dialog(filter)
        if tmp != "":
            self.sending_filename = tmp
        if self.sending_filename != "":
            try:
                self.file_to_send.setText(self.sending_filename)
            except Exception as e:
                self.show_fail_dialog("Error", "Generic error")
                print(e)

    def set_public_key(self):
        tmp = self.show_file_dialog("PEM Files (*.pem)")
        if tmp != "":
            self.public_key_path = tmp
        if self.public_key_path != "":
            with open(self.public_key_path, "r") as kk:
                self.public_key_in_memory = kk.read()

            self.public_key.setText(self.public_key_path)

    def set_private_key(self):
        tmp = self.show_file_dialog("PEM Files (*.pem)")
        if tmp != "":
            self.private_key_path = tmp
        if self.private_key_path != "":
            password, done1 = QInputDialog.getText(self.widget, 'Input Dialog', 'Enter password:')
            if not done1:
                return
            try:
                self.private_key_in_memory = decrypt_key(self.private_key_path, password)
            except Exception as e:
                self.show_fail_dialog("Error", "Wrong password")
                print(e)
                return
            self.private_key.setText(self.private_key_path)

    def generate_keys(self):
        print("generate keys")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        path = self.mode + "Data/"
        password, done1 = QInputDialog.getText(self.widget, 'Input Dialog', 'Enter password:')
        if not done1:
            return
        encrypt_key(private_key, path + self.mode + "_private.pem", password)
        print("after enc")

        f2 = open(path + self.mode + "_public.pem", "w")
        f2.write(public_key.decode())
        f2.close()

    def set_is_encrypt(self, is_encrypt):
        self.is_encrypt = is_encrypt
        self.clear_form()

    def set_is_CBC(self, is_CBC):
        self.is_CBC = is_CBC

    def set_status(self, status: bool):
        self.is_connected = status
        if self.is_connected:
            self.status.setText("CONNECTED")
            self.status.setStyleSheet("color : green")
        else:
            self.status.setText("DISCONNECTED")
            self.status.setStyleSheet("color : red")

    @staticmethod
    def show_success_dialog(text):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Action performed")
        msg.setInformativeText(text + " done")
        msg.setWindowTitle(text)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    @staticmethod
    def show_fail_dialog(text, InfoText):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText(text)
        msg.setInformativeText(InfoText)
        msg.setWindowTitle("Error")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    @staticmethod
    def show_file_dialog(filter=None):
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.AnyFile)
        if filter is not None:
            dialog.setNameFilter(filter)
        fileName = ""
        if dialog.exec_():
            fileName = dialog.selectedFiles()
            return fileName[0]
        return fileName
