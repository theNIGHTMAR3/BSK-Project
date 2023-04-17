import os
import sys
from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QRadioButton, QVBoxLayout, QPushButton, QApplication, \
    QMainWindow, QMessageBox, QFileDialog
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import QApplication as qapp
from wdc import encrypt, decrypt

import tqdm as tqdm

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024

class Interface:
    def __init__(self, mainWindow, socket):
        self.isEncrypt = True
        self.inputFilename = ""
        self.outputFilename = ""
        self.sendingFilename= ""
        self.keyStr = ""
        self.socket = socket


        self.widget = QWidget(mainWindow)
        flo = QFormLayout()

        self.encr = QRadioButton("Encrypt file")
        self.encr.setChecked(True)
        self.encr.toggled.connect(lambda: self.setIsEncrypt(self.encr.isChecked()))
        self.decr = QRadioButton("Decrypt file")
        layout = QVBoxLayout()
        layout.addWidget(self.encr)
        layout.addWidget(self.decr)

        flo.addRow("Choose action", layout)

        self.inputFile = QPushButton("Choose input file")
        self.inputFile.clicked.connect(lambda: self.setInputFilename())

        self.outputFile = QPushButton("Choose output file")
        self.outputFile.clicked.connect(lambda: self.setOutputFilename())

        self.key = QPushButton("Choose key file")
        self.key.clicked.connect(lambda: self.setKey())

        flo.addRow("Input filename:", self.inputFile)
        flo.addRow("Output filename:", self.outputFile)
        flo.addRow("Key:", self.key)

        button = QPushButton("Perform action")
        button.clicked.connect(lambda: self.performAction())
        flo.addRow("", button)

        message = QLineEdit()
        sendButton = QPushButton("Send message")
        sendButton.clicked.connect(lambda: self.sendMessage(message.text()))
        flo.addRow("", message)
        flo.addRow("", sendButton)

        self.fileToSend = QPushButton("Choose file to send")
        self.fileToSend.clicked.connect(lambda: self.setFileToSend())
        flo.addRow("File to send:", self.fileToSend)

        sendFileButton = QPushButton("Send File")
        sendFileButton.clicked.connect(lambda: self.sendFile(self.sendingFilename))
        flo.addRow("", sendFileButton)


        self.widget.setLayout(flo)
        mainWindow.setCentralWidget(self.widget)
        mainWindow.show()

    def clearForm(self):
        self.inputFile.setText("Choose input file")
        self.inputFilename = ""
        self.outputFile.setText("Choose output file")
        self.outputFilename = ""
        self.key.setText("Choose key file")
        self.keyStr = ""
        self.encr.setChecked(True)

    def performAction(self):
        if self.keyStr != "" and self.inputFilename != "" and self.outputFilename != "":
            success = False
            if self.isEncrypt:
                encrypt(self.inputFilename, self.outputFilename, self.keyStr)
                success = True
            else:
                try:
                    decrypt(self.inputFilename, self.outputFilename, self.keyStr)
                    success = True
                except:
                    self.showFailDialog("Error", "Generic error")
            if(success):
                self.showSuccessDialog("Enrypting" if self.isEncrypt else "Decrypting")
            self.clearForm()
        else:
            self.showFailDialog("Wrong input", "All fields must be filled")

    def sendMessage(self, message):
        self.socket.send(bytes(message, 'utf-8'))

    def sendFile(self, filename):
        filesize = os.path.getsize(filename)
        self.socket.send(f"{filename}{SEPARATOR}{filesize}".encode())

        progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "rb") as f:
            while True:
                # read the bytes from the file
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    # file transmitting is done
                    break
                # we use sendall to assure transimission in
                # busy networks
                self.socket.sendall(bytes_read)
                # update the progress bar
                progress.update(len(bytes_read))


    def setInputFilename(self):
        filter = None
        if not self.isEncrypt:
            filter = "(*.enc)"
        tmp = self.showFileDialog(filter)
        if tmp != "":
            self.inputFilename = tmp
        if self.inputFilename != "":
            self.inputFile.setText(self.inputFilename)

    def setOutputFilename(self):
        filter = None
        if self.isEncrypt:
            filter = "(*.enc)"
        tmp = self.showFileDialog(filter)
        if tmp != "":
            self.outputFilename = tmp
        if self.outputFilename != "":
            self.outputFile.setText(self.outputFilename)

    def setFileToSend(self):
        filter = None
        if not self.isEncrypt:
            filter = "(*.enc)"
        tmp = self.showFileDialog(filter)
        if tmp != "":
            self.sendingFilename = tmp
        if self.sendingFilename != "":
            self.fileToSend.setText(self.sendingFilename)

    def setKey(self):
        tmp = self.showFileDialog("PEM Files (*.pem)")
        if tmp != "":
            self.keyStr = tmp
        if self.keyStr != "":
            self.key.setText(self.keyStr)

    def setIsEncrypt(self, isEncrypt):
        self.isEncrypt = isEncrypt
        tmp = self.inputFilename
        self.inputFilename = self.outputFilename
        self.outputFilename = tmp
        self.outputFile.setText(self.outputFilename) if self.outputFilename != "" else self.outputFile.setText("Choose output file")
        self.inputFile.setText(self.inputFilename) if self.inputFilename != "" else self.inputFile.setText("Choose input file")



    def showSuccessDialog(self, text):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)

        msg.setText("Action performed")
        msg.setInformativeText(text + " done")
        msg.setWindowTitle(text)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def showFailDialog(self, text, InfoText):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)

        msg.setText(text)
        msg.setInformativeText(InfoText)
        msg.setWindowTitle("Error")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def showFileDialog(self, filt=None):
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.AnyFile)
        if filt is not None:
            dialog.setNameFilter(filt)
        fileName = ""
        if dialog.exec_():
            fileName = dialog.selectedFiles()
            return fileName[0]
        return fileName


#if __name__ == "__main__":


    #loader = QUiLoader()
    #app = qapp(sys.argv)
    #window = loader.load("testUI.ui", None)

    # app = QApplication(sys.argv)
    # app.setStyle('Fusion')
    # window = QMainWindow()
    # window.resize(300, 300)
    # appInterface = Interface(window)


    # sys.exit(app.exec_())
