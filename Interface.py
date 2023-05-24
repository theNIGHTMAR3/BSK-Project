import os
import sys
from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QRadioButton, QVBoxLayout, QPushButton, QApplication, \
    QMainWindow, QMessageBox, QFileDialog, QLabel, QButtonGroup, QProgressBar
from PyQt5 import QtCore
from wdc import encryptCFB, decryptCFB
from wdc import encryptCBC, decryptCBC
from Crypto.PublicKey import RSA

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
        self.isCBC = True
        self.isConnected = False
        self.mode = None
        self.progress = ""

        self.widget = QWidget(mainWindow)
        flo = QFormLayout()

        self.status = QLabel()
        flo.addRow("STATUS:", self.status)
        self.setStatus(False)

        self.buttonGroup1 = QButtonGroup()
        self.buttonGroup2 = QButtonGroup()

        self.cbc = QRadioButton("CBC Mode")
        self.cbc.setChecked(True)
        self.cbc.toggled.connect(lambda: self.setIsCBC(self.cbc.isChecked()))
        self.cfb = QRadioButton("CFB Mode")

        self.buttonGroup1.addButton(self.cbc,1)
        self.buttonGroup1.addButton(self.cfb,2)

        layout1 = QVBoxLayout()
        layout1.addWidget(self.cbc)
        layout1.addWidget(self.cfb)

        flo.addRow("Choose mode", layout1)

        self.encr = QRadioButton("Encrypt file")
        self.encr.setChecked(True)
        self.encr.toggled.connect(lambda: self.setIsEncrypt(self.encr.isChecked()))
        self.decr = QRadioButton("Decrypt file")

        self.buttonGroup2.addButton(self.encr, 1)
        self.buttonGroup2.addButton(self.decr, 2)
        layout2 = QVBoxLayout()
        layout2.addWidget(self.encr)
        layout2.addWidget(self.decr)

        flo.addRow("Choose action", layout2)

        self.inputFile = QPushButton("Choose input file")
        self.inputFile.clicked.connect(lambda: self.setInputFilename())

        self.keyGenerator = QPushButton("Generate public and private keys")
        self.keyGenerator.clicked.connect(lambda: self.generateKeys())

        self.key = QPushButton("Choose key file")
        self.key.clicked.connect(lambda: self.setKey())

        flo.addRow("Input filename:", self.inputFile)
        flo.addRow("Key Generator:", self.keyGenerator)
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

        self.progress = QProgressBar()
        self.progress.setAlignment(QtCore.Qt.AlignCenter)
        flo.addRow("progress:", self.progress)

        self.widget.setLayout(flo)
        mainWindow.setCentralWidget(self.widget)
        mainWindow.show()

    def setSocket(self, socket):
        self.socket = socket

    def clearForm(self):
        self.inputFile.setText("Choose input file")
        self.inputFilename = ""
        self.outputFilename = ""
        self.key.setText("Choose key file")
        self.sendingFilename=""
        self.fileToSend=""
        self.keyStr = ""
        self.encr.setChecked(True)
        self.progress.reset()

    def performAction(self):
        if self.keyStr != "" and self.inputFilename != "" and self.outputFilename != "":
            success = False
            if self.isEncrypt:
                if self.isCBC:
                    encryptCBC(self.inputFilename, self.outputFilename, self.keyStr)
                else:
                    encryptCFB(self.inputFilename, self.outputFilename, self.keyStr)
                success = True
            else:
                try:
                    if self.isCBC:
                        decryptCBC(self.inputFilename, self.outputFilename, self.keyStr)
                    else:
                        decryptCFB(self.inputFilename, self.outputFilename, self.keyStr)
                    success = True
                except Exception as e:
                    self.showFailDialog("Error", "Generic error")
                    print(e)
            if success:
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
        reduced_filesize = filesize
        divider = 1
        round = 0

        while reduced_filesize > 2_147_483_647:
            divider *= 10
            reduced_filesize = filesize/divider

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
                    self.socket.sendall(bytes_read)
                    # update the progress bar
                    round += 1
                    self.progress.setValue(int((round * BUFFER_SIZE) / divider))
                    progress.update(len(bytes_read))
            except Exception as e:
                self.showFailDialog("Error", "Generic error")
                print(e)
        # Sending done
        self.progress.setValue(self.progress.maximum())
        self.showSuccessDialog("Sending")
        self.clearForm()



    def setInputFilename(self):
        filter = None
        prename = self.mode+"Data/"
        if not self.isEncrypt:
            filter = "(*.enc)"
            self.outputFilename = prename + "decrypted.txt"
        else:
            self.outputFilename = prename + "encrypted.enc"
        tmp = self.showFileDialog(filter)
        if tmp != "":
            self.inputFilename = tmp
        if self.inputFilename != "":
            self.inputFile.setText(self.inputFilename)


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

    def generateKeys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        path = self.mode+"Data/"

        f1=open(path+"private.pem","w")
        f1.write(private_key.decode())
        f1.close()

        f2 = open(path + "public.pem", "w")
        f2.write(public_key.decode())
        f2.close()

    def setIsEncrypt(self, isEncrypt):
        self.isEncrypt = isEncrypt
        tmp = self.inputFilename
        self.inputFilename = self.outputFilename
        self.outputFilename = tmp
        # self.outputFile.setText(self.outputFilename) if self.outputFilename != "" else self.outputFile.setText(
        #     "Choose output file")
        self.inputFile.setText(self.inputFilename) if self.inputFilename != "" else self.inputFile.setText(
            "Choose input file")

    def setIsCBC(self, isCBC):
        self.isCBC = isCBC

    def setStatus(self, status: bool):
        self.isConnected = status
        if self.isConnected:
            self.status.setText("CONNECTED")
            self.status.setStyleSheet("color : green")
        else:
            self.status.setText("DISCONNECTED")
            self.status.setStyleSheet("color : red")

    # def setProgress(self, progress: str):
    #     self.progress.setText(progress)
    #     self.progress.setStyleSheet("color : red")

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


if __name__ == "__main__":
    # loader = QUiLoader()
    # app = qapp(sys.argv)
    # window = loader.load("testUI.ui", None)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = QMainWindow()
    window.resize(300, 300)
    appInterface = Interface(window, "socket")

    sys.exit(app.exec_())
