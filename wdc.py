from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import getopt
import sys

def encrypt(inputFile, outputFile, key):
    with open(key, "r") as kk:
        key = RSA.import_key(kk.read())
    with open(inputFile, 'rb') as data:
        data = data.read()
        k = get_random_bytes(16)
        c = AES.new(k, AES.MODE_CFB)
        c_data = c.encrypt(data)
        ck = PKCS1_OAEP.new(key)
        c_k = ck.encrypt(k)
        with open(outputFile, "w+b") as output:
            output.write(len(c_k).to_bytes(4, "little"))
            output.write(c_k)
            output.write(c.iv)
            output.write(c_data)

def decrypt(inputFile, outputFile, key):
    with open(key, "r") as kk:
        key = RSA.import_key(kk.read())
    with open(inputFile, "rb") as c_data:
        size = c_data.read(4)
        c_k = c_data.read(int.from_bytes(size, "little"))
        iv = c_data.read(16)
        data = c_data.read()
        ck = PKCS1_OAEP.new(key)
        k = ck.decrypt(c_k)
        c = AES.new(k, AES.MODE_CFB, iv=iv)
        data = c.decrypt(data)
        with open(outputFile, "wb") as output:
            output.write(data)








if __name__ == "__main__":
    inputFile = ''
    outputFile = ''
    key = ''
    mode = ''
    opts, args = getopt.getopt(sys.argv[1:], "edi:o:k:", ["encrypt", "decrypt", "input=", "output=", "key="])
    for opt, arg in opts:
        if opt in ("-o", "--output"):
            outputFile = arg
        if opt in ("-i", "--input"):
            inputFile = arg
        if opt in ("-k", "--key"):
            key = arg
        if opt in ("-e", "--encrypt"):
            mode = "e"
        if opt in ("-d", "--decrypt"):
            mode = "d"
    if mode == "e":
        encrypt(inputFile, outputFile, key)

    if mode == "d":
        decrypt(inputFile, outputFile, key)