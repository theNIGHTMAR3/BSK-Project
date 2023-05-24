from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

import getopt
import sys


def encryptCFB(inputFile, outputFile, key):
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


def encryptCBC(inputFile, outputFile, key):
    with open(key, "r") as kk:
        key = RSA.import_key(kk.read())
    with open(inputFile, 'rb') as data:
        data = data.read()
        k = get_random_bytes(16)
        c = AES.new(k, AES.MODE_CBC)
        c_data = c.encrypt(pad(data, AES.block_size))
        ck = PKCS1_OAEP.new(key)
        c_k = ck.encrypt(k)
        with open(outputFile, "w+b") as output:
            output.write(len(c_k).to_bytes(4, "little"))
            output.write(c_k)
            output.write(c.iv)
            output.write(c_data)


def decryptCFB(inputFile, outputFile, key):
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


def decryptCBC(inputFile, outputFile, key):
    with open(key, "r") as kk:
        key = RSA.import_key(kk.read())
    with open(inputFile, "rb") as c_data:
        size = c_data.read(4)
        c_k = c_data.read(int.from_bytes(size, "little"))
        iv = c_data.read(16)
        data = c_data.read()
    ck = PKCS1_OAEP.new(key)
    k = ck.decrypt(c_k)
    c = AES.new(k, AES.MODE_CBC, iv=iv)
    data = unpad(c.decrypt(data), AES.block_size)
    with open(outputFile, "wb") as f:
        f.write(data)