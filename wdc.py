import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


def encrypt_key(private_k, output_file, password):
    password = bytes(password, 'utf-8')
    h = SHA256.new(password)
    k = h.digest()
    c = AES.new(k, AES.MODE_CBC)
    c_data = c.encrypt(pad(private_k, AES.block_size))
    with open(output_file, "w+b") as output:
        output.write(c.iv)
        output.write(c_data)


def decrypt_key(input_file, password):
    password = bytes(password, 'utf-8')
    h = SHA256.new(password)
    k = h.digest()
    with open(input_file, "rb") as c_data:
        iv = c_data.read(16)
        data = c_data.read()
    c = AES.new(k, AES.MODE_CBC, iv=iv)
    data = unpad(c.decrypt(data), AES.block_size)
    return data


def save_encrypted(input_file, output_file, key, k, c, c_data):
    ck = PKCS1_OAEP.new(key)
    filename = os.path.basename(input_file)
    filename = bytes(filename, 'utf-8')
    c_filename = ck.encrypt(filename)
    c_k = ck.encrypt(k)
    with open(output_file, "w+b") as output:
        output.write(len(c_filename).to_bytes(4, "little"))
        output.write(c_filename)
        output.write(len(c_k).to_bytes(4, "little"))
        output.write(c_k)
        output.write(c.iv)
        output.write(c_data)


def read_encrypted(input_file, key):
    key = RSA.import_key(key)
    with open(input_file, "rb") as c_data:
        filename_size = c_data.read(4)
        c_filename = c_data.read(int.from_bytes(filename_size, "little"))
        size = c_data.read(4)
        c_k = c_data.read(int.from_bytes(size, "little"))
        iv = c_data.read(16)
        data = c_data.read()
    ck = PKCS1_OAEP.new(key)
    filename = ck.decrypt(c_filename)
    filename = filename.decode("utf-8")
    k = ck.decrypt(c_k)
    return k, iv, data, filename


def encryptCFB(input_file, output_file, key):
    key = RSA.import_key(key)
    with open(input_file, 'rb') as data:
        data = data.read()
    k = get_random_bytes(16)
    c = AES.new(k, AES.MODE_CFB)
    c_data = c.encrypt(data)
    save_encrypted(input_file, output_file, key, k, c, c_data)


def encryptCBC(input_file, output_file, key):
    key = RSA.import_key(key)
    with open(input_file, 'rb') as data:
        data = data.read()
    k = get_random_bytes(16)
    c = AES.new(k, AES.MODE_CBC)
    c_data = c.encrypt(pad(data, AES.block_size))
    print("before save")
    save_encrypted(input_file, output_file, key, k, c, c_data)
    print("after save")


def decryptCFB(input_file, output_path, key):
    k, iv, data, filename = read_encrypted(input_file, key)
    c = AES.new(k, AES.MODE_CFB, iv=iv)
    data = c.decrypt(data)
    with open(output_path + filename, "wb") as output:
        output.write(data)


def decryptCBC(input_file, output_path, key):
    k, iv, data, filename = read_encrypted(input_file, key)
    c = AES.new(k, AES.MODE_CBC, iv=iv)
    data = unpad(c.decrypt(data), AES.block_size)
    with open(output_path + filename, "wb") as f:
        f.write(data)
