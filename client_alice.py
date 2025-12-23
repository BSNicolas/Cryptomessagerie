import socket
import os
import oqs
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

os.add_dll_directory(r"C:\msys64\mingw64\bin")

def derive_key(secret):
    hash = hashes.Hash(hashes.SHA256())
    hash.update(secret)
    return hash.finalize()

def receive_thread(socket, aesgcm):
    while True:
        data = socket.recv(4096)
        if not data: 
            break
        n, messageEncrypt = data[:12], data[12:]
        decrypt = aesgcm.decrypt(n, messageEncrypt, None)
        print(f"\n[BOB] : {decrypt.decode()}\n[MOI] : ", end="")

def start_client():
    host, port = '127.0.0.1', 65432
    algoKEM, algoSign = "ML-KEM-768", "ML-DSA-65"
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    with oqs.Signature(algoSign) as verif:
        signPrivateKeyLength = verif.details['length_public_key']
        signLength = verif.details['length_signature']
        bobSignPrivateKey = client_socket.recv(signPrivateKeyLength)
        with oqs.KeyEncapsulation(algoKEM) as kem:
            kemPrivateKeyLength = kem.details['length_public_key']
            bobKEMPrivateKey = client_socket.recv(kemPrivateKeyLength)
            signature = client_socket.recv(signLength)
            if not verif.verify(bobKEMPrivateKey, signature, bobSignPrivateKey):
                print("ALERTE : Signature invalide !"); return
            ciphertext, secret = kem.encap_secret(bobKEMPrivateKey)
            client_socket.sendall(ciphertext)
            aesgcm = AESGCM(derive_key(secret))
            print("[] Connecté à Bob.")
            threading.Thread(target=receive_thread, args=(client_socket, aesgcm), daemon=True).start()
            while True:
                message = input("[MOI] : ")
                if message.lower() == 'exit': 
                    break
                n = os.urandom(12)
                client_socket.sendall(n + aesgcm.encrypt(n, message.encode(), None))

if __name__ == "__main__":
    start_client()