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

def receive_thread(connexion, aesgcm):
    while True:
        data = connexion.recv(4096)
        if not data: 
            break
        n, messageEncrypt = data[:12], data[12:]
        decrypt = aesgcm.decrypt(n, messageEncrypt, None)
        print(f"\n[ALICE] : {decrypt.decode()}\n[MOI] : ", end="")

def start_server():
    host, port = '127.0.0.1', 65432
    algoKEM, algoSign = "ML-KEM-768", "ML-DSA-65"
    with oqs.Signature(algoSign) as sign:
        bobSignPrivateKey = sign.generate_keypair()
        with oqs.KeyEncapsulation(algoKEM) as kem:
            bobKEMPrivateKey = kem.generate_keypair()
            signature = sign.sign(bobKEMPrivateKey)
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((host, port))
            server_socket.listen(1)
            print(f"[] Bob attend sur {port}...")
            connexion, addr = server_socket.accept()
            with connexion:
                connexion.sendall(bobSignPrivateKey + bobKEMPrivateKey + signature)
                ciphertext = connexion.recv(2048)
                secret = kem.decap_secret(ciphertext)
                aesKey = derive_key(secret)
                aesgcm = AESGCM(aesKey)
                print("[] Canal sécurisé établi.")
                threading.Thread(target=receive_thread, args=(connexion, aesgcm), daemon=True).start()
                while True:
                    message = input("[MOI] : ")
                    if message.lower() == 'exit': 
                        break
                    n = os.urandom(12)
                    connexion.sendall(n + aesgcm.encrypt(n, message.encode(), None))

if __name__ == "__main__":
    start_server()