# server.py
import socket, json, base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SERVER_PRIV_FILE = Path("server_private.pem")
CERT_FILE = Path("server_cert.json")

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def server_main():
    server_priv = RSA.import_key(SERVER_PRIV_FILE.read_bytes())
    cert_bundle = json.loads(CERT_FILE.read_text())

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 5050))
    s.listen(1)
    print("Server listening on 127.0.0.1:5050")

    conn, addr = s.accept()
    print("Client connected from", addr)

    # 1) Send certificate bundle
    conn.sendall((json.dumps(cert_bundle) + "\n").encode())

    # 2) Receive encrypted AES key
    enc_key_b64 = conn.recv(4096).strip()
    enc_key = base64.b64decode(enc_key_b64)

    rsa_cipher = PKCS1_OAEP.new(server_priv)
    session_key = rsa_cipher.decrypt(enc_key)
    print("Session key established.")

    # 3) Communicate using AES-CBC (simple for demo)
    while True:
        data = conn.recv(4096)
        if not data:
            break
        iv = data[:16]
        ct = data[16:]

        aes = AES.new(session_key, AES.MODE_CBC, iv)
        msg = unpad(aes.decrypt(ct))
        print("Client says:", msg.decode())

        # Echo back uppercased
        reply = msg.decode().upper().encode()
        iv2 = get_random_bytes(16)
        aes2 = AES.new(session_key, AES.MODE_CBC, iv2)
        ct2 = aes2.encrypt(pad(reply))
        conn.sendall(iv2 + ct2)

    conn.close()
    s.close()

if __name__ == "__main__":
    server_main()
