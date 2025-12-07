# client.py
import socket, json, base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

CA_PUB_FILE = Path("ca_public.pem")

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def verify_cert_bundle(bundle: dict) -> RSA.RsaKey:
    ca_pub = RSA.import_key(CA_PUB_FILE.read_bytes())

    cert = bundle["cert"]
    sig_b64 = bundle["signature"]
    signature = base64.b64decode(sig_b64)

    cert_bytes = json.dumps(cert, sort_keys=True).encode()
    h = SHA256.new(cert_bytes)
    pkcs1_15.new(ca_pub).verify(h, signature)  # raises if invalid

    print("Certificate verified. Issuer:", cert["issuer"])
    if cert["subject"] != "MyTestServer":
        raise ValueError("Unexpected server subject!")

    server_pub_pem = cert["public_key_pem"].encode()
    server_pub = RSA.import_key(server_pub_pem)
    return server_pub

def client_main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 5050))

    # 1) Receive certificate bundle (one line JSON)
    bundle_line = s.recv(8192).decode().strip()
    cert_bundle = json.loads(bundle_line)
    server_pub = verify_cert_bundle(cert_bundle)

    # 2) Generate AES session key and send encrypted key
    session_key = get_random_bytes(32)  # 256-bit
    rsa_cipher = PKCS1_OAEP.new(server_pub)
    enc_key = rsa_cipher.encrypt(session_key)
    s.sendall(base64.b64encode(enc_key))

    print("Session key sent. Now you can chat.")
    while True:
        msg = input("You: ").encode()
        if not msg:
            break

        iv = get_random_bytes(16)
        aes = AES.new(session_key, AES.MODE_CBC, iv)
        ct = aes.encrypt(pad(msg))
        s.sendall(iv + ct)

        resp = s.recv(4096)
        if not resp:
            break
        iv2 = resp[:16]
        ct2 = resp[16:]
        aes2 = AES.new(session_key, AES.MODE_CBC, iv2)
        reply = unpad(aes2.decrypt(ct2))
        print("Server:", reply.decode())

    s.close()

if __name__ == "__main__":
    client_main()
