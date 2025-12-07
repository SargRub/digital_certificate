from Crypto.PublicKey import RSA
from pathlib import Path

key = RSA.generate(2048)
Path("server_private.pem").write_bytes(key.export_key("PEM"))
Path("server_public.pem").write_bytes(key.publickey().export_key("PEM"))