import json, base64, datetime
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from pathlib import Path

CA_PRIV_FILE = Path("ca_private.pem")
CA_PUB_FILE = Path("ca_public.pem")
CERT_FILE = Path("server_cert.json")

def generate_ca_keys():
    key = RSA.generate(2048)
    CA_PRIV_FILE.write_bytes(key.export_key("PEM"))
    CA_PUB_FILE.write_bytes(key.publickey().export_key("PEM"))

def load_ca_keys():
    priv = RSA.import_key(CA_PRIV_FILE.read_bytes())
    pub = RSA.import_key(CA_PUB_FILE.read_bytes())
    return priv, pub

def issue_server_cert(server_name: str, server_pub_pem: bytes):
    ca_priv, ca_pub = load_ca_keys()

    cert = {
        "subject": server_name,
        "public_key_pem": server_pub_pem.decode(),
        "issuer": "MyToyCA",
        "valid_from": datetime.datetime.utcnow().isoformat(),
        "valid_to": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
    }

    cert_bytes = json.dumps(cert, sort_keys=True).encode()
    h = SHA256.new(cert_bytes)
    signature = pkcs1_15.new(ca_priv).sign(h)
    bundle = {
        "cert": cert,
        "signature": base64.b64encode(signature).decode()
    }

    CERT_FILE.write_text(json.dumps(bundle, indent=2))
    print("Issued certificate saved to", CERT_FILE)

if __name__ == "__main__":
    if not CA_PRIV_FILE.exists():
        print("Generating CA key pair...")
        generate_ca_keys()
    else:
        print("CA keys already exist.")

    # Example: read server public key from file
    server_pub_pem = Path("server_public.pem").read_bytes()
    issue_server_cert("MyTestServer", server_pub_pem)
