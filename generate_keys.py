# generate_keys.py
from Crypto.PublicKey import RSA
import os

os.makedirs("keys", exist_ok=True)

def gen_pair(prefix):
    key = RSA.generate(2048)
    with open(f"keys/{prefix}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"keys/{prefix}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print(f"Generated keys/{prefix}_private.pem and keys/{prefix}_public.pem")

if __name__ == "__main__":
    gen_pair("sender")
    gen_pair("receiver")