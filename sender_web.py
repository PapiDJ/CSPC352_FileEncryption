import os
import base64
import uuid
import requests
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    public_key_to_pem,
    load_public_key_from_pem,
    package_for_receiver,
)

BASE_URL = "https://cspc352-fileencryption.onrender.com"

def register_user(user_id, public_key_pem):
    requests.post(
        f"{BASE_URL}/register",
        json={
            "user_id": user_id,
            "public_key_pem": public_key_pem.decode("utf-8"),
        },
        timeout=10,
    ).raise_for_status()

def get_pubkey(user_id):
    r = requests.get(f"{BASE_URL}/pubkey/{user_id}", timeout=10)
    r.raise_for_status()
    return load_public_key_from_pem(
        r.json()["public_key_pem"].encode("utf-8")
    )

def upload_file(package):
    r = requests.post(f"{BASE_URL}/upload", json={"package": package}, timeout=20)
    r.raise_for_status()
    return r.json()["file_id"]

def main():
    sender_id = "alice"
    receiver_id = "bob"
    file_path = "test.txt"

    sk_sender, pk_sender = load_or_create_rsa_keypair(sender_id)
    register_user(sender_id, public_key_to_pem(pk_sender))

    receiver_pub = get_pubkey(receiver_id)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    file_id = str(uuid.uuid4())

    package = package_for_receiver(
        plaintext,
        sender_id,
        receiver_id,
        file_id,
        sk_sender,
        receiver_pub,
    )

    package["original_name"] = os.path.basename(file_path)
    package["plaintext_size"] = len(plaintext)

    real_id = upload_file(package)

    ciphertext_size = len(base64.b64decode(package["ciphertext_b64"]))

    print("\n" + "="*60)
    print("✓ FILE UPLOAD SUCCESSFUL")
    print("="*60)
    print(f"File ID: {real_id}")
    print(f"From: {sender_id}")
    print(f"To: {receiver_id}")
    print(f"Filename: {package['original_name']}")
    print(f"Size: {len(plaintext)} bytes")
    print(f"Encrypted Size: {ciphertext_size} bytes")
    print("Server Response: file uploaded successfully")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
