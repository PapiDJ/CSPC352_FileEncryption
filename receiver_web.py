import os
import requests
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    public_key_to_pem,
    load_public_key_from_pem,
    unpack_for_receiver,
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

def list_files(receiver_id):
    r = requests.get(f"{BASE_URL}/list/{receiver_id}", timeout=10)
    r.raise_for_status()
    return r.json()["files"]

def download_file(file_id):
    r = requests.get(f"{BASE_URL}/download/{file_id}", timeout=20)
    r.raise_for_status()
    return r.json()["package"]

def get_sender_pub(sender_id):
    r = requests.get(f"{BASE_URL}/pubkey/{sender_id}", timeout=10)
    r.raise_for_status()
    return load_public_key_from_pem(
        r.json()["public_key_pem"].encode("utf-8")
    )

def main():
    receiver_id = "bob"

    sk_receiver, pk_receiver = load_or_create_rsa_keypair(receiver_id)
    register_user(receiver_id, public_key_to_pem(pk_receiver))

    files = list_files(receiver_id)
    if not files:
        print("No files.")
        return

    meta = files[0]
    file_id = meta["file_id"]
    sender_id = meta["sender_id"]

    package = download_file(file_id)
    original_name = package.get("original_name", f"{file_id}.bin")

    out_dir = os.path.join("received_files", receiver_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, original_name)

    plaintext = unpack_for_receiver(
        package,
        sk_receiver,
        get_sender_pub,
    )

    with open(out_path, "wb") as f:
        f.write(plaintext)

    print("\n" + "="*60)
    print("[OK] FILE DECRYPTION SUCCESSFUL")
    print("="*60)
    print(f"File ID: {file_id}")
    print(f"From: {sender_id}")
    print(f"Original name: {original_name}")
    print(f"Saved to: {out_path}")
    print(f"Size: {len(plaintext)} bytes")
    print("Signature: VERIFIED")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
