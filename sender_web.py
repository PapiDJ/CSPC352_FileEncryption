import requests
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    public_key_to_pem,
    load_public_key_from_pem,
    package_for_receiver,
)

BASE_URL = "https://cspc352-fileencryption-1.onrender.com"

def register_user(user_id: str, public_key_pem_bytes: bytes):
    r = requests.post(f"{BASE_URL}/register", json={
        "user_id": user_id,
        "public_key_pem": public_key_pem_bytes.decode("utf-8"),
    }, timeout=10)
    r.raise_for_status()

def get_pubkey(user_id: str):
    r = requests.get(f"{BASE_URL}/pubkey/{user_id}", timeout=10)
    if r.status_code == 404:
        raise RuntimeError(f"User '{user_id}' not registered on server yet.")
    r.raise_for_status()
    pem_str = r.json()["public_key_pem"]
    return load_public_key_from_pem(pem_str.encode("utf-8"))

def upload_file(package: dict) -> str:
    r = requests.post(f"{BASE_URL}/upload", json={"package": package}, timeout=20)
    r.raise_for_status()
    return r.json()["file_id"]

def main():
    sender_id = "alice"
    receiver_id = "bob"
    file_path = "secret.txt"  # your plaintext file :contentReference[oaicite:4]{index=4}

    sk_sender, pk_sender = load_or_create_rsa_keypair(sender_id)
    pk_pem = public_key_to_pem(pk_sender)

    # 1) register alice public key
    register_user(sender_id, pk_pem)

    # 2) get bob's public key
    receiver_pub = get_pubkey(receiver_id)

    # 3) read plaintext locally
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # 4) encrypt + sign locally (server never sees plaintext / private keys) :contentReference[oaicite:5]{index=5}
    file_id = "file-1"
    package = package_for_receiver(
        plaintext,
        sender_id=sender_id,
        receiver_id=receiver_id,
        file_id=file_id,
        sender_private_key=sk_sender,
        receiver_public_key=receiver_pub,
    )

    # 5) upload encrypted package
    real_file_id = upload_file(package)
    print("Uploaded file with id:", real_file_id)

if __name__ == "__main__":
    main()