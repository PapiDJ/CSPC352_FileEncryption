import requests
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    public_key_to_pem,
    load_public_key_from_pem,
    unpack_for_receiver,
)

BASE_URL = "https://cspc352-fileencryption-1.onrender.com"

def register_user(user_id: str, public_key_pem_bytes: bytes):
    r = requests.post(f"{BASE_URL}/register", json={
        "user_id": user_id,
        "public_key_pem": public_key_pem_bytes.decode("utf-8"),
    }, timeout=10)
    r.raise_for_status()

def list_files(receiver_id: str):
    r = requests.get(f"{BASE_URL}/list/{receiver_id}", timeout=10)
    r.raise_for_status()
    return r.json()["files"]

def download_file(file_id: str):
    r = requests.get(f"{BASE_URL}/download/{file_id}", timeout=20)
    r.raise_for_status()
    return r.json()["package"]

def get_pub(sender_id: str):
    r = requests.get(f"{BASE_URL}/pubkey/{sender_id}", timeout=10)
    r.raise_for_status()
    pem_str = r.json()["public_key_pem"]
    return load_public_key_from_pem(pem_str.encode("utf-8"))

def main():
    receiver_id = "bob"

    sk_receiver, pk_receiver = load_or_create_rsa_keypair(receiver_id)
    pk_pem = public_key_to_pem(pk_receiver)

    # 1) register bob public key
    register_user(receiver_id, pk_pem)

    # 2) list files for bob
    files = list_files(receiver_id)
    print("Files for", receiver_id, ":", files)
    if not files:
        print("No files.")
        return

    # 3) download first file
    file_id = files[0]["file_id"]
    package = download_file(file_id)

    # 4) decrypt + verify locally :contentReference[oaicite:6]{index=6}
    plaintext = unpack_for_receiver(
        package,
        receiver_private_key=sk_receiver,
        get_sender_public_key_by_id=get_pub,
    )

    out_name = f"received_{file_id}.bin"
    with open(out_name, "wb") as f:
        f.write(plaintext)

    print("Saved decrypted file as", out_name)

if __name__ == "__main__":
    main()