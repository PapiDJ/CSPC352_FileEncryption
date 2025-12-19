from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid

app = FastAPI(title="FileDrop Web Service")

# Same idea as your current server dicts (in-memory). :contentReference[oaicite:2]{index=2}
USERS: dict[str, str] = {}   # user_id -> public_key_pem (string)
FILES: dict[str, dict] = {}  # file_id -> encrypted package (dict)

class RegisterReq(BaseModel):
    user_id: str
    public_key_pem: str

class UploadReq(BaseModel):
    package: dict

@app.get("/")
def info():
    return {
        "service": "File Drop (CSPC 352)",
        "what_server_stores": ["encrypted file packages", "metadata", "public keys"],
        "what_server_never_sees": ["plaintext files", "symmetric keys", "private keys"],
        "crypto": {
            "file_encryption": "AES-GCM",
            "key_wrap": "RSA-OAEP",
            "signature": "RSA-PSS (SHA-256)"
        },
        "docs": "/docs"
    }

@app.post("/register")
def register(req: RegisterReq):
    USERS[req.user_id] = req.public_key_pem
    return {"ok": True}

@app.get("/pubkey/{user_id}")
def get_pubkey(user_id: str):
    pem = USERS.get(user_id)
    if pem is None:
        raise HTTPException(status_code=404, detail="unknown user")
    return {"ok": True, "public_key_pem": pem}

@app.post("/upload")
def upload(req: UploadReq):
    package = req.package
    file_id = package.get("file_id") or str(uuid.uuid4())
    package["file_id"] = file_id
    FILES[file_id] = package
    return {"ok": True, "file_id": file_id}

@app.get("/list/{receiver_id}")
def list_files(receiver_id: str):
    meta = [
        {"file_id": fid, "sender_id": pkg["sender_id"]}
        for fid, pkg in FILES.items()
        if pkg.get("receiver_id") == receiver_id
    ]
    return {"ok": True, "files": meta}

@app.get("/download/{file_id}")
def download(file_id: str):
    pkg = FILES.get(file_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail="no such file")
    return {"ok": True, "package": pkg}