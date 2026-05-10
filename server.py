"""
SecureFS v2 — Python Backend
FastAPI server: AES-256-GCM crypto + Projects + Team Access Control

Usage:
    pip install fastapi uvicorn python-multipart cryptography
    python server.py --http          # HTTP on port 8443 (local dev)
    python server.py --http --port 9000
    python server.py                 # HTTPS (needs cert.pem + key.pem)
"""

import argparse
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile, Body, Request
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential, AuthenticatorSelectionCriteria, AuthenticatorAttachment, UserVerificationRequirement, AttestationConveyancePreference
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, HTMLResponse, RedirectResponse

# ── Directory layout (Bundle Aware) ──────────────────────────────────────────
import sys
if getattr(sys, 'frozen', False):
    # Running in a bundle (.exe)
    BASE_DIR = Path(sys.executable).parent
else:
    # Running in normal python environment
    BASE_DIR = Path(__file__).parent

STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(exist_ok=True)

FILES_DIR = STORAGE_DIR / "files"
FILES_DIR.mkdir(exist_ok=True)
DB_PATH = STORAGE_DIR / "db.json"

# ── Crypto constants (must match frontend exactly) ───────────────────────────
SALT_LEN   = 16
IV_LEN     = 12
ITERATIONS = 100_000
KEY_LEN    = 32
TAG_LEN    = 16

VERSION = "2.1.0"

# ── DB helpers ───────────────────────────────────────────────────────────────
_DB_DEFAULTS = {
    "projects":    {},
    "memberships": {},
    "files":       {},
    "audit":       [],
    "users":       {},
}

def load_db() -> dict:
    if DB_PATH.exists():
        try:
            data = json.loads(DB_PATH.read_text())
            for k, v in _DB_DEFAULTS.items():
                data.setdefault(k, v)
            return data
        except Exception:
            pass
    return {k: (v.copy() if isinstance(v, dict) else list(v)) for k, v in _DB_DEFAULTS.items()}

def save_db(db: dict):
    DB_PATH.write_text(json.dumps(db, indent=2))

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="SecureFS v2 Backend", version=VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-File-Id"],
)

# ── Frontend Hosting ─────────────────────────────────────────────────────────
@app.get("/")
async def serve_frontend():
    # Redirect to the main application page
    return RedirectResponse(url="/ui")

@app.get("/ui")
async def serve_ui():
    # Use resource_path logic to find the HTML inside the bundle
    try:
        base = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).parent
    except:
        base = Path(__file__).parent
        
    html_path = base / "securefs_v2 (1).html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return {"message": f"Frontend HTML not found at {html_path}"}

# ── Audit log (in-memory + persisted) ────────────────────────────────────────
_boot_db = load_db()
audit_log: list[dict] = _boot_db.get("audit", [])

def log_event(action: str, username: str, detail: str, status: str, project_id: str = ""):
    entry = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "action":     action,
        "user":       username,
        "detail":     detail,
        "status":     status,
        "project_id": project_id,
    }
    audit_log.append(entry)
    print(f"[{entry['timestamp']}] {action} | {username} | {detail} | {status}")
    try:
        db = load_db()
        db["audit"] = audit_log[-500:]
        save_db(db)
    except Exception:
        pass
    return entry


# ── Crypto helpers ───────────────────────────────────────────────────────────

def derive_file_key(session_key: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITERATIONS)
    return kdf.derive(session_key)

def build_aad(username: str, employee_id: str) -> bytes:
    return f"{username}|{employee_id}".encode()

def encrypt_bytes(plaintext: bytes, session_key_hex: str, username: str, employee_id: str, project_key_hex: str = "", project_id: str = "") -> bytes:
    if project_key_hex and project_id:
        sk = bytes.fromhex(project_key_hex)
        aad = project_id.encode()
    else:
        sk = bytes.fromhex(session_key_hex)
        aad = build_aad(username, employee_id)
        
    salt = os.urandom(SALT_LEN)
    iv   = os.urandom(IV_LEN)
    key  = derive_file_key(sk, salt)
    ct   = AESGCM(key).encrypt(iv, plaintext, aad)
    return salt + iv + ct

def decrypt_bytes(blob: bytes, session_key_hex: str, username: str, employee_id: str, project_key_hex: str = "", project_id: str = "") -> bytes:
    if len(blob) < SALT_LEN + IV_LEN + TAG_LEN:
        raise ValueError("File too short — not a valid .enc file")
    
    if project_key_hex and project_id:
        sk = bytes.fromhex(project_key_hex)
        aad = project_id.encode()
    else:
        sk = bytes.fromhex(session_key_hex)
        aad = build_aad(username, employee_id)
        
    salt = blob[:SALT_LEN]
    iv   = blob[SALT_LEN:SALT_LEN + IV_LEN]
    ct   = blob[SALT_LEN + IV_LEN:]
    key  = derive_file_key(sk, salt)
    return AESGCM(key).decrypt(iv, ct, aad)


# ── Access helpers ───────────────────────────────────────────────────────────

def get_member_role(db: dict, project_id: str, username: str) -> Optional[str]:
    return db["memberships"].get(project_id, {}).get(username)

def require_member(db: dict, project_id: str, username: str, min_role: str = "viewer"):
    roles_order = ["viewer", "editor", "owner"]
    role = get_member_role(db, project_id, username)
    if role is None:
        raise HTTPException(status_code=403, detail="Not a member of this project.")
    if roles_order.index(role) < roles_order.index(min_role):
        raise HTTPException(status_code=403, detail=f"Requires '{min_role}' role or higher.")

def safe_id(raw: str) -> str:
    return "".join(c for c in raw if c.isalnum() or c in "_-")

def escrow_key(db: dict, username: str, session_key_hex: str, employee_id: str):
    if "users" not in db:
        db["users"] = {}
    if username not in db["users"]:
        db["users"][username] = {"role": "DEVELOPER"}
    db["users"][username]["session_key"] = session_key_hex
    db["users"][username]["employee_id"] = employee_id


# ════════════════════════════════════════════════════════════════════════════
# BASIC ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.get("/ping")
async def ping():
    db = load_db()
    return {
        "status":       "ok",
        "version":      VERSION,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "projects":     len(db["projects"]),
        "files":        len(db["files"]),
        "audit_events": len(audit_log),
    }

@app.get("/audit")
async def get_audit_log():
    return {"events": list(reversed(audit_log[-200:])), "count": len(audit_log)}


# ════════════════════════════════════════════════════════════════════════════
# USERS & AUTHENTICATION
# ════════════════════════════════════════════════════════════════════════════

@app.get("/users")
async def list_users():
    db = load_db()
    users = db.get("users", {})
    # Strip sensitive data for the list
    safe_users = {}
    for uname, u in users.items():
        safe_users[uname] = {
            "employeeId": u.get("employee_id", ""),
            "role": u.get("role", "VIEWER"),
            "locked": u.get("locked", False)
        }
    return safe_users

@app.get("/users/{username}/salt")
async def get_user_salt(username: str):
    db = load_db()
    user = db.get("users", {}).get(username)
    if not user or not user.get("salt"):
        raise HTTPException(status_code=404, detail="User not found or salt missing")
    return {"salt": user["salt"]}

@app.post("/login")
async def login_user(payload: dict = Body(...)):
    username = payload.get("username", "")
    password_hash = payload.get("password_hash", "")
    db = load_db()
    
    if username not in db.get("users", {}):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user = db["users"][username]
    if user.get("locked", False):
        raise HTTPException(status_code=403, detail="Account is locked")
        
    if user.get("password_hash") != password_hash:
        # Increment failed attempts
        fails = user.get("failed_attempts", 0) + 1
        user["failed_attempts"] = fails
        if fails >= 5:
            user["locked"] = True
            save_db(db)
            raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts")
        save_db(db)
        raise HTTPException(status_code=401, detail=f"Invalid username or password. {5-fails} attempts remaining.")
        
    # Success
    user["failed_attempts"] = 0
    save_db(db)
    return {
        "status": "ok",
        "username": username,
        "role": user.get("role", "VIEWER"),
        "employeeId": user.get("employee_id", "")
    }

@app.post("/users")
async def create_user(payload: dict = Body(...)):
    username = payload.get("username", "")
    if not username:
        raise HTTPException(status_code=422, detail="Username required")
        
    db = load_db()
    if "users" not in db:
        db["users"] = {}
        
    if username in db["users"] and db["users"][username].get("salt"):
        raise HTTPException(status_code=400, detail="User already exists")
        
    db["users"][username] = {
        "employee_id": payload.get("employeeId", ""),
        "role": payload.get("role", "VIEWER"),
        "salt": payload.get("salt", ""),
        "password_hash": payload.get("password_hash", ""),
        "locked": False,
        "failed_attempts": 0
    }
    save_db(db)
    return {"status": "ok", "username": username}

@app.patch("/users/{username}")
async def update_user(username: str, payload: dict = Body(...)):
    db = load_db()
    if username not in db.get("users", {}):
        raise HTTPException(status_code=404, detail="User not found")
        
    user = db["users"][username]
    if "role" in payload:
        user["role"] = payload["role"]
    if "locked" in payload:
        user["locked"] = payload["locked"]
        if not payload["locked"]:
            user["failed_attempts"] = 0
    if "password_hash" in payload:
        user["password_hash"] = payload["password_hash"]
    if "salt" in payload:
        user["salt"] = payload["salt"]
        
    save_db(db)
    return {"status": "ok", "username": username}

@app.delete("/users/{username}")
async def delete_user(username: str):
    db = load_db()
    if username not in db.get("users", {}):
        raise HTTPException(status_code=404, detail="User not found")
        
    del db["users"][username]
    save_db(db)
    return {"status": "ok"}



# ════════════════════════════════════════════════════════════════════════════
# ENCRYPT / DECRYPT / VERIFY
# ════════════════════════════════════════════════════════════════════════════

@app.post("/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    username: str    = Form(...),
    employee_id: str = Form(...),
    project_id: str  = Form(default=""),
    expires_at: str  = Form(default=""),
    max_views: int   = Form(default=0),
    x_session_token: str = Header(..., alias="X-Session-Token"),
):
    plaintext     = await file.read()
    original_name = file.filename or "file"

    db = load_db()
    pid = project_id.strip() if project_id else ""
    project_key_hex = ""

    if pid:
        if pid not in db["projects"]:
            raise HTTPException(status_code=404, detail="Project not found.")
        require_member(db, pid, username, "editor")
        project_key_hex = db["projects"][pid].get("project_key", "")

    try:
        encrypted = encrypt_bytes(plaintext, x_session_token, username, employee_id, project_key_hex, pid)
    except Exception as e:
        log_event("ENCRYPT", username, original_name, "FAILED", pid)
        raise HTTPException(status_code=400, detail=f"Encryption error: {e}")

    file_id  = f"{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"
    enc_name = original_name + ".enc"
    enc_hash = hashlib.sha256(encrypted).hexdigest()

    (FILES_DIR / f"{file_id}.enc").write_bytes(encrypted)

    meta = {
        "id":             file_id,
        "original_name":  original_name,
        "enc_name":       enc_name,
        "size":           len(encrypted),
        "enc_hash":       enc_hash,
        "encrypted_by":   username,
        "time":           datetime.now(timezone.utc).isoformat(),
        "project_id":     pid or None,
        "expires_at":     expires_at if expires_at else None,
        "max_views":      max_views if max_views > 0 else None,
        "download_count": 0,
        "last_download":  None,
        "last_accessed":  datetime.now(timezone.utc).isoformat(),
    }
    db["files"][file_id] = meta
    escrow_key(db, username, x_session_token, employee_id)
    save_db(db)
    log_event("ENCRYPT", username, original_name, "OK", pid)

    return Response(
        content=encrypted,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{enc_name}"',
            "X-File-Id": file_id,
        },
    )


@app.post("/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    username: str    = Form(...),
    employee_id: str = Form(...),
    project_id: str  = Form(default=""),
    x_session_token: str = Header(..., alias="X-Session-Token"),
):
    blob     = await file.read()
    enc_name = file.filename or "file.enc"
    out_name = enc_name.removesuffix(".enc") or "decrypted.bin"

    pid = project_id.strip() if project_id else ""
    project_key_hex = ""
    if pid:
        db = load_db()
        if pid not in db["projects"]:
            raise HTTPException(status_code=404, detail="Project not found.")
        require_member(db, pid, username, "viewer")
        project_key_hex = db["projects"][pid].get("project_key", "")

    try:
        plaintext = decrypt_bytes(blob, x_session_token, username, employee_id, project_key_hex, pid)
    except Exception as e:
        log_event("DECRYPT", username, enc_name, "FAILED")
        raise HTTPException(status_code=400, detail=f"Decryption failed — tampered file, wrong identity, or wrong session key. ({e})")

    log_event("DECRYPT", username, enc_name, "OK")
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )


@app.post("/verify")
async def verify_file(
    file: UploadFile = File(...),
    username: str    = Form(...),
    employee_id: str = Form(...),
    project_id: str  = Form(default=""),
    x_session_token: str = Header(..., alias="X-Session-Token"),
):
    blob     = await file.read()
    enc_name = file.filename or "file.enc"

    pid = project_id.strip() if project_id else ""
    project_key_hex = ""
    if pid:
        db = load_db()
        if pid in db["projects"] and get_member_role(db, pid, username) is not None:
            project_key_hex = db["projects"][pid].get("project_key", "")

    try:
        decrypt_bytes(blob, x_session_token, username, employee_id, project_key_hex, pid)
        valid = True
    except Exception:
        valid = False

    escrow_key(db, username, x_session_token, employee_id)
    save_db(db)

    log_event("VERIFY", username, enc_name, "PASSED" if valid else "FAILED")
    return {
        "valid":     valid,
        "status":    "ok" if valid else "fail",
        "file":      enc_name,
        "user":      username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/files/{file_id}/share")
async def share_file(
    file_id: str,
    project_id: str = Form(...),
    username: str = Form(...),
    employee_id: str = Form(...),
    x_session_token: str = Header(..., alias="X-Session-Token")
):
    pid = safe_id(project_id)
    fid = safe_id(file_id)
    db = load_db()

    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    
    require_member(db, pid, username, "editor")

    if fid not in db["files"]:
        raise HTTPException(status_code=404, detail="File not found in history.")
    
    file_meta = db["files"][fid]

    if file_meta.get("project_id"):
        raise HTTPException(status_code=400, detail="File is already assigned to a project.")

    blob_path = FILES_DIR / f"{fid}.enc"
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="Encrypted file missing from disk.")

    blob = blob_path.read_bytes()

    try:
        plaintext = decrypt_bytes(blob, x_session_token, username, employee_id)
    except Exception as e:
        log_event("SHARE_FILE", username, file_meta["original_name"], "FAILED", pid)
        raise HTTPException(status_code=400, detail=f"Failed to decrypt personal file. ({e})")

    project_key_hex = db["projects"][pid].get("project_key", "")
    if not project_key_hex:
        raise HTTPException(status_code=500, detail="Project is missing a master key.")

    try:
        new_encrypted = encrypt_bytes(plaintext, "", username, employee_id, project_key_hex, pid)
    except Exception as e:
        log_event("SHARE_FILE", username, file_meta["original_name"], "FAILED", pid)
        raise HTTPException(status_code=500, detail=f"Failed to re-encrypt file for project. ({e})")

    blob_path.write_bytes(new_encrypted)
    
    file_meta["project_id"] = pid
    file_meta["enc_hash"] = hashlib.sha256(new_encrypted).hexdigest()
    file_meta["size"] = len(new_encrypted)
    file_meta["time"] = datetime.now(timezone.utc).isoformat()
    file_meta["last_accessed"] = datetime.now(timezone.utc).isoformat()
    db["files"][fid] = file_meta
    escrow_key(db, username, x_session_token, employee_id)
    save_db(db)

    log_event("SHARE_FILE", username, file_meta["original_name"], "OK", pid)
    return {"status": "success", "file": file_meta}


# ════════════════════════════════════════════════════════════════════════════
# FILE HISTORY
# ════════════════════════════════════════════════════════════════════════════

def check_ephemeral(db: dict, meta: dict, file_id: str):
    deleted = False
    if meta.get("expires_at"):
        try:
            exp = datetime.fromisoformat(meta["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                deleted = True
        except:
            pass
            
    if meta.get("max_views") is not None and meta.get("max_views") > 0:
        if meta.get("download_count", 0) >= meta["max_views"]:
            deleted = True
            
    if deleted:
        blob_path = FILES_DIR / f"{file_id}.enc"
        if blob_path.exists():
            blob_path.unlink()
        if file_id in db["files"]:
            del db["files"][file_id]
        save_db(db)
        log_event("EPHEMERAL_DELETE", "system", meta["original_name"], "OK", meta.get("project_id", ""))
        return True
    return False

@app.get("/files")
async def list_files(username: str = "", is_admin: bool = False):
    db = load_db()
    result = []
    
    # Verify admin claim against actual DB role (don't trust the client)
    verified_admin = False
    if is_admin and username:
        user_data = db.get("users", {}).get(username, {})
        verified_admin = user_data.get("role") in ["ADMIN", "DEVELOPER"]
    
    # Lazily delete expired files
    for fid in list(db["files"].keys()):
        if check_ephemeral(db, db["files"][fid], fid):
            continue
            
    for fid, meta in db["files"].items():
        owner = meta.get("encrypted_by", "")
        owner_sk = ""
        owner_emp = ""
        if verified_admin and owner in db.get("users", {}):
            owner_sk = db["users"][owner].get("session_key", "")
            owner_emp = db["users"][owner].get("employee_id", "")

        pid = meta.get("project_id")
        file_info = {
            **meta, 
            "owner_session_key": owner_sk, 
            "owner_employee_id": owner_emp
        }
        
        if pid:
            if verified_admin or (username and get_member_role(db, pid, username) is not None):
                proj = db["projects"].get(pid, {})
                result.append({**file_info, "project_name": proj.get("name", ""), "project_color": proj.get("color", "")})
        else:
            if verified_admin or not username or owner == username:
                result.append({**file_info, "project_name": None, "project_color": None})
    result.sort(key=lambda m: m.get("time", ""), reverse=True)
    return {"files": result, "count": len(result)}


@app.get("/files/{file_id}")
async def download_file(file_id: str, username: str = ""):
    fid  = safe_id(file_id)
    db   = load_db()
    meta = db["files"].get(fid)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found in registry.")

    if check_ephemeral(db, meta, fid):
        raise HTTPException(status_code=410, detail="File has self-destructed due to view limits or expiration.")

    blob_path = FILES_DIR / f"{fid}.enc"
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="File blob missing on disk.")

    pid = meta.get("project_id")
    if pid and username:
        require_member(db, pid, username)

    meta["download_count"] = meta.get("download_count", 0) + 1
    meta["last_download"]  = datetime.now(timezone.utc).isoformat()
    meta["last_accessed"]  = datetime.now(timezone.utc).isoformat()
    save_db(db)
    log_event("DOWNLOAD", username or "anon", meta["original_name"], "OK", pid or "")

    return Response(
        content=blob_path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{meta["enc_name"]}"'},
    )


@app.delete("/files/{file_id}")
async def delete_file(file_id: str, username: str = ""):
    fid  = safe_id(file_id)
    db   = load_db()
    meta = db["files"].get(fid)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found.")

    # Admins can delete any file
    user_role = db.get("users", {}).get(username, {}).get("role", "")
    is_admin = user_role in ["ADMIN", "DEVELOPER"]

    pid = meta.get("project_id")
    if not is_admin:
        if pid and username:
            require_member(db, pid, username, "editor")
        elif username and meta.get("encrypted_by") != username:
            raise HTTPException(status_code=403, detail="Only the uploader or an admin can delete this file.")

    blob_path = FILES_DIR / f"{fid}.enc"
    if blob_path.exists():
        blob_path.unlink()

    del db["files"][fid]
    save_db(db)
    log_event("DELETE_FILE", username, meta["original_name"], "OK", pid or "")
    return {"deleted": fid}


@app.get("/admin/decrypt/{file_id}")
async def admin_decrypt_file(
    file_id: str,
    admin_username: str
):
    db = load_db()
    
    # Enforce admin role — only ADMIN/DEVELOPER can use admin decrypt
    admin_user = db.get("users", {}).get(admin_username)
    if not admin_user or admin_user.get("role") not in ["ADMIN", "DEVELOPER"]:
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    
    fid = safe_id(file_id)
    if fid not in db["files"]:
        raise HTTPException(status_code=404, detail="File not found")
    meta = db["files"][fid]
    owner_username = meta["encrypted_by"]
    
    if "users" not in db or owner_username not in db["users"]:
        raise HTTPException(status_code=400, detail="Owner's session key is not escrowed on the server.")
    
    owner_info = db["users"][owner_username]
    owner_sk = owner_info["session_key"]
    owner_emp = owner_info["employee_id"]

    blob_path = FILES_DIR / f"{fid}.enc"
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="File missing from disk.")
        
    blob = blob_path.read_bytes()
    pid = meta.get("project_id", "")
    project_key_hex = db["projects"][pid].get("project_key", "") if pid else ""

    try:
        plaintext = decrypt_bytes(blob, owner_sk, owner_username, owner_emp, project_key_hex, pid)
    except Exception as e:
        log_event("ADMIN_DECRYPT", admin_username, meta["original_name"], "FAILED", pid)
        raise HTTPException(status_code=400, detail=f"Admin decryption failed: {e}")

    meta["last_accessed"] = datetime.now(timezone.utc).isoformat()
    save_db(db)
    
    log_event("ADMIN_DECRYPT", admin_username, meta["original_name"], "OK", pid)
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{meta["original_name"]}"'}
    )


@app.post("/admin/decrypt_local")
async def admin_decrypt_local_file(
    file: UploadFile = File(...),
    admin_username: str = Form(...),
    owner_username: str = Form(...),
    x_session_token: str = Header(..., alias="X-Session-Token")
):
    db = load_db()
    if "users" not in db or owner_username not in db["users"]:
        raise HTTPException(status_code=400, detail="Owner's session key is not escrowed on the server.")
    
    owner_info = db["users"][owner_username]
    owner_sk = owner_info["session_key"]
    owner_emp = owner_info["employee_id"]

    blob = await file.read()
    
    try:
        plaintext = decrypt_bytes(blob, owner_sk, owner_username, owner_emp, "", "")
    except Exception as e:
        log_event("ADMIN_DECRYPT_LOCAL", admin_username, file.filename, "FAILED")
        raise HTTPException(status_code=400, detail=f"Admin local decryption failed: {e}")

    out_name = (file.filename or "decrypted_file").removesuffix(".enc") or "decrypted_file"
    log_event("ADMIN_DECRYPT_LOCAL", admin_username, file.filename, "OK")
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'}
    )


# ════════════════════════════════════════════════════════════════════════════
# PROJECTS
# ════════════════════════════════════════════════════════════════════════════

PROJECT_COLORS = [
    "#38bdf8", "#34d399", "#f472b6", "#fbbf24",
    "#a78bfa", "#fb923c", "#22d3ee", "#60a5fa",
]

@app.post("/projects")
async def create_project(payload: dict = Body(...)):
    username = payload.get("username", "").strip()
    name     = payload.get("name", "").strip()
    if not username or not name:
        raise HTTPException(status_code=422, detail="username and name are required.")

    db  = load_db()
    pid = uuid.uuid4().hex[:12]

    project = {
        "id":          pid,
        "name":        name,
        "description": payload.get("description", ""),
        "color":       payload.get("color", PROJECT_COLORS[len(db["projects"]) % len(PROJECT_COLORS)]),
        "owner":       username,
        "created":     datetime.now(timezone.utc).isoformat(),
        "project_key": os.urandom(32).hex()
    }
    db["projects"][pid]              = project
    db["memberships"].setdefault(pid, {})[username] = "owner"
    save_db(db)
    log_event("CREATE_PROJECT", username, name, "OK", pid)
    return project


@app.get("/projects")
async def list_projects(username: str = ""):
    db = load_db()
    result = []
    for pid, proj in db["projects"].items():
        members = db["memberships"].get(pid, {})
        if not username or username in members:
            file_count = sum(1 for f in db["files"].values() if f.get("project_id") == pid)
            result.append({
                **proj,
                "my_role":      members.get(username, "viewer") if username else "owner",
                "member_count": len(members),
                "file_count":   file_count,
                "members":      [{"username": u, "role": r} for u, r in members.items()],
            })
    result.sort(key=lambda p: p.get("created", ""), reverse=True)
    return {"projects": result, "count": len(result)}


@app.get("/projects/{project_id}")
async def get_project(project_id: str, username: str = ""):
    pid = safe_id(project_id)
    db  = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    if username:
        require_member(db, pid, username)

    proj    = db["projects"][pid]
    members = db["memberships"].get(pid, {})
    files   = [f for f in db["files"].values() if f.get("project_id") == pid]
    files.sort(key=lambda f: f.get("time", ""), reverse=True)

    return {
        **proj,
        "my_role":    members.get(username, "viewer") if username else "owner",
        "members":    [{"username": u, "role": r} for u, r in members.items()],
        "files":      files,
        "file_count": len(files),
    }


@app.patch("/projects/{project_id}")
async def update_project(project_id: str, payload: dict = Body(...)):
    pid      = safe_id(project_id)
    username = payload.get("username", "")
    db       = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    if username:
        require_member(db, pid, username, "editor")

    proj = db["projects"][pid]
    for field in ("name", "description", "color"):
        if field in payload:
            proj[field] = payload[field]
    save_db(db)
    log_event("UPDATE_PROJECT", username, proj["name"], "OK", pid)
    return proj


@app.delete("/projects/{project_id}")
async def delete_project(project_id: str, username: str = ""):
    pid = safe_id(project_id)
    db  = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    if username:
        require_member(db, pid, username, "owner")

    proj_name = db["projects"][pid]["name"]

    for fid, meta in list(db["files"].items()):
        if meta.get("project_id") == pid:
            blob = FILES_DIR / f"{fid}.enc"
            if blob.exists():
                blob.unlink()
            del db["files"][fid]

    del db["projects"][pid]
    db["memberships"].pop(pid, None)
    save_db(db)
    log_event("DELETE_PROJECT", username, proj_name, "OK", pid)
    return {"deleted": pid}


@app.get("/projects/{project_id}/files")
async def list_project_files(project_id: str, username: str = ""):
    pid = safe_id(project_id)
    db  = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    if username:
        require_member(db, pid, username)

    files = [f for f in db["files"].values() if f.get("project_id") == pid]
    files.sort(key=lambda f: f.get("time", ""), reverse=True)
    return {"files": files, "count": len(files)}


@app.post("/projects/{project_id}/files")
async def upload_to_project(
    project_id: str,
    file: UploadFile = File(...),
    username: str    = Form(...),
    employee_id: str = Form(...),
    x_session_token: str = Header(..., alias="X-Session-Token"),
):
    pid = safe_id(project_id)
    db  = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    require_member(db, pid, username, "editor")

    plaintext     = await file.read()
    original_name = file.filename or "file"

    try:
        project_key_hex = db["projects"][pid]["project_key"]
        encrypted = encrypt_bytes(plaintext, x_session_token, username, employee_id, project_key_hex, pid)
    except Exception as e:
        log_event("ENCRYPT", username, original_name, "FAILED", pid)
        raise HTTPException(status_code=400, detail=f"Encryption error: {e}")

    file_id  = f"{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"
    enc_name = original_name + ".enc"
    enc_hash = hashlib.sha256(encrypted).hexdigest()

    (FILES_DIR / f"{file_id}.enc").write_bytes(encrypted)

    meta = {
        "id":             file_id,
        "original_name":  original_name,
        "enc_name":       enc_name,
        "size":           len(encrypted),
        "enc_hash":       enc_hash,
        "encrypted_by":   username,
        "time":           datetime.now(timezone.utc).isoformat(),
        "project_id":     pid,
        "download_count": 0,
        "last_download":  None,
    }
    db["files"][file_id] = meta
    save_db(db)
    log_event("ENCRYPT", username, original_name, "OK", pid)

    return Response(
        content=encrypted,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{enc_name}"',
            "X-File-Id": file_id,
        },
    )


# ── Project membership ────────────────────────────────────────────────────────

@app.post("/projects/{project_id}/members")
async def add_member(project_id: str, payload: dict = Body(...)):
    pid          = safe_id(project_id)
    requester    = payload.get("username", "").strip()
    new_username = payload.get("new_username", "").strip()
    role         = payload.get("role", "viewer")

    if role not in ("viewer", "editor", "owner"):
        raise HTTPException(status_code=422, detail="role must be viewer, editor, or owner.")
    if not new_username:
        raise HTTPException(status_code=422, detail="new_username is required.")

    db = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")

    requester_role = get_member_role(db, pid, requester)
    if requester_role not in ("owner", "editor"):
        raise HTTPException(status_code=403, detail="Only owners/editors can add members.")
    if role in ("editor", "owner") and requester_role != "owner":
        raise HTTPException(status_code=403, detail="Only owners can grant editor/owner roles.")

    db["memberships"].setdefault(pid, {})[new_username] = role
    save_db(db)
    log_event("ADD_MEMBER", requester, f"{new_username}→{role}", "OK", pid)
    return {"project_id": pid, "username": new_username, "role": role}


@app.delete("/projects/{project_id}/members/{target_username}")
async def remove_member(project_id: str, target_username: str, username: str = ""):
    pid    = safe_id(project_id)
    target = safe_id(target_username)
    db     = load_db()

    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")

    if username:
        my_role = get_member_role(db, pid, username)
        if my_role != "owner" and username != target:
            raise HTTPException(status_code=403, detail="Only owners can remove other members.")

    members = db["memberships"].get(pid, {})
    if target not in members:
        raise HTTPException(status_code=404, detail="Member not found.")

    owners = [u for u, r in members.items() if r == "owner"]
    if target in owners and len(owners) == 1:
        raise HTTPException(status_code=400, detail="Cannot remove the last owner.")

    del members[target]
    save_db(db)
    log_event("REMOVE_MEMBER", username or target, target, "OK", pid)
    return {"removed": target, "project_id": pid}


@app.patch("/projects/{project_id}/members/{target_username}")
async def update_member_role(project_id: str, target_username: str, payload: dict = Body(...)):
    pid    = safe_id(project_id)
    target = safe_id(target_username)
    role   = payload.get("role", "viewer")
    actor  = payload.get("username", "")

    if role not in ("viewer", "editor", "owner"):
        raise HTTPException(status_code=422, detail="Invalid role.")

    db = load_db()
    if pid not in db["projects"]:
        raise HTTPException(status_code=404, detail="Project not found.")
    if actor:
        require_member(db, pid, actor, "owner")

    members = db["memberships"].get(pid, {})
    if target not in members:
        raise HTTPException(status_code=404, detail="Member not found.")

    members[target] = role
    save_db(db)
    log_event("UPDATE_ROLE", actor, f"{target}→{role}", "OK", pid)
    return {"project_id": pid, "username": target, "role": role}


# ════════════════════════════════════════════════════════════════════════════
from webauthn import options_to_json, base64url_to_bytes

# -----------------------------------------------------------------------------
# WEBAUTHN ENDPOINTS
# -----------------------------------------------------------------------------
RP_NAME = "SecureFS"

def get_rp_id(request: Request) -> str:
    origin = request.headers.get("origin", "")
    if origin.startswith("https://"):
        return origin.split("https://")[1].split(":")[0]
    elif origin.startswith("http://"):
        return origin.split("http://")[1].split(":")[0]
    return "localhost"

def get_origin(request: Request) -> str:
    origin = request.headers.get("origin", "")
    return origin if origin else "http://localhost:8443"

@app.post("/webauthn/register/generate-options")
async def webauthn_register_generate(request: Request, body: dict = Body(...)):
    username = body.get("username")
    x_session_token = request.headers.get("X-Session-Token", "")
    
    db = load_db()
    if username not in db["users"]:
        raise HTTPException(404, "User not found")
        
    if db["users"][username].get("session_key") != x_session_token:
        raise HTTPException(403, "Invalid session token")

    rp_id = get_rp_id(request)
    existing = db["users"][username].get("webauthn_credentials", [])
    exclude_credentials = [
        {"id": bytes.fromhex(c["credential_id"]), "type": "public-key"}
        for c in existing
    ]
    
    user_id = db["users"][username].get("employee_id", "EMP000").encode("utf-8")
    
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude_credentials,
    )
    
    db["users"][username]["webauthn_challenge"] = options.challenge.hex()
    save_db(db)
    
    return json.loads(options_to_json(options))

@app.post("/webauthn/register/verify")
async def webauthn_register_verify(request: Request, body: dict = Body(...)):
    username = body.get("username")
    credential_data = body.get("credential")
    x_session_token = request.headers.get("X-Session-Token", "")
    
    db = load_db()
    if username not in db["users"] or db["users"][username].get("session_key") != x_session_token:
        raise HTTPException(403, "Invalid user or session token")
        
    challenge_hex = db["users"][username].get("webauthn_challenge")
    if not challenge_hex:
        raise HTTPException(400, "No active challenge")
        
    rp_id = get_rp_id(request)
    origin = get_origin(request)
    
    try:
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=bytes.fromhex(challenge_hex),
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {str(e)}")
        
    if "webauthn_credentials" not in db["users"][username]:
        db["users"][username]["webauthn_credentials"] = []
        
    db["users"][username]["webauthn_credentials"].append({
        "credential_id": verification.credential_id.hex(),
        "public_key": verification.credential_public_key.hex(),
        "sign_count": verification.sign_count
    })
    
    db["users"][username]["webauthn_challenge"] = ""
    save_db(db)
    
    log_event("WEBAUTHN_REGISTER", username, "Registered new biometric authenticator", "OK", "SYSTEM")
    return {"status": "success"}

@app.post("/webauthn/login/generate-options")
async def webauthn_login_generate(request: Request, body: dict = Body(...)):
    username = body.get("username")
    db = load_db()
    if username not in db["users"]:
        raise HTTPException(404, "User not found")
        
    credentials = db["users"][username].get("webauthn_credentials", [])
    if not credentials:
        raise HTTPException(400, "No biometric credentials registered")
        
    allow_credentials = [
        {"id": bytes.fromhex(c["credential_id"]), "type": "public-key"}
        for c in credentials
    ]
    
    rp_id = get_rp_id(request)
    
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    
    db["users"][username]["webauthn_challenge"] = options.challenge.hex()
    save_db(db)
    
    return json.loads(options_to_json(options))

@app.post("/webauthn/login/verify")
async def webauthn_login_verify(request: Request, body: dict = Body(...)):
    username = body.get("username")
    credential_data = body.get("credential")
    
    db = load_db()
    if username not in db["users"]:
        raise HTTPException(404, "User not found")
        
    challenge_hex = db["users"][username].get("webauthn_challenge")
    if not challenge_hex:
        raise HTTPException(400, "No active challenge")
        
    credentials = db["users"][username].get("webauthn_credentials", [])
    
    rp_id = get_rp_id(request)
    origin = get_origin(request)
    
    target_cred = None
    cred_id_bytes = base64url_to_bytes(credential_data.get("id"))
    for c in credentials:
        if cred_id_bytes == bytes.fromhex(c["credential_id"]):
            target_cred = c
            break

    if not target_cred:
        raise HTTPException(400, "Credential mismatch")

    try:
        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=bytes.fromhex(challenge_hex),
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes.fromhex(target_cred["public_key"]),
            credential_current_sign_count=target_cred["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        log_event("WEBAUTHN_LOGIN", username, "Biometric login failed", "FAILED", "SYSTEM")
        raise HTTPException(400, f"Login failed: {str(e)}")
        
    for c in db["users"][username]["webauthn_credentials"]:
        if c["credential_id"] == verification.credential_id.hex():
            c["sign_count"] = verification.new_sign_count
            break
            
    db["users"][username]["webauthn_challenge"] = ""
    save_db(db)
    
    log_event("WEBAUTHN_LOGIN", username, "Biometric login successful", "OK", "SYSTEM")
    
    session_key = db["users"][username]["session_key"]
    return {
        "status": "success",
        "session_key": session_key,
        "employee_id": db["users"][username]["employee_id"],
        "role": db["users"][username]["role"],
    }


# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="SecureFS v2 Backend")
    parser.add_argument("--http",   action="store_true", help="Run plain HTTP (no TLS)")
    parser.add_argument("--port",   type=int, default=8443)
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    ssl_kwargs = {}
    if not args.http:
        if os.path.exists("cert.pem") and os.path.exists("key.pem"):
            ssl_kwargs = {"ssl_certfile": "cert.pem", "ssl_keyfile": "key.pem"}
        else:
            print("[WARNING] cert.pem / key.pem not found - falling back to HTTP.")

    scheme = "http" if (args.http or not ssl_kwargs) else "https"
    print(f"\n[SecureFS v2.1 Backend]  -  {scheme}://{args.host}:{args.port}")
    print(f"   Ping:     {scheme}://localhost:{args.port}/ping")
    print(f"   Audit:    {scheme}://localhost:{args.port}/audit")
    print(f"   Projects: {scheme}://localhost:{args.port}/projects")
    print(f"   Docs:     {scheme}://localhost:{args.port}/docs\n")

    uvicorn.run("server:app", host=args.host, port=args.port, reload=args.reload, **ssl_kwargs)

@app.get("/admin/compliance-report")
async def get_compliance_report(username: str, x_session_token: str = Header(None)):
    db = load_db()
    if username not in db["users"] or db["users"][username]["role"] not in ["ADMIN", "DEVELOPER", "AUDITOR"]:
        raise HTTPException(403, "Compliance report access required")
    
    if db["users"][username].get("session_key") != x_session_token:
        raise HTTPException(403, "Invalid session")
        
    logs = db.get("audit", [])
    bc = db.get("blockchain", [])
    
    # Simple integrity check
    integrity = True
    for i in range(1, len(bc)):
        if bc[i]["previousHash"] != bc[i-1]["hash"]:
            integrity = False
            break
            
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_events": len(logs),
        "user_activity": {},
        "action_distribution": {},
        "integrity_check": "OK" if integrity else "FAILED",
        "blockchain_depth": len(bc),
        "high_risk_events": [l for l in logs if l.get("status") == "FAILED"][-10:]
    }
    
    for l in logs:
        u = l.get("user", "unknown")
        report["user_activity"][u] = report["user_activity"].get(u, 0) + 1
        a = l.get("action", "unknown")
        report["action_distribution"][a] = report["action_distribution"].get(a, 0) + 1
        
    return report

@app.post("/upload_enc")
async def upload_encrypted_file(
    file: UploadFile = File(...),
    username: str    = Form(...),
    employee_id: str = Form(...),
    project_id: str  = Form(default=""),
    x_session_token: str = Header(None)
):
    db = load_db()
    if username not in db["users"] or db["users"][username].get("session_key") != x_session_token:
        raise HTTPException(403, "Invalid session")
        
    content = await file.read()
    file_id = f"{int(time.time()*1000)}_{os.urandom(4).hex()}"
    
    # Save to storage/vault/
    vault_path = os.path.join("storage", "vault")
    os.makedirs(vault_path, exist_ok=True)
    with open(os.path.join(vault_path, file_id), "wb") as f:
        f.write(content)
        
    # Register in DB
    entry = {
        "id": file_id,
        "original_name": file.filename.replace(".enc", ""),
        "enc_name": file.filename,
        "size": len(content),
        "enc_hash": hashlib.sha256(content).hexdigest(),
        "encrypted_by": username,
        "time": datetime.utcnow().isoformat(),
        "project_id": project_id if project_id else None,
        "expires_at": None,
        "max_views": None,
        "download_count": 0
    }
    db["files"][file_id] = entry
    save_db(db)
    
    log_event("SYNC_UPLOAD", username, file.filename, "OK", project_id)
    return {"status": "ok", "file_id": file_id}
