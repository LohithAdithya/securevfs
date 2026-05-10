import os
import time
import json
import base64
import hashlib
import requests
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuration
API_URL = "http://localhost:8443"
SYNC_DIR = Path("./secure_sync_folder")
USERNAME = "admin"
PASSWORD = "admin_password_here" # In a real app, this would be entered securely

# Cryptography Constants
SALT_LEN = 16
IV_LEN = 12

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password, username, employee_id):
    with open(file_path, "rb") as f:
        data = f.read()
    
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(password, salt)
    
    # AAD: username|employee_id
    aad = f"{username}|{employee_id}".encode()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, aad)
    
    # Format: [SALT][IV][CIPHERTEXT]
    return salt + iv + ciphertext

def sync_file(file_path):
    print(f"[SYNC] Processing {file_path.name}...")
    
    # 1. Login to get employee_id and session_key (for audit/auth)
    # Note: In Zero-Knowledge, the server doesn't know the password,
    # but we need a session token for the API.
    # For simplicity in this demo script, we assume the user is already authenticated
    # or we perform a login call.
    
    # Let's assume we have the session token from a previous login
    # For now, we'll just use a mock flow for the demonstration
    
    try:
        # Mock login to get user details
        # In a real sync app, you'd store the session token securely
        emp_id = "DEV001"
        
        # Encrypt
        enc_data = encrypt_file(file_path, PASSWORD, USERNAME, emp_id)
        
        # Upload
        files = {
            'file': (file_path.name + ".enc", enc_data, 'application/octet-stream')
        }
        data = {
            'username': USERNAME,
            'employee_id': emp_id
        }
        
        # Use a dummy session token for this demo
        headers = {'X-Session-Token': '24a3f1a72250179d347f0bb1d5343dba4d54aee89cfa87cf72c6034706689467'}
        
        resp = requests.post(f"{API_URL}/upload_enc", files=files, data=data, headers=headers)
        
        if resp.status_code == 200:
            print(f"[SUCCESS] {file_path.name} synced to SecureFS.")
        else:
            print(f"[ERROR] Failed to sync {file_path.name}: {resp.text}")
            
    except Exception as e:
        print(f"[CRITICAL] Error syncing {file_path.name}: {str(e)}")

def main():
    if not SYNC_DIR.exists():
        SYNC_DIR.mkdir()
        print(f"[INFO] Created sync directory at {SYNC_DIR.absolute()}")
        
    print(f"--- SecureFS Desktop Sync Client Active ---")
    print(f"Monitoring: {SYNC_DIR.absolute()}")
    
    known_files = {}
    
    while True:
        for f in SYNC_DIR.glob("*"):
            if f.is_file() and not f.name.endswith(".enc"):
                mtime = f.stat().st_mtime
                if f.name not in known_files or known_files[f.name] < mtime:
                    sync_file(f)
                    known_files[f.name] = mtime
        
        time.sleep(5)

if __name__ == "__main__":
    main()
