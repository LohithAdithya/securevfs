
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
