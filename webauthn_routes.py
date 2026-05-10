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
        {"id": base64url_to_bytes(c["credential_id"]), "type": "public-key"}
        for c in existing
    ]
    
    user_id = db["users"][username].get("employee_id", "EMP000").encode("utf-8")
    
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        attestation="none",
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
    
    target_cred = credentials[0] if credentials else None
    for c in credentials:
        try:
            if credential_data.get("id") == base64url_to_bytes(c["credential_id"]):
                target_cred = c
                break
        except:
            pass

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
