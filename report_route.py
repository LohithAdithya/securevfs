
@app.get("/admin/compliance-report")
async def get_compliance_report(username: str, x_session_token: str = Header(None)):
    db = load_db()
    if username not in db["users"] or db["users"][username]["role"] != "ADMIN":
        raise HTTPException(403, "Admin access required")
    
    if db["users"][username].get("session_key") != x_session_token:
        raise HTTPException(403, "Invalid session")
        
    logs = db.get("audit_log", [])
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
