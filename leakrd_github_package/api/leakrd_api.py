from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn, os, json, re
from typing import List
from datetime import datetime
import pathlib, sys
    # add project root to path
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    # import scanning logic from app.leakrd_model_full (note: file must be present)
try:
    from app.leakrd_model_full import scan_text, scan_local_folder, FINDINGS, process_candidate, request_revoke_in_memory
except Exception as e:
        # lightweight fallback if import fails
    scan_text = lambda txt, source='api', location='api': []
    scan_local_folder = lambda folder: []
    FINDINGS = []
    process_candidate = lambda *a, **k: {}
    request_revoke_in_memory = lambda *a, **k: {"id":0}

app = FastAPI(title="LeakRd API", description="Detection endpoints (demo)")

class ScanRequest(BaseModel):
    text: str
    source: str = "api"
    location: str = "api_payload"

@app.post("/scan", summary="Scan text payload for leaks")
def scan_endpoint(req: ScanRequest):
        if not req.text:
            raise HTTPException(status_code=400, detail="empty text")
        items = scan_text(req.text, source=req.source, location=req.location)
        return {"count": len(items), "items": items}

@app.get("/findings", summary="List findings")
def list_findings():
        return {"count": len(FINDINGS), "items": FINDINGS[:200]}

@app.post("/revoke", summary="Request revoke (demo)")
def request_revoke(finding_id: int, requester: str = "api_user"):
        ap = request_revoke_in_memory(finding_id, requester=requester)
        return {"approval": ap}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
