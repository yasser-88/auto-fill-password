
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from crypto import load_vault, write_vault
from helpers import get_domain_from_url
app = FastAPI()

class CredentialsRequest(BaseModel):
    master_password: str
    domain: str

class AddCredentialsRequest(BaseModel):
    master_password: str
    domain: str
    username: str
    password: str

@app.post("/get_credentials")
async def get_credentials(req: CredentialsRequest):
    try:
        entries = load_vault(req.master_password)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password")
    
    domain = get_domain_from_url(req.domain)
    for entry in entries:
        if domain == entry["domain"]:
            return {
                "username": entry["username"],
                "password": entry["password"],
            }

    raise HTTPException(status_code=404, detail=f"No credentials found for '{req.domain}'")

@app.post("/add_credentials")
async def add_credentials(req: AddCredentialsRequest):
    try:
        entries = load_vault(req.master_password)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password")
    
    domain = get_domain_from_url(req.domain)
    entries.append({
        "domain": domain,
        "username": req.username,
        "password": req.password
    })
    
    write_vault(req.master_password, entries)
    return {"success": True}

def run_server():
    try:
        print("Starting server...")
        uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")
    except Exception as e:
        print(f"Server error: {e}")
        import traceback
        traceback.print_exc()