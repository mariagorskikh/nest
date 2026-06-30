import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Agent Persistent Memory API", version="1.0.0")

# Enable CORS so agents running in browsers can query this if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# File path to persist memories across restarts
DB_FILE = "memories.json"

# In-memory database structure: { agent_id: { key: value } }
db = {}

def load_db():
    global db
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                db = json.load(f)
        except Exception:
            db = {}
    else:
        db = {}

def save_db():
    try:
        with open(DB_FILE, "w") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        print(f"Error saving database: {e}")

# Load existing database on startup
load_db()

class MemoryPayload(BaseModel):
    agent_id: str
    key: str
    value: str

@app.get("/health")
def health():
    """Simple check to verify the service is running and reachable."""
    return {"status": "ok", "entries_loaded": len(db)}

@app.post("/memory")
def store_memory(payload: MemoryPayload):
    """Store a persistent memory key-value pair under an agent_id namespace."""
    agent_id = payload.agent_id.strip()
    key = payload.key.strip()
    value = payload.value

    if not agent_id or not key:
        raise HTTPException(status_code=400, detail="agent_id and key cannot be empty.")

    if agent_id not in db:
        db[agent_id] = {}

    db[agent_id][key] = value
    save_db()

    return {"message": "Memory stored successfully.", "agent_id": agent_id, "key": key}

@app.get("/memory")
def retrieve_memory(agent_id: str, key: str):
    """Retrieve a previously stored memory value by agent_id and key."""
    agent_id = agent_id.strip()
    key = key.strip()

    if agent_id not in db or key not in db[agent_id]:
        raise HTTPException(
            status_code=404, 
            detail=f"No memory found for agent '{agent_id}' with key '{key}'."
        )

    return {
        "agent_id": agent_id,
        "key": key,
        "value": db[agent_id][key]
    }

@app.delete("/memory")
def delete_memory(agent_id: str, key: str):
    """Delete a memory value under an agent_id namespace."""
    agent_id = agent_id.strip()
    key = key.strip()

    if agent_id not in db or key not in db[agent_id]:
        raise HTTPException(
            status_code=404, 
            detail=f"No memory found for agent '{agent_id}' with key '{key}' to delete."
        )

    del db[agent_id][key]
    # Clean up empty agent namespace to keep db tidy
    if not db[agent_id]:
        del db[agent_id]
        
    save_db()

    return {"message": "Memory deleted successfully.", "agent_id": agent_id, "key": key}

@app.get("/memories")
def list_memories(agent_id: str):
    """List all stored keys and their current values for a given agent_id."""
    agent_id = agent_id.strip()

    if agent_id not in db:
        return {"agent_id": agent_id, "keys": [], "memories": {}}

    return {
        "agent_id": agent_id,
        "keys": list(db[agent_id].keys()),
        "memories": db[agent_id]
    }
