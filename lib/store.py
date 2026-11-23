# lib/store.py — Upstash Redis KV wrapper
# Uses UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN env vars (set in Vercel dashboard)
# Falls back to in-memory dict for local dev (wiped on cold start, fine for testing)

import os, json, time, hashlib, hmac
from typing import Any, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

_MEM: dict = {}   # local fallback

UPSTASH_URL   = os.environ.get("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
_USE_UPSTASH   = bool(UPSTASH_URL and UPSTASH_TOKEN and _HAS_HTTPX)

# ── raw Upstash REST ────────────────────────────────────────────────────
def _upstash(cmd: list) -> Any:
    import httpx as hx
    r = hx.post(
        f"{UPSTASH_URL.rstrip('/')}/pipeline",
        headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"},
        json=[cmd],
        timeout=8.0,
    )
    r.raise_for_status()
    results = r.json()
    return results[0]["result"] if isinstance(results, list) else None

# ── public API ──────────────────────────────────────────────────────────
def kv_set(key: str, value: Any, ex: int = 0) -> None:
    """Set key to JSON-serialised value. ex = TTL seconds (0 = no expiry)."""
    blob = json.dumps(value)
    if _USE_UPSTASH:
        cmd = ["SET", key, blob]
        if ex > 0:
            cmd += ["EX", ex]
        _upstash(cmd)
    else:
        _MEM[key] = (blob, time.time() + ex if ex > 0 else None)

def kv_get(key: str) -> Optional[Any]:
    """Get key → parsed JSON, or None if missing/expired."""
    if _USE_UPSTASH:
        raw = _upstash(["GET", key])
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return raw
    else:
        entry = _MEM.get(key)
        if entry is None:
            return None
        blob, exp = entry
        if exp and time.time() > exp:
            del _MEM[key]
            return None
        try:
            return json.loads(blob)
        except Exception:
            return blob

def kv_delete(key: str) -> None:
    if _USE_UPSTASH:
        _upstash(["DEL", key])
    else:
        _MEM.pop(key, None)

def kv_keys(pattern: str) -> list:
    """Return all keys matching pattern (glob-style on Upstash, prefix match locally)."""
    if _USE_UPSTASH:
        result = _upstash(["KEYS", pattern])
        return result if isinstance(result, list) else []
    else:
        prefix = pattern.rstrip("*")
        return [k for k in _MEM if k.startswith(prefix)]

# ── account store helpers ───────────────────────────────────────────────
ACCOUNTS_KEY = "ff:accounts"

def load_accounts() -> list:
    data = kv_get(ACCOUNTS_KEY)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return []

def save_accounts(accounts: list) -> None:
    kv_set(ACCOUNTS_KEY, accounts)

def add_account(uid: str, password: str) -> dict:
    accounts = load_accounts()
    uid = str(uid).strip()
    password = str(password).strip()
    # dedup by uid
    for a in accounts:
        if str(a.get("uid")) == uid:
            a["password"] = password
            save_accounts(accounts)
            return {"status": "updated", "uid": uid}
    accounts.append({"uid": uid, "password": password})
    save_accounts(accounts)
    return {"status": "added", "uid": uid}

def remove_account(uid: str) -> bool:
    accounts = load_accounts()
    before = len(accounts)
    accounts = [a for a in accounts if str(a.get("uid")) != str(uid)]
    if len(accounts) < before:
        save_accounts(accounts)
        return True
    return False

# ── job store helpers ────────────────────────────────────────────────────
JOB_PREFIX = "ff:job:"
JOB_TTL    = 3600   # 1 hour

def job_create(job_id: str, payload: dict) -> None:
    kv_set(f"{JOB_PREFIX}{job_id}", {
        "id": job_id,
        "status": "pending",
        "created_at": time.time(),
        "payload": payload,
        "results": [],
        "error": None,
    }, ex=JOB_TTL)

def job_get(job_id: str) -> Optional[dict]:
    return kv_get(f"{JOB_PREFIX}{job_id}")

def job_update(job_id: str, **kwargs) -> None:
    job = job_get(job_id)
    if job is None:
        return
    job.update(kwargs)
    kv_set(f"{JOB_PREFIX}{job_id}", job, ex=JOB_TTL)

def job_append_result(job_id: str, result: dict) -> None:
    job = job_get(job_id)
    if job is None:
        return
    results = job.get("results", [])
    results.append(result)
    job["results"] = results
    kv_set(f"{JOB_PREFIX}{job_id}", job, ex=JOB_TTL)

def list_jobs() -> list:
    keys = kv_keys(f"{JOB_PREFIX}*")
    jobs = []
    for k in keys:
        j = kv_get(k)
        if j:
            jobs.append(j)
    jobs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return jobs[:20]
