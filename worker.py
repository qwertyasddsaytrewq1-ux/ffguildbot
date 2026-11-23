# worker.py
# Railway backend — FastAPI app
# Endpoints:
#   POST /start          { guild_id, account_count }  → starts full pipeline
#   POST /pause          toggle pause
#   POST /stop           stop everything
#   GET  /status         current state JSON
#   GET  /stream         SSE log stream
#   GET  /accounts       list generated accounts
#   DELETE /accounts     wipe accounts

import asyncio, json, time, os, uuid
from typing import AsyncGenerator

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

from lib.auth  import generate_account
from lib.glory import join_guild_batch
from lib.match import run_match_bot

app = FastAPI(title="FF Glory Bot Worker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── in-memory state ────────────────────────────────────────────────────────
_STATE = {
    "job_id":        None,
    "status":        "idle",   # idle | generating | joining | playing | paused | stopped | done
    "guild_id":      None,
    "account_count": 0,
    "accounts":      [],       # generated account dicts
    "joined":        0,
    "failed_joins":  0,
    "matches":       0,
    "stop":          False,
    "pause":         False,
    "log":           [],       # [{ts, msg, type}]
}

_LOG_QUEUE: asyncio.Queue = asyncio.Queue()

def _log(msg: str, kind: str = "info"):
    entry = {"ts": time.time(), "msg": msg, "type": kind}
    _STATE["log"].append(entry)
    if len(_STATE["log"]) > 500:
        _STATE["log"] = _STATE["log"][-400:]
    # non-blocking put
    try:
        _LOG_QUEUE.put_nowait(entry)
    except asyncio.QueueFull:
        pass

def _stop_flag(): return _STATE["stop"]
def _pause_flag(): return _STATE["pause"]

# ── pipeline ───────────────────────────────────────────────────────────────
async def _run_pipeline(guild_id: str, account_count: int):
    _STATE.update({
        "status": "generating", "guild_id": guild_id,
        "account_count": account_count, "accounts": [],
        "joined": 0, "failed_joins": 0, "matches": 0,
        "stop": False, "pause": False, "log": [],
    })

    _log(f"Pipeline start: guild={guild_id}, accounts={account_count}", "info")

    # ── PHASE 1: generate accounts ────────────────────────────────────────
    _log(f"Phase 1: generating {account_count} guest accounts…", "info")
    sem = asyncio.Semaphore(10)

    async def _gen_one(idx: int):
        async with sem:
            if _stop_flag(): return None
            while _pause_flag():
                await asyncio.sleep(1.0)
            acc = await generate_account(region="BD", nickname_prefix="GBot")
            if acc:
                _STATE["accounts"].append(acc)
                _log(f"[GEN {idx+1}/{account_count}] uid={acc['uid']} ✓", "success")
            else:
                _log(f"[GEN {idx+1}/{account_count}] FAILED", "error")
            return acc

    tasks = [asyncio.create_task(_gen_one(i)) for i in range(account_count)]
    await asyncio.gather(*tasks, return_exceptions=True)

    if _stop_flag():
        _STATE["status"] = "stopped"; _log("Stopped during generation", "warning"); return

    _log(f"Generated {len(_STATE['accounts'])}/{account_count} accounts", "info")

    # ── PHASE 2: join guild ────────────────────────────────────────────────
    _STATE["status"] = "joining"
    _log(f"Phase 2: joining guild {guild_id} with {len(_STATE['accounts'])} accounts…", "info")

    result = await join_guild_batch(
        guild_uid   = guild_id,
        accounts    = _STATE["accounts"],
        log         = _log,
        stop_flag   = _stop_flag,
        pause_flag  = _pause_flag,
    )
    _STATE["joined"]       = result["joined"]
    _STATE["failed_joins"] = result["failed"]
    _log(f"Guild join done: {result['joined']} joined, {result['failed']} failed", "info")

    if _stop_flag():
        _STATE["status"] = "stopped"; _log("Stopped during guild join", "warning"); return

    # ── PHASE 3: play matches ──────────────────────────────────────────────
    _STATE["status"] = "playing"
    _log(f"Phase 3: starting match bots for {len(_STATE['accounts'])} accounts…", "info")

    match_sem = asyncio.Semaphore(20)

    async def _play_one(acc: dict, idx: int):
        async with match_sem:
            if _stop_flag(): return
            res = await run_match_bot(
                account    = acc,
                log        = _log,
                stop_flag  = _stop_flag,
                pause_flag = _pause_flag,
                region_idx = idx,
            )
            _STATE["matches"] += res.get("matches_played", 0)
            _log(f"[BOT {idx+1}] uid={acc.get('uid')} matches={res.get('matches_played',0)}", "info")

    play_tasks = [
        asyncio.create_task(_play_one(acc, i))
        for i, acc in enumerate(_STATE["accounts"])
    ]
    await asyncio.gather(*play_tasks, return_exceptions=True)

    _STATE["status"] = "done"
    _log(f"Pipeline complete. Joined={_STATE['joined']} Matches={_STATE['matches']}", "success")


# ── API models ─────────────────────────────────────────────────────────────
class StartRequest(BaseModel):
    guild_id:      str
    account_count: int = 10

# ── routes ─────────────────────────────────────────────────────────────────
@app.post("/start")
async def start(req: StartRequest, bg: BackgroundTasks):
    if _STATE["status"] in ("generating", "joining", "playing"):
        return JSONResponse({"error": "already running"}, status_code=409)
    _STATE["job_id"] = str(uuid.uuid4())[:8]
    count = max(1, min(req.account_count, 200))
    bg.add_task(_run_pipeline, req.guild_id, count)
    return {"job_id": _STATE["job_id"], "guild_id": req.guild_id, "account_count": count}

@app.post("/pause")
async def pause():
    if _STATE["status"] not in ("generating", "joining", "playing"):
        return JSONResponse({"error": "not running"}, status_code=400)
    _STATE["pause"] = not _STATE["pause"]
    if _STATE["pause"]:
        _STATE["status"] = "paused"
        _log("Paused", "warning")
    else:
        # restore previous play status
        _STATE["status"] = "playing"
        _log("Resumed", "info")
    return {"paused": _STATE["pause"]}

@app.post("/stop")
async def stop():
    _STATE["stop"] = True
    _STATE["pause"] = False
    _log("Stop signal sent", "warning")
    return {"stopped": True}

@app.get("/status")
async def status():
    return {
        "job_id":        _STATE["job_id"],
        "status":        _STATE["status"],
        "guild_id":      _STATE["guild_id"],
        "account_count": _STATE["account_count"],
        "accounts_gen":  len(_STATE["accounts"]),
        "joined":        _STATE["joined"],
        "failed_joins":  _STATE["failed_joins"],
        "matches":       _STATE["matches"],
        "paused":        _STATE["pause"],
    }

@app.get("/accounts")
async def get_accounts():
    # strip sensitive fields before returning
    safe = [{k: v for k, v in a.items() if k not in ("jwt", "aes_key", "aes_iv")}
            for a in _STATE["accounts"]]
    return {"accounts": safe, "total": len(safe)}

@app.delete("/accounts")
async def delete_accounts():
    if _STATE["status"] in ("generating", "joining", "playing"):
        return JSONResponse({"error": "cannot clear while running"}, status_code=409)
    _STATE["accounts"] = []
    return {"cleared": True}

@app.get("/stream")
async def stream():
    """SSE log stream — Vercel frontend subscribes here."""
    async def _gen() -> AsyncGenerator[str, None]:
        # first: send all existing log entries
        for entry in _STATE["log"]:
            yield f"data: {json.dumps(entry)}\n\n"
        # then stream new ones
        while True:
            try:
                entry = await asyncio.wait_for(_LOG_QUEUE.get(), timeout=25.0)
                yield f"data: {json.dumps(entry)}\n\n"
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"   # keep connection alive

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@app.get("/")
async def root():
    return {"service": "FF Glory Bot Worker", "status": _STATE["status"]}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("worker:app", host="0.0.0.0", port=port, reload=False)
