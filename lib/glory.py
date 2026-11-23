# lib/glory.py
# Guild join logic — mirrors suji.py but runs directly against the game API
# via auth token refresh + TCP guild-join packet, with HTTP fallback

import asyncio, json, time, random
import httpx

# ── external join relay (same as suji.py target) ─────────────────────────
_JOIN_API = "https://ngsujeetguild-manejar.vercel.app/Join"

async def join_guild_via_api(guild_uid: str, uid: str, password: str,
                              log=None) -> bool:
    """
    Quick path: hit the external join relay.
    Returns True on HTTP 200 with a success body.
    """
    url = f"{_JOIN_API}?guild_uid={guild_uid}&uid={uid}&password={password}"
    _log = log or (lambda m, t="info": None)
    for attempt in range(4):
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
                r = await c.get(url)
            body = r.text.strip().lower()
            if r.status_code == 200 and ("success" in body or "joined" in body or "ok" in body):
                _log(f"[JOIN] UID {uid} joined guild {guild_uid} ✓", "success")
                return True
            _log(f"[JOIN] UID {uid} attempt {attempt+1} → {r.status_code} {r.text[:80]}", "warning")
        except Exception as e:
            _log(f"[JOIN] UID {uid} attempt {attempt+1} error: {e}", "error")
        await asyncio.sleep(1.0 + random.uniform(0, 0.5))
    return False


async def join_guild_batch(guild_uid: str, accounts: list,
                            log=None, stop_flag=None, pause_flag=None) -> dict:
    """
    Join guild for every account in the list.
    accounts: [{uid, password, ...}, ...]
    Returns {joined: int, failed: int, results: [{uid, ok, msg}]}
    """
    _log = log or (lambda m, t="info": None)
    joined = 0; failed = 0; results = []

    for acc in accounts:
        if stop_flag and stop_flag():
            _log("[JOIN] Stop requested — aborting guild joins", "warning")
            break
        while pause_flag and pause_flag():
            _log("[JOIN] Paused…", "info")
            await asyncio.sleep(1.0)

        uid = str(acc.get("uid", ""))
        pw  = str(acc.get("password", ""))
        if not uid or not pw:
            failed += 1
            results.append({"uid": uid, "ok": False, "msg": "missing uid/password"})
            continue

        ok = await join_guild_via_api(guild_uid, uid, pw, log=_log)
        if ok:
            joined += 1
            results.append({"uid": uid, "ok": True, "msg": "joined"})
        else:
            failed += 1
            results.append({"uid": uid, "ok": False, "msg": "failed after retries"})

        # small delay between accounts — avoids rate limit bursts
        await asyncio.sleep(random.uniform(0.6, 1.4))

    return {"joined": joined, "failed": failed, "results": results}
