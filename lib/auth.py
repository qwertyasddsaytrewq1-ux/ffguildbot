# lib/auth.py
# Garena OAuth guest register/token + Free Fire MajorLogin
# Ported from GUEST.zip main.py — same logic, cleaned into reusable async functions

import asyncio, json, time, uuid, random, string, hashlib, hmac, socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import httpx

# ── constants ────────────────────────────────────────────────────────────
HKEY      = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
AES_KEY   = b'Yg&tc%DEuh6%Zc^8'
AES_IV    = b'6oyZDr22E3ychjM%'
MSDK_UA   = "GarenaMSDK/4.0.42(NX809J ;Android 9;en;US;app 1.134.14 2024010012;)"
UNITY_UA  = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
LOGIN_HOST    = "loginbp.ppmainecoonghj.com"
RELEASE_VER   = "OB55"
CLIENT_VER    = "1.134.14"
PASSWORD_PREFIX = "NG_SUJEET_"

FIELD22_HEX = (
    "47475245010101008202000048d0c6912766f3f72cedb7201cf7a7098d74888b9eb4070aec58e1cd29f26559fb3b8d32cc302d17c00fe629c20b94bece7b75867df5d2c63ad694fe754b06ca5f200fcc316532ee2d705c69d64e873a976d73f1bada85dedb1271bfd90f13e6eb1f607b197ea5741550829c40b5b9ab59f305fd460c462ac2ba9a50561b453053303105b3329e6aef4bf468da4ae276023c26fa39932d0ec40d874a849550e72f67b2f1e0974f835df6a8b5f3cd886483abd0da7cbccc6cd4df72aa5b104e63ea2bfeaf7b08d5176d2a9b128b8630468f625392397e2e43f63969e842f6e2c001c6da1cab2660eacaf8fdbc20520e1316a538406c480f3eefae89171f542b6aa5a8da797673764b0b05ac26a31511759cbdad6826ab621d208e0cf5282a76eb8453f8f768fd8d52dd408d64c0063149605de6af9b34bdf22202ea8d132cd797bbfb6ac72455000c493b18085957df0144f73b36b1aec77f8f5ca3c838d1c2b7e065db59df08b0e8b87dc6769a12ed8ed729c5a3c58468afc6f0c52604a3448b3dbca6a587ccff08bbdcd22e767169949942742142f52f837bfe97f49c801cad0b2d3fd22101188bd5e1dafeeabc4259abe0c7f2b96c5ded89eac5843e7cb95177755b6cf63edd6abaccf03fadcb7084988b2c28d7f3574da8775f6a2de3a429513837ad8319fefa6eb9bfaa1a1a8b06f9d58778c953ab1fc38b4569879416e65625d15ce233cbfffb2cbd56aeb16e07e05da7a52bff20f1d4e11643a328b28105ab74256507f9fccab3bfd0575b4b6fb0fdbeb448c9a1e4e780a4dfdabb2b487cd83f42764816d9a6f3e313349b95ce6fb5ca6dbb60d2f5c3b5157da94c84e2b7ce0e47e5dcbf4d7c146089b104979a5627e4f70a0a8d51a9ce358761119e0eb5ec3d2d7fea4f87227f9dfeaeb3a4ccd2b4cd38caa754c827d45ff0d00d520db11a49fdb6f0b4010203"
)
KEYSTREAM = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
             0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]

_PW_STASH: dict = {}

# ── helpers ───────────────────────────────────────────────────────────────
def _gen_sig(payload: str) -> str:
    return hmac.new(HKEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

def _aes_encrypt(data: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, 16))

def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _build_proto(fields: dict) -> bytes:
    out = bytearray()
    for f, v in fields.items():
        if isinstance(v, int):
            out += _encode_varint((f << 3) | 0) + _encode_varint(v)
        elif isinstance(v, (str, bytes)):
            b = v.encode() if isinstance(v, str) else v
            out += _encode_varint((f << 3) | 2) + _encode_varint(len(b)) + b
        elif isinstance(v, dict):
            nested = _build_proto(v)
            out += _encode_varint((f << 3) | 2) + _encode_varint(len(nested)) + nested
    return bytes(out)

def _first_varint(data: bytes, want: int):
    off = 0
    while off < len(data):
        key = shift = 0
        while True:
            b = data[off]; off += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v = shift = 0
            while True:
                b = data[off]; off += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            if fn == want: return v
        elif wt == 2:
            ln = shift = 0
            while True:
                b = data[off]; off += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            off += ln
        elif wt == 1: off += 8
        elif wt == 5: off += 4
        else: break
    return None

def _gen_password() -> str:
    return PASSWORD_PREFIX + ''.join(random.choices(string.ascii_letters + string.digits, k=26))

def _gen_nickname(prefix: str = "Bot") -> str:
    return f"{prefix}{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}"

def _get_server_time():
    try:
        import httpx as hx
        r = hx.head("https://www.google.com", timeout=3)
        d = r.headers.get('Date')
        if d:
            from datetime import datetime, timezone
            dt = datetime.strptime(d, "%a, %d %b %Y %H:%M:%S GMT")
            return int(dt.replace(tzinfo=timezone.utc).timestamp()), dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return int(time.time()), time.strftime("%Y-%m-%d %H:%M:%S")

# ── proxy pool ────────────────────────────────────────────────────────────
_PROXY_POOL: list = []
_PROXY_FETCHED_AT: float = 0.0

async def _refresh_proxies():
    global _PROXY_POOL, _PROXY_FETCHED_AT
    if time.time() - _PROXY_FETCHED_AT < 300 and _PROXY_POOL:
        return
    try:
        async with httpx.AsyncClient(timeout=4.0) as c:
            r = await c.get(
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
                "&timeout=2500&country=all&ssl=yes&anonymity=elite"
            )
            proxies = [p.strip() for p in r.text.strip().split("\n") if ":" in p]
            if proxies:
                random.shuffle(proxies)
                _PROXY_POOL = proxies[:60]
                _PROXY_FETCHED_AT = time.time()
    except Exception:
        pass

def _next_proxy() -> str | None:
    return random.choice(_PROXY_POOL) if _PROXY_POOL else None

# ── Garena OAuth ───────────────────────────────────────────────────────────
async def guest_register(max_retries: int = 10) -> tuple[str | None, str | None]:
    """Register a new guest account. Returns (uid, password)."""
    password = _gen_password()
    body_dict = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
    body = json.dumps(body_dict, separators=(',', ':'))
    headers = {
        "User-Agent": MSDK_UA,
        "Authorization": f"Signature {_gen_sig(body)}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "100067.connect.garena.com",
        "Connection": "Keep-Alive",
    }
    for attempt in range(max_retries):
        try:
            proxy = None
            if attempt > 1:
                await _refresh_proxies()
                p = _next_proxy()
                if p:
                    proxy = f"http://{p}"
            async with httpx.AsyncClient(
                verify=False,
                proxies=proxy,
                timeout=2.5,
            ) as c:
                r = await c.post(
                    "https://100067.connect.garena.com/api/v2/oauth/guest:register",
                    headers=headers,
                    content=body,
                )
            if r.status_code == 200:
                j = r.json()
                if "data" in j and "uid" in j["data"]:
                    uid = str(j["data"]["uid"])
                    _PW_STASH[uid] = password
                    return uid, password
            elif r.status_code == 429:
                await asyncio.sleep(0.3)
        except Exception:
            pass
        await asyncio.sleep(0.1)
    return None, None

async def guest_token(uid: str, password: str) -> dict | None:
    """Get access_token + open_id for an existing guest account."""
    body_dict = {
        "client_id": 100067,
        "client_secret": HKEY,
        "client_type": 2,
        "password": password,
        "response_type": "token",
        "uid": int(uid),
    }
    body = json.dumps(body_dict, separators=(',', ':'))
    headers = {
        "User-Agent": MSDK_UA,
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "100067.connect.garena.com",
        "Connection": "Keep-Alive",
    }
    for attempt in range(5):
        try:
            async with httpx.AsyncClient(verify=False, timeout=2.5) as c:
                r = await c.post(
                    "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
                    headers=headers,
                    content=body,
                )
            if r.status_code == 200:
                d = r.json()
                if "data" in d and "access_token" in d["data"]:
                    return {
                        "access_token": d["data"]["access_token"],
                        "open_id": d["data"].get("open_id", ""),
                    }
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return None

# ── MajorLogin payload builder ────────────────────────────────────────────
def _build_majorlogin_payload(access_token: str, open_id: str, server_time_str: str, region: str) -> bytes:
    P: dict = {}
    if region == "IND":
        P[3]=server_time_str; P[4]="free fire"; P[5]=1; P[7]="1.134.14"
        P[8]="Android OS 14 / API-34 (UP1A.231005.007/E156BXXS6AYD4)"
        P[9]="Handheld"; P[10]="airtel"; P[11]="CarrierDataNetwork"
        P[12]=2340; P[13]=1080; P[14]="295"
        P[15]="ARM64 FP ASIMD AES | 2200 | 8"; P[16]=5586
        P[17]="Mali-G57 MC2"; P[18]="OpenGL ES 3.2 v1.r38p1"
        P[19]="Google|f4d8aefb-7549-4778-a92b-2ed885bf9ec4"
        P[20]="27.61.46.111"; P[21]="en"; P[22]=open_id; P[23]="4"
        P[24]="Handheld"; P[25]="samsung SM-A155F"; P[26]="IND"
        P[29]=access_token; P[30]=1; P[41]="airtel"; P[42]="4G"
        P[57]="7428b253defc164018c604a1ebbfebdf"
        P[60]=108009; P[61]=3859; P[62]=5023; P[64]=3987
        P[65]=108009; P[66]=3987; P[67]=108009; P[70]=4; P[73]=3
        P[74]="/data/app/~~OlJmIW-Yzl-44x2WnJP4Nw==/com.garena.game.ffi-_eDk_pQQMiFk1YUeqwJBvQ==/lib/arm64"
        P[76]=3
        P[77]="dd9d4c174e0472d34b7fd34bd5924bc9|/data/app/~~OlJmIW-Yzl-44x2WnJP4Nw==/com.garena.game.ffi-_eDk_pQQMiFk1YUeqwJBvQ==/base.apk"
        P[78]=3; P[79]=2; P[81]="64"; P[83]="2019121269"
        P[85]=3; P[86]="OpenGLES2"; P[87]=8191; P[88]=4
        P[90]="Coimbatore"; P[91]="TN"; P[92]=9570; P[93]="android"
        P[94]="KqsHT54jON6bxITmlrRyOrXWBqKqZ4BoqPzT/mhtriAfRt2dt7gC8pnAJfj11alcEUA5sD8BshSYQhxXT9RFmU6YzcI1FKK4MwxJcF4+kvelPD1H"
        P[95]=111207; P[96]='{"cur_rate":null,"support_etc2":false}'
        P[97]=1; P[99]="4"; P[100]="4"; P[104]=11921; P[105]=1
        P[106]="https://dl-tata.freefireind.in/live/ABHotUpdates/|https://core-tata.freefireind.in/live/ABHotUpdates/|dff941d41e6e3a9e76f05ed71fdc8d87"
        P[107]="1.6168622e0868ddbd"
    else:   # BD
        P[3]=server_time_str; P[4]="free fire"; P[5]=1; P[7]="1.134.14"
        P[8]="Android OS 14 / API-34 (UP1A.231005.007/V816.0.15.0.UNQMIXM)"
        P[9]="Handheld"; P[10]="Grameenphone"; P[11]="CarrierDataNetwork"
        P[12]=1666; P[13]=750; P[14]="352"
        P[15]="ARM64 FP ASIMD AES | 2400 | 8"; P[16]=5563
        P[17]="Mali-G57 MC2"; P[18]="OpenGL ES 3.2 v1.r32p1-01eac0.0a0b917d9265b4c01be9925306306139"
        P[19]="Google|9cc73f7a-91f6-40f6-87ec-5b67e597eb8c"
        P[20]="59.152.5.188"; P[21]="en"; P[22]=open_id; P[23]="8"
        P[24]="Handheld"; P[25]="Xiaomi 2312DRAABI"; P[26]="BD"
        P[29]=access_token; P[30]=1; P[41]="Grameenphone"; P[42]="Cellular"
        P[57]="7428b253defc164018c604a1ebbfebdf"
        P[60]=109685; P[61]=58294; P[62]=797; P[63]=18000
        P[64]=58818; P[65]=109685; P[66]=58818; P[67]=109685; P[73]=2
        P[74]="/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/lib/arm64"
        P[76]=1
        P[77]="b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/base.apk"
        P[78]=3; P[79]=2; P[81]="64"; P[83]="2019121229"
        P[85]=3; P[86]="OpenGLES2"; P[87]=4095; P[88]=8
        P[89]=b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
        P[90]="Dhaka"; P[91]="C"; P[92]=8043; P[93]="android"
        P[94]="KqsHT4XbSZhqerDNUhjbS3DxG/4+I62zQU2tZFJN91kBUICAlZ5yujshLKvjlk/KiShfKfis8EeB1PMhFHIodWPncZC4fCHYF3TcTwNj95aWY/S3"
        P[95]=111207; P[96]='{"cur_rate":[60,90,120],"support_etc2":false}'
        P[97]=1; P[98]=1; P[99]="4"; P[100]="4"; P[102]="GQ]        e"
        P[103]=1; P[104]=45174; P[105]=1
        P[106]="https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a"
        P[107]="1.9393e7b8e53e8aeb"
    return _aes_encrypt(_build_proto(P))

def _extract_majorlogin(ml_resp: bytes) -> dict | None:
    if not ml_resp or len(ml_resp) <= 64:
        return None
    body = ml_resp[64:] if ml_resp[0] != 0x0a else ml_resp
    f: dict = {}
    pos = 0; n = len(body)
    while pos < n:
        try:
            key = shift = 0
            while True:
                b = body[pos]; pos += 1
                key |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
        except Exception:
            break
        fn, wt = key >> 3, key & 0x07
        try:
            if wt == 0:
                val = shift = 0
                while True:
                    b = body[pos]; pos += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
            elif wt == 2:
                ln = shift = 0
                while True:
                    b = body[pos]; pos += 1
                    ln |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                val = body[pos:pos+ln]; pos += ln
            elif wt == 5: val = body[pos:pos+4]; pos += 4
            elif wt == 1: val = body[pos:pos+8]; pos += 8
            else: break
        except Exception:
            break
        f.setdefault(fn, []).append(val)

    jwt_b  = f.get(8,  [None])[0]
    url_b  = f.get(10, [None])[0]
    key_b  = f.get(22, [None])[0]
    iv_b   = f.get(23, [None])[0]
    if not jwt_b or not isinstance(key_b, bytes) or not isinstance(iv_b, bytes):
        return None
    return {
        "jwt":  jwt_b.decode(errors="ignore"),
        "url":  url_b.decode(errors="ignore") if isinstance(url_b, bytes) else None,
        "key":  key_b,
        "iv":   iv_b,
    }

async def major_register(open_id: str, access_token: str, nickname: str,
                         sync_ts: int, lang: str = "en",
                         max_retries: int = 6) -> str | None:
    """Register in-game account. Returns game account_id string."""
    encoded = "".join(chr(ord(c) ^ KEYSTREAM[i % len(KEYSTREAM)]) for i, c in enumerate(open_id))
    fields = {
        1: nickname, 2: access_token, 3: open_id,
        5: 102000007, 6: 4, 7: 1, 8: 4,
        13: 1, 14: encoded.encode('latin1'), 15: lang, 16: 1,
        20: CLIENT_VER, 21: 1, 22: bytes.fromhex(FIELD22_HEX),
    }
    payload = _aes_encrypt(_build_proto(fields))
    headers = {
        "User-Agent": UNITY_UA,
        "Accept": "*/*",
        "X-GA-SV": str(sync_ts),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VER,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Host": LOGIN_HOST,
        "Connection": "Keep-Alive",
    }
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(verify=False, timeout=2.0) as c:
                r = await c.post(
                    f"https://{LOGIN_HOST}/MajorRegister",
                    content=payload,
                    headers=headers,
                )
            if r.status_code == 200:
                aid = _first_varint(r.content, 3)
                if aid:
                    return str(aid)
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return None

async def major_login(access_token: str, open_id: str, server_time_str: str,
                      region: str, sync_ts: int,
                      max_retries: int = 6) -> dict | None:
    """Full MajorLogin → returns {jwt, url, key, iv}."""
    payload = _build_majorlogin_payload(access_token, open_id, server_time_str, region)
    headers = {
        "User-Agent": UNITY_UA,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(sync_ts),
        "Authorization": "Bearer ",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VER,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(verify=False, timeout=2.5) as c:
                r = await c.post(
                    f"https://{LOGIN_HOST}/MajorLogin",
                    content=payload,
                    headers=headers,
                )
            if r.status_code in (200, 201) and len(r.content) > 64:
                return _extract_majorlogin(r.content)
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return None

# ── full account generation pipeline ─────────────────────────────────────
async def generate_account(region: str = "BD", nickname_prefix: str = "Bot") -> dict | None:
    """
    Full pipeline: register guest → get token → register in-game → login.
    Returns account dict or None on failure.
    """
    sync_ts, sync_time_str = _get_server_time()

    uid, password = await guest_register()
    if not uid:
        return None

    token_data = await guest_token(uid, password)
    if not token_data:
        return None

    open_id      = token_data["open_id"]
    access_token = token_data["access_token"]
    nickname     = _gen_nickname(nickname_prefix)

    account_id = await major_register(open_id, access_token, nickname, sync_ts, lang="en")
    if not account_id:
        return None

    ml = await major_login(access_token, open_id, sync_time_str, region, sync_ts)
    if not ml:
        return None

    return {
        "uid":          uid,
        "password":     password,
        "account_id":   account_id,
        "name":         nickname,
        "region":       region,
        "open_id":      open_id,
        "access_token": access_token,
        "jwt":          ml["jwt"],
        "game_url":     ml.get("url") or f"https://client.{region.lower()}.freefiremobile.com",
        "aes_key":      ml["key"].hex(),
        "aes_iv":       ml["iv"].hex(),
  }
  
