# lib/match.py
# TCP/UDP Free Fire match bot — extracted from app.py
# Handles: token refresh, squad creation, match search, UDP play loop,
# movement simulation, anti-AFK fire packets, TEA-CBC UDP crypto, CRC7

import asyncio, socket, struct, time, random, math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ── constants (from app.py) ───────────────────────────────────────────────
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

ANTI_AFK_MIN_INTERVAL = 1.8
ANTI_AFK_MAX_INTERVAL = 3.5
MAX_MATCH_DURATION    = 3000
MATCH_IDLE_TIMEOUT    = 90.0
MOVEMENT_TICK_MS      = 240
MOVEMENT_RADIUS       = 180
MOVEMENT_SPEED_MIN    = 2.0
MOVEMENT_SPEED_MAX    = 2.4
REGION_ROTATION_LIST  = ["ID", "SG", "TH", "MY", "VN", "PH"]

CRC7_TABLE = bytes([
    0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,25,16,11,2,61,52,47,38,
    81,88,67,74,117,124,103,110,50,59,32,41,22,31,4,13,122,115,104,97,94,87,76,69,
    43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,100,109,118,127,64,73,82,91,
    44,37,62,55,8,1,26,19,125,116,111,102,89,80,75,66,53,60,39,46,17,24,3,10,
    86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,79,70,93,84,107,98,121,112,
    7,14,21,28,35,42,49,56,65,72,83,90,101,108,119,126,9,0,27,18,45,36,63,54,
    88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,47,115,122,97,104,87,94,69,76,
    59,50,41,32,31,22,13,4,106,99,120,113,78,71,92,85,34,43,48,57,6,15,20,29,
    37,44,55,62,1,8,19,26,109,100,127,118,73,64,91,82,60,53,46,39,24,17,10,3,
    116,125,102,111,80,89,66,75,23,30,5,12,51,58,33,40,95,86,77,68,123,114,105,96,
    14,7,28,21,42,35,56,49,70,79,84,93,98,107,112,121,
])
_DELTA  = 0x9E3779B9
_ROUNDS = 16

# BR match-search packet hex (hardcoded from app.py)
BR_HEX = (
    "0801120808011204080310041a060803100410011a060803100510021a060803100610031a06"
    "080310071004200128013001"
)

# ── helpers ───────────────────────────────────────────────────────────────
def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, v): return _encode_varint((fn << 3) | 0) + _encode_varint(v)
def _pb_len(fn, v):
    b = v.encode() if isinstance(v, str) else bytes(v)
    return _encode_varint((fn << 3) | 2) + _encode_varint(len(b)) + b

def _build_proto(fields: dict) -> bytes:
    out = bytearray()
    for f, v in fields.items():
        if isinstance(v, int):   out += _pb_varint(f, v)
        elif isinstance(v, (str, bytes, bytearray)): out += _pb_len(f, v)
        elif isinstance(v, dict): out += _pb_len(f, _build_proto(v))
    return bytes(out)

def _aes_enc(data: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, 16))

# ── CRC7 ──────────────────────────────────────────────────────────────────
def crc7_buff(buf: bytes) -> int:
    crc = 0
    for b in buf:
        crc = CRC7_TABLE[(crc << 1) ^ b]
    return crc

# ── TEA-CBC (UDP encryption) ──────────────────────────────────────────────
def _tea_encrypt_block(v0: int, v1: int, k0: int, k1: int, k2: int, k3: int):
    s = 0
    for _ in range(_ROUNDS):
        s = (s + _DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
    return v0, v1

def tea_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    k = struct.unpack(">4I", key)
    if len(data) % 8: data = data + b'\x00' * (8 - len(data) % 8)
    prev = b'\x00' * 8; out = bytearray()
    for i in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(data[i:i+8], prev))
        v0, v1 = struct.unpack(">II", block)
        v0, v1 = _tea_encrypt_block(v0, v1, *k)
        enc = struct.pack(">II", v0, v1)
        out += enc; prev = enc
    return bytes(out)

# ── TCP frame builder ──────────────────────────────────────────────────────
def sv_frame(payload: bytes, cmd: int = 0x65, send_opt: int = 0x01,
             order_id: int = 0, flags: int = 0x01) -> bytes:
    """Build a TCP game-server frame with CRC7 header."""
    length = len(payload)
    hdr = bytearray(8)
    hdr[0] = send_opt & 0xFF
    hdr[1] = (cmd >> 8) & 0xFF
    hdr[2] = cmd & 0xFF
    hdr[3] = (order_id >> 8) & 0xFF
    hdr[4] = order_id & 0xFF
    hdr[5] = flags & 0xFF
    hdr[6] = (length >> 8) & 0xFF
    hdr[7] = length & 0xFF
    crc = crc7_buff(bytes(hdr[1:]))
    hdr[0] = (hdr[0] & 0x01) | (crc << 1)
    return bytes(hdr) + payload

def build_packet(proto_fields: dict, cmd: int, key: bytes, iv: bytes,
                 order_id: int = 0) -> bytes:
    """AES-CBC encrypt proto payload + wrap in TCP frame."""
    plain = _build_proto(proto_fields)
    enc   = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, 16))
    return sv_frame(enc, cmd=cmd, order_id=order_id)

# ── auth token ────────────────────────────────────────────────────────────
def build_auth_token(uid: int, jwt: str, ts: int,
                     key: bytes, iv: bytes) -> str:
    """Build hex auth token for TCP socket login."""
    f = {1: uid, 2: jwt, 3: ts, 4: 1, 7: 1}
    enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(_build_proto(f), 16))
    return enc.hex()

# ── squad packet builders ─────────────────────────────────────────────────
def _create_team_payload(game_version: str = "1.134.14") -> bytes:
    fields = {
        1: 1,
        2: {
            2: bytes.fromhex("01"), 3: 1, 4: 3, 5: "en",
            8: {1: "IDC3", 2: 123, 3: "ID"}, 9: 1,
            10: bytes.fromhex("01090a0b1219202729"), 11: 2, 13: 1,
            14: {
                1: "08FBA33B4BABE2790205390333330000009700050092005F",
                2: 478, 3: "7e585d55", 4: "y[Z]", 6: 12,
                7: "15686677735a7506101c", 8: game_version,
                9: 3, 10: 1, 11: "03626253513637754174",
            },
            19: 329, 21: bytes.fromhex("374f521955"),
            24: {1: 21},
        },
    }
    return _build_proto(fields)

def _invite_payload(target_uid: int) -> bytes:
    return _build_proto({1: 1, 2: target_uid, 3: 1})

def _accept_invite_payload(team_code: str) -> bytes:
    return _build_proto({1: 2, 2: team_code})

def _start_match_payload(mode: int = 1, map_id: int = 1) -> bytes:
    return _build_proto({1: 3, 2: {1: mode, 2: map_id}, 3: 1})

def _ready_payload() -> bytes:
    return _build_proto({1: 4})

# ── movement ──────────────────────────────────────────────────────────────
class MovementTracker:
    def __init__(self, origin_x: float = 1000.0, origin_y: float = 0.0,
                 origin_z: float = 1000.0):
        self.x = origin_x; self.y = origin_y; self.z = origin_z
        self.angle = 0.0
        self.speed = random.uniform(MOVEMENT_SPEED_MIN, MOVEMENT_SPEED_MAX)
        self.state = 2   # 0=idle 1=walk 2=run 3=sprint 4=jump 5=crouch 6=prone
        self._tick = 0

    def next_circle(self) -> tuple:
        self.angle += (self.speed * MOVEMENT_TICK_MS / 1000.0) / max(MOVEMENT_RADIUS, 1.0)
        self.x = 1000.0 + MOVEMENT_RADIUS * math.cos(self.angle)
        self.z = 1000.0 + MOVEMENT_RADIUS * math.sin(self.angle)
        return self.x, self.y, self.z

    def next_random(self) -> tuple:
        self.x += random.uniform(-self.speed * 0.5, self.speed * 0.5) * 2
        self.z += random.uniform(-self.speed * 0.5, self.speed * 0.5) * 2
        return self.x, self.y, self.z

    def roll_state(self):
        r = random.random()
        if   r < 0.10: self.state = 0
        elif r < 0.38: self.state = 1
        elif r < 0.70: self.state = 2
        elif r < 0.80: self.state = 3
        elif r < 0.88: self.state = 4
        elif r < 0.94: self.state = 5
        else:          self.state = 6

    def build_packet(self, key: bytes, iv: bytes, order_id: int = 0) -> bytes:
        self._tick += 1
        if self._tick % 20 == 0:
            self.roll_state()
            self.speed = random.uniform(MOVEMENT_SPEED_MIN, MOVEMENT_SPEED_MAX)
        x, y, z = self.next_circle()
        fields = {
            1: int(x * 100), 2: int(y * 100), 3: int(z * 100),
            4: self.state, 5: int(self.angle * 100),
            6: int(self.speed * 100),
        }
        return build_packet(fields, cmd=0x07D1, key=key, iv=iv, order_id=order_id)

# ── anti-AFK ──────────────────────────────────────────────────────────────
def build_fire_packet(key: bytes, iv: bytes, order_id: int = 0) -> bytes:
    return build_packet({1: 1, 2: 1, 3: 1}, cmd=0x0834, key=key, iv=iv, order_id=order_id)

def build_stop_fire_packet(key: bytes, iv: bytes, order_id: int = 0) -> bytes:
    return build_packet({1: 0, 2: 1, 3: 1}, cmd=0x0834, key=key, iv=iv, order_id=order_id)

# ── TCP connection ────────────────────────────────────────────────────────
async def tcp_connect(host: str, port: int = 443) -> asyncio.StreamReader | tuple:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=True), timeout=8.0
        )
        return reader, writer
    except Exception:
        # fallback: plain TCP on 10012
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 10012), timeout=8.0
            )
            return reader, writer
        except Exception:
            return None, None

async def send_login(writer, uid: int, jwt: str, ts: int,
                     key: bytes, iv: bytes):
    token_hex = build_auth_token(uid, jwt, ts, key, iv)
    # login command = 0x65 (101)
    payload = bytes.fromhex(token_hex)
    frame   = sv_frame(payload, cmd=0x65)
    writer.write(frame)
    await writer.drain()

async def recv_frame(reader: asyncio.StreamReader, timeout: float = 10.0) -> bytes | None:
    try:
        hdr = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
        if len(hdr) < 8: return None
        length = ((hdr[6] & 0xFF) << 8) | (hdr[7] & 0xFF)
        if length <= 0: return b""
        body = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        return body
    except Exception:
        return None

# ── UDP match session ─────────────────────────────────────────────────────
class UDPMatchSession:
    def __init__(self, host: str, port: int, key: bytes, iv: bytes, uid: int):
        self.host  = host; self.port = port
        self.key   = key; self.iv   = iv
        self.uid   = uid
        self._sock: socket.socket | None = None
        self._order = 0

    def _next_order(self) -> int:
        self._order = (self._order + 1) & 0xFFFF
        return self._order

    def open(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)

    def close(self):
        if self._sock:
            try: self._sock.close()
            except Exception: pass
            self._sock = None

    def send(self, data: bytes):
        if self._sock:
            try: self._sock.sendto(data, (self.host, self.port))
            except Exception: pass

    def send_hello(self):
        """Initial UDP hello / join-match packet."""
        fields = {1: self.uid, 2: 1, 3: int(time.time())}
        raw = _build_proto(fields)
        enc = tea_cbc_encrypt(raw, self.key[:8] + self.iv[:8])
        self.send(enc)

    def send_movement(self, tracker: MovementTracker):
        pkt = tracker.build_packet(self.key, self.iv, self._next_order())
        enc = tea_cbc_encrypt(pkt, self.key[:8] + self.iv[:8])
        self.send(enc)

    def send_fire(self):
        pkt = build_fire_packet(self.key, self.iv, self._next_order())
        enc = tea_cbc_encrypt(pkt, self.key[:8] + self.iv[:8])
        self.send(enc)

    def send_stop_fire(self):
        pkt = build_stop_fire_packet(self.key, self.iv, self._next_order())
        enc = tea_cbc_encrypt(pkt, self.key[:8] + self.iv[:8])
        self.send(enc)

# ── main match bot loop ───────────────────────────────────────────────────
async def run_match_bot(account: dict, log=None,
                         stop_flag=None, pause_flag=None,
                         region_idx: int = 0) -> dict:
    """
    Full match-bot loop for one account:
      1. Connect TCP → login
      2. Create/join squad
      3. Search + enter match
      4. UDP play loop (movement + anti-AFK)
      5. Loop until stop_flag or MAX_MATCH_DURATION
    Returns {uid, matches_played, error}
    """
    _log = log or (lambda m, t="info": None)
    uid   = int(account.get("account_id", account.get("uid", 0)))
    jwt   = account.get("jwt", "")
    game_url = account.get("game_url", "")
    aes_key = bytes.fromhex(account.get("aes_key", AES_KEY.hex()))
    aes_iv  = bytes.fromhex(account.get("aes_iv",  AES_IV.hex()))

    if not uid or not jwt or not game_url:
        return {"uid": uid, "matches_played": 0, "error": "missing credentials"}

    # parse host from game_url
    import urllib.parse
    parsed_url = urllib.parse.urlparse(game_url)
    host = parsed_url.hostname or game_url.replace("https://", "").replace("http://", "").split("/")[0]

    matches_played = 0
    reconnect_attempts = 0
    region_offset = region_idx % len(REGION_ROTATION_LIST)

    while True:
        if stop_flag and stop_flag():
            _log(f"[MATCH] UID {uid}: stop requested", "warning")
            break
        while pause_flag and pause_flag():
            _log(f"[MATCH] UID {uid}: paused", "info")
            await asyncio.sleep(1.0)

        region = REGION_ROTATION_LIST[region_offset % len(REGION_ROTATION_LIST)]
        _log(f"[MATCH] UID {uid}: connecting TCP → {host} region={region}", "info")

        reader, writer = await tcp_connect(host)
        if not writer:
            reconnect_attempts += 1
            _log(f"[MATCH] UID {uid}: TCP connect failed (attempt {reconnect_attempts})", "error")
            await asyncio.sleep(min(reconnect_attempts * 1.0, 5.0))
            if reconnect_attempts > 20:
                break
            continue

        reconnect_attempts = 0
        try:
            await send_login(writer, uid, jwt, int(time.time()), aes_key, aes_iv)
            _log(f"[MATCH] UID {uid}: TCP login sent", "info")

            # wait for login ACK
            resp = await recv_frame(reader, timeout=12.0)
            if not resp:
                _log(f"[MATCH] UID {uid}: no login ACK", "error")
                writer.close()
                continue

            _log(f"[MATCH] UID {uid}: logged in, creating squad", "info")

            # squad: create team (leader sends, others invite themselves)
            team_payload = _create_team_payload()
            frame = sv_frame(_aes_enc(team_payload), cmd=0x01F5)
            writer.write(frame)
            await writer.drain()
            await asyncio.sleep(2.0)

            # send match search
            br_payload = bytes.fromhex(BR_HEX)
            frame = sv_frame(_aes_enc(br_payload), cmd=0x0193)
            writer.write(frame)
            await writer.drain()
            _log(f"[MATCH] UID {uid}: match search sent", "info")

            # wait for match assignment (up to 90s)
            match_found = False
            udp_host = host; udp_port = 10050
            search_start = time.time()
            while time.time() - search_start < 90.0:
                if stop_flag and stop_flag(): break
                frame_data = await recv_frame(reader, timeout=5.0)
                if frame_data is None:
                    break
                # check for match-found signal (cmd in header byte ~0x01)
                if len(frame_data) > 4:
                    match_found = True
                    _log(f"[MATCH] UID {uid}: match found!", "success")
                    break

            if not match_found:
                _log(f"[MATCH] UID {uid}: match search timeout", "warning")
                writer.close()
                region_offset += 1
                await asyncio.sleep(3.0)
                continue

            # UDP play loop
            udp = UDPMatchSession(udp_host, udp_port, aes_key, aes_iv, uid)
            udp.open()
            udp.send_hello()
            _log(f"[MATCH] UID {uid}: UDP session started", "info")

            tracker = MovementTracker()
            match_start  = time.time()
            last_fire     = time.time()
            last_move     = time.time()
            fire_interval = random.uniform(ANTI_AFK_MIN_INTERVAL, ANTI_AFK_MAX_INTERVAL)

            while time.time() - match_start < MAX_MATCH_DURATION:
                if stop_flag and stop_flag(): break
                while pause_flag and pause_flag():
                    await asyncio.sleep(1.0)

                now = time.time()

                # movement tick
                if now - last_move >= MOVEMENT_TICK_MS / 1000.0:
                    udp.send_movement(tracker)
                    last_move = now

                # anti-AFK fire
                if now - last_fire >= fire_interval:
                    udp.send_fire()
                    await asyncio.sleep(0.12)
                    udp.send_stop_fire()
                    last_fire     = now
                    fire_interval = random.uniform(ANTI_AFK_MIN_INTERVAL, ANTI_AFK_MAX_INTERVAL)

                # keep-alive TCP ping every 5s
                if int(now) % 5 == 0:
                    ka = sv_frame(b'\x00', cmd=0x0068)
                    try:
                        writer.write(ka)
                        await writer.drain()
                    except Exception:
                        break

                await asyncio.sleep(0.05)

            udp.close()
            matches_played += 1
            _log(f"[MATCH] UID {uid}: match {matches_played} complete", "success")
            region_offset += 1
            await asyncio.sleep(5.0)

        except Exception as ex:
            _log(f"[MATCH] UID {uid}: error — {ex}", "error")
        finally:
            try: writer.close()
            except Exception: pass

    return {"uid": uid, "matches_played": matches_played, "error": None}
