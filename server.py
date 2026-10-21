import gzip, hashlib, hmac, json, os, queue, random, re, secrets, sqlite3, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from engine import Game
import math
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookies import SimpleCookie

ROOT = os.path.dirname(os.path.abspath(__file__))
BOTS, STATS = os.path.join(ROOT, "bots"), os.path.join(ROOT, "stats.json")
DICE_RANGE = (3, 10)  # každá hra dostane náhodný počet kociek na hráča z tohto rozsahu
MAX_KOCAK_V_HRE = 50
cfg = dict(delay=0)  # Run bot games continuously; replay speed is controlled in the browser.
games, lock = {}, threading.Lock()

REPLAYS = os.path.join(ROOT, "replays")
os.makedirs(REPLAYS, exist_ok=True)
HIST = os.path.join(ROOT, "history.json")
history = json.load(open(HIST, encoding="utf-8")) if os.path.exists(HIST) else []
os.makedirs(BOTS, exist_ok=True)
DB = os.path.join(ROOT, "accounts.sqlite3")
INVITE_FILE = os.path.join(ROOT, "registration_code.txt")
SESSION_DAYS = 7
CATALOG_LOCK = threading.RLock()
board_cache = {}
metadata_version = 0


def db_connection():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bot_meta (
                name TEXT PRIMARY KEY,
                owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                competitive INTEGER NOT NULL DEFAULT 0 CHECK(competitive IN (0,1)),
                created_at REAL NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_competitive_per_user
                ON bot_meta(owner_id) WHERE competitive=1 AND owner_id IS NOT NULL;
        """)


def invite_code():
    override = os.environ.get("KOCKY_INVITE_CODE")
    if override:
        return override
    if not os.path.exists(INVITE_FILE):
        with open(INVITE_FILE, "x", encoding="utf-8") as f:
            f.write(secrets.token_urlsafe(18) + "\n")
        try:
            os.chmod(INVITE_FILE, 0o600)
        except OSError:
            pass
    return open(INVITE_FILE, encoding="utf-8").read().strip()


init_db()
REGISTRATION_CODE = invite_code()


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), 600_000).hex()


def register_user(username, password, invitation):
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,23}", username):
        raise ValueError("Používateľské meno: 3–24 znakov, písmená/čísla/_, začína písmenom.")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        raise ValueError("Heslo musí mať 8–128 znakov.")
    if not isinstance(invitation, str) or not hmac.compare_digest(invitation, REGISTRATION_CODE):
        raise ValueError("Nesprávny registračný kód. Vlastník servera ho nájde v registration_code.txt.")
    salt = secrets.token_hex(16)
    hashed = password_hash(password, salt)
    try:
        with db_connection() as conn:
            cur = conn.execute("INSERT INTO users(username,salt,password_hash,created_at) VALUES(?,?,?,?)",
                               (username, salt, hashed, time.time()))
            return dict(id=cur.lastrowid, username=username)
    except sqlite3.IntegrityError:
        raise ValueError("Toto používateľské meno už existuje.")


def login_user(username, password):
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 128:
        return None
    with db_connection() as conn:
        record = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    if not record:
        return None
    stored = bytes.fromhex(record["password_hash"])
    actual = bytes.fromhex(password_hash(password, record["salt"]))
    if not hmac.compare_digest(stored, actual):
        return None
    return dict(id=record["id"], username=record["username"])


def session_user(raw_token):
    if not raw_token or len(raw_token) > 128:
        return None
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    with db_connection() as conn:
        row = conn.execute("""SELECT users.id,users.username FROM sessions
             JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?""",
             (digest, time.time())).fetchone()
    return dict(row) if row else None


def create_session(user_id):
    raw = secrets.token_urlsafe(32)
    with db_connection() as conn:
        conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                     (hashlib.sha256(raw.encode()).hexdigest(), user_id, time.time() + SESSION_DAYS*86400))
    return raw


def expire_session(raw):
    if raw:
        with db_connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(raw.encode()).hexdigest(),))


def all_bot_info():
    """Existing bots without metadata remain unowned legacy bots in the casual league."""
    with CATALOG_LOCK:
        with db_connection() as conn:
            rows = conn.execute("""SELECT b.name,b.owner_id,b.competitive,u.username
                FROM bot_meta b LEFT JOIN users u ON u.id=b.owner_id""").fetchall()
        known = {r["name"]: r for r in rows}
        result = []
        for filename in sorted(os.listdir(BOTS)):
            if not filename.endswith(".py") or not re.fullmatch(r"[A-Za-z0-9_-]{1,90}\.py", filename):
                continue
            name = filename[:-3]
            r = known.get(name)
            owner = r["username"] if r else None
            display = name
            if r and owner and name.startswith(f"u{r['owner_id']}__"):
                display = name[len(f"u{r['owner_id']}__"):]
            result.append(dict(name=name, display=display, owner=owner,
                               owner_id=r["owner_id"] if r else None,
                               competitive=bool(r["competitive"]) if r else False))
        return result


def bots(league=None):
    available = all_bot_info()
    if league == "competitive":
        # Competition is restricted to one nominated bot per user.
        available = [b for b in available if b["competitive"]]
    # Casual games and the noncompetitive leaderboard include EVERY bot,
    # including bots that also participate in the competitive league.
    return [b["name"] for b in available]


def changed_bot_catalog():
    global metadata_version
    with lock:
        metadata_version += 1
        board_cache.clear()


def upload_bot(owner, filename, data):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,30}\.py", filename or ""):
        raise ValueError("Názov súboru: 1–30 znakov [a-zA-Z0-9_-] a .py.")
    if len(data) > 2_000_000:
        raise ValueError("Bot môže mať najviac 2 MB.")
    source = data.decode("utf-8-sig")
    if "def decide" not in source:
        raise ValueError("Bot musí definovať decide(state).")
    compile(source, filename, "exec")
    physical = f"u{owner['id']}__{filename[:-3]}"
    target = os.path.join(BOTS, physical + ".py")
    with CATALOG_LOCK:
        with db_connection() as conn:
            row = conn.execute("SELECT owner_id FROM bot_meta WHERE name=?", (physical,)).fetchone()
            if (row and row["owner_id"] != owner["id"]) or (not row and os.path.exists(target)):
                raise ValueError("Súbor s týmto názvom už existuje.")
            tmp = target + ".upload"
            try:
                with open(tmp, "wb") as f:
                    f.write(source.encode("utf-8"))
                os.replace(tmp, target)
                conn.execute("""INSERT INTO bot_meta(name,owner_id,competitive,created_at)
                    VALUES(?,?,0,?) ON CONFLICT(name) DO NOTHING""", (physical, owner["id"], time.time()))
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
    changed_bot_catalog()
    return physical


def set_competitive(owner, name, enabled):
    if type(enabled) is not bool:
        raise ValueError("competitive musí byť true alebo false.")
    with CATALOG_LOCK:
        with db_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT owner_id FROM bot_meta WHERE name=?", (name,)).fetchone()
            if row is None or row["owner_id"] != owner["id"] or not os.path.isfile(os.path.join(BOTS, name + ".py")):
                raise ValueError("Môžeš označiť iba svojho vlastného bota.")
            if enabled:
                conn.execute("UPDATE bot_meta SET competitive=0 WHERE owner_id=?", (owner["id"],))
            conn.execute("UPDATE bot_meta SET competitive=? WHERE name=?", (int(enabled), name))
    changed_bot_catalog()


def claim_legacy_bot(owner, name):
    """The first account may claim pre-authentication bot files, without overwriting any owner."""
    if owner["id"] != 1:
        raise ValueError("Starých botov môže prevziať iba prvý vytvorený účet.")
    with CATALOG_LOCK:
        if name not in bots():
            raise ValueError("Bot neexistuje.")
        with db_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT owner_id FROM bot_meta WHERE name=?", (name,)).fetchone()
            if existing:
                if existing["owner_id"] is not None:
                    raise ValueError("Tento bot už má vlastníka.")
                conn.execute("UPDATE bot_meta SET owner_id=? WHERE name=?", (owner["id"], name))
            else:
                conn.execute("INSERT INTO bot_meta(name,owner_id,competitive,created_at) VALUES(?,?,0,?)",
                             (name, owner["id"], time.time()))
    changed_bot_catalog()


def delete_my_bot(owner, name):
    with CATALOG_LOCK:
        with db_connection() as conn:
            row = conn.execute("SELECT owner_id FROM bot_meta WHERE name=?", (name,)).fetchone()
            if row is None or row["owner_id"] != owner["id"]:
                raise ValueError("Môžeš vymazať iba svojho bota.")
            conn.execute("DELETE FROM bot_meta WHERE name=?", (name,))
            path = os.path.join(BOTS, name + ".py")
            if os.path.isfile(path):
                os.remove(path)
    changed_bot_catalog()


def profile(user):
    mine = [b for b in all_bot_info() if b["owner_id"] == user["id"]]
    categories = {b["name"]: ("competitive" if b["competitive"] else "noncompetitive") for b in mine}
    stats = {b["name"]: dict(games=0, wins=0, points=0,
                             league_games=0, league_wins=0, league_points=0) for b in mine}
    with lock:
        recent_history = history[:]
    for record in recent_history:
        league = record.get("league", "noncompetitive")
        for name, points in record.get("points", {}).items():
            if name not in stats: continue
            r = stats[name]
            r["games"] += 1
            r["wins"] += int(record.get("winner") == name)
            r["points"] += points
            if league == categories[name]:
                r["league_games"] += 1
                r["league_wins"] += int(record.get("winner") == name)
                r["league_points"] += points
    for r in stats.values():
        r["points_per_game"] = r["points"] / r["games"] if r["games"] else 0
        r["league_points_per_game"] = r["league_points"] / r["league_games"] if r["league_games"] else 0
    return dict(user=user, bots=[{**b, **stats[b["name"]]} for b in mine],
                total_bots=len(mine), competitive_bot=next((b["name"] for b in mine if b["competitive"]), None),
                legacy=[b["name"] for b in all_bot_info() if b["owner_id"] is None] if user["id"] == 1 else [],
                admin=user["id"] == 1)


# No uploaded Python source is executed by the host Python interpreter.
# Each bot is confined to its own disposable, locked-down Linux container.
# REQUIREMENT: Docker Desktop with Linux containers, plus a locally pulled image.
BOT_IMAGE = os.environ.get("KOCKY_BOT_IMAGE", "python:3.12-slim")
DOCKER = os.environ.get("KOCKY_DOCKER", "docker")
BOT_START_TIMEOUT = 25.0       # time to start a container and import the bot
BOT_MOVE_TIMEOUT = 3.0         # decision time, excluding container startup
MAX_BOT_REPLY = 4096           # bytes per protocol line
SANDBOX_RETRY_SECONDS = 20
# Also cap authenticated users' ability to consume Docker worker resources.
MAX_ACTIVE_GAMES = 6
MAX_ACTIVE_GAMES_PER_USER = 2
MAX_CONCURRENT_BOTS = 20
sandbox_retry_after = 0.0


class SandboxError(RuntimeError):
    pass


def check_docker_sandbox():
    """Fail CLOSED; never fall back to executing uploaded code on the host."""
    try:
        info = subprocess.run([DOCKER, "info", "--format", "{{.OSType}}"],
                              capture_output=True, text=True, timeout=12, check=True)
        if info.stdout.strip() != "linux":
            raise SandboxError("Docker musi bezat v rezime Linux containers.")
        image = subprocess.run([DOCKER, "image", "inspect", BOT_IMAGE],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               text=True, timeout=12)
        if image.returncode:
            raise SandboxError(f"Chyba Docker image {BOT_IMAGE}; spusti: docker pull {BOT_IMAGE}")
        if not os.path.isfile(os.path.join(ROOT, "bot_runner.py")):
            raise SandboxError("Chyba subor bot_runner.py v priecinku projektu.")
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise SandboxError("Docker nie je spusteny alebo dostupny. Spusti Docker Desktop (Linux containers).") from exc


def validate_bot_action(action, state):
    """Validate shape AND legality before passing anything to the game engine."""
    if type(action) is not dict:
        raise ValueError("Bot must return a JSON object")
    kind = action.get("action")
    if kind == "call":
        if set(action) != {"action"} or not state["can_call"]:
            raise ValueError("Invalid call")
    elif kind == "bid":
        if (set(action) != {"action", "count", "face"}
                or type(action["count"]) is not int or type(action["face"]) is not int
                or [action["count"], action["face"]] not in state["legal_bids"]):
            raise ValueError("Invalid bid")
    elif kind == "reveal":
        indices = action.get("indices")
        if (set(action) != {"action", "indices"} or type(indices) is not list
                or not indices or len(indices) > len(state["your_dice"])
                or any(type(i) is not int or i < 0 or i >= len(state["your_dice"]) for i in indices)
                or len(set(indices)) != len(indices)
                or state["must_raise"] or not state["legal_bids"]):
            raise ValueError("Invalid reveal")
    else:
        raise ValueError("Unknown bot action")
    return action


class BotProc:
    """One persistent container per bot per game. Never executes bot code locally."""
    def __init__(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,90}", name):
            raise SandboxError("Invalid bot name")
        source = os.path.abspath(os.path.join(BOTS, name + ".py"))
        bot_dir = os.path.realpath(BOTS)
        if (os.path.islink(source) or not os.path.isfile(source)
                or os.path.realpath(os.path.dirname(source)) != bot_dir):
            raise SandboxError("Bot file missing or unsafe")
        runner = os.path.abspath(os.path.join(ROOT, "bot_runner.py"))
        if not os.path.isfile(runner):
            raise SandboxError("Missing bot_runner.py")
        # Docker's --mount syntax uses commas as separators. Reject ambiguous paths.
        if any(c in source + runner for c in (",", "\n", "\r")):
            raise SandboxError("Folder paths must not contain commas or line breaks")

        self.container = "kocky-bot-" + secrets.token_hex(12)
        self.q = queue.Queue(maxsize=2)
        self.problem = None
        self.closed = False
        self.p = None
        args = [
            DOCKER, "run", "--rm", "-i", "--pull=never", "--name", self.container,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=65534:65534",
            "--pids-limit=16", "--memory=256m", "--memory-swap=256m",
            "--cpus=1.0", "--ulimit=nofile=64:64", "--shm-size=8m",
            "--log-driver=none", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--workdir=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1",
            "--mount", f"type=bind,source={source},target=/sandbox/bot.py,readonly",
            "--mount", f"type=bind,source={runner},target=/sandbox/runner.py,readonly",
            BOT_IMAGE, "python", "-I", "-B", "-u", "/sandbox/runner.py", "/sandbox/bot.py"
        ]
        try:
            self.p = subprocess.Popen(args, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      bufsize=0)
            threading.Thread(target=self._read, name="sandbox-stdout", daemon=True).start()
            ready = self._recv(BOT_START_TIMEOUT)
            if ready != {"status": "ready"}:
                raise SandboxError("Bot import/sandbox startup failed")
        except Exception as exc:
            self.close()
            if isinstance(exc, SandboxError):
                raise
            raise SandboxError("Failed to launch bot sandbox: " + type(exc).__name__) from exc

    def _read(self):
        try:
            while True:
                line = self.p.stdout.readline(MAX_BOT_REPLY + 1)
                if not line:
                    self.q.put_nowait(None) if not self.q.full() else None
                    return
                if len(line) > MAX_BOT_REPLY or not line.endswith(b"\n"):
                    self.problem = "Bot response exceeded size limit"
                    self.p.kill()
                    return
                try:
                    self.q.put_nowait(line)
                except queue.Full:
                    self.problem = "Bot sent unsolicited/flooded responses"
                    self.p.kill()
                    return
        except (OSError, ValueError):
            self.problem = "Bot protocol stream failed"

    def _recv(self, timeout):
        try:
            raw = self.q.get(timeout=timeout)
        except queue.Empty as exc:
            raise SandboxError(self.problem or "Bot timed out") from exc
        if raw is None or self.problem:
            raise SandboxError(self.problem or "Bot process exited")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise SandboxError("Invalid JSON from bot") from exc

    def ask(self, state, t=BOT_MOVE_TIMEOUT):
        if self.closed:
            return {"error": "Bot sandbox is no longer running"}
        try:
            payload = json.dumps(state, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
            if len(payload) > 262144:
                raise SandboxError("State too large")
            self.p.stdin.write(payload)
            self.p.stdin.flush()
            return validate_bot_action(self._recv(t), state)
        except (OSError, BrokenPipeError, ValueError, SandboxError) as exc:
            self.close()
            return {"error": str(exc)[:120]}

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.p is None:
            return
        try:
            self.p.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.p.wait(timeout=0.35)
            return
        except subprocess.TimeoutExpired:
            pass
        # Killing the Docker CLI alone may leave the container running.
        # Force-remove by the unguessable container name (no user-controlled name).
        try:
            subprocess.run([DOCKER, "rm", "--force", self.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            self.p.kill()
            self.p.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def fallback(v):
    if v["can_call"]: return {"action": "call"}
    c, f = v["legal_bids"][0]; return {"action": "bid", "count": c, "face": f}

def track(m):  # remember the order in which players ran out of dice
    g = m["game"]; out = m.setdefault("out", [])
    out += [i for i in range(len(g.names)) if not g.size(i) and i not in out]

def finish(m):  # points = place counted from the bottom: first out 0 ... winner N-1
    g, out = m["game"], m.get("out", [])
    rest = sorted((i for i in range(len(g.names)) if i not in out and i != g.winner), key=g.size)
    order = out + rest + [g.winner]
    rec = dict(id=m["id"], t=m["t"], names=g.names, winner=g.names[g.winner],
               points={g.names[i]: k for k, i in enumerate(order)}, league=m.get("league", "noncompetitive"))
    # Store a compact, persistent replay before exposing the match in history.
    if m["frames"] is not None:
        path = os.path.join(REPLAYS, m["id"] + ".json.gz")
        tmp = path + ".tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            json.dump({"id": m["id"], "status": "finished", "frames": m["frames"]},
                      f, separators=(",", ":"))
        os.replace(tmp, path)
    with lock:
        history.append(rec); json.dump(history, open(HIST, "w"))

AVG_WINDOWS = (25, 50, 75, 100, 150, 200, 250, 300, 400, 500)


def leaderboard(window=50, league="noncompetitive"):
    """Separate series for competitive and casual matches. Legacy matches are casual."""
    names = bots(league)
    with lock:
        recent_history = history[:]
        cache_key = (league, window, len(recent_history), metadata_version)
        if cache_key in board_cache:
            return board_cache[cache_key]

    rows = {n: dict(name=n, points=0, games=0, wins=0) for n in names}
    recent = {n: deque(maxlen=window) for n in names}
    recent_totals = {n: 0 for n in names}
    series = {n: deque(maxlen=200) for n in names}
    avgs = {n: deque(maxlen=200) for n in names}

    for record in recent_history:
        if record.get("league", "noncompetitive") != league:
            continue
        for name, points in record["points"].items():
            if name not in rows:
                continue
            row = rows[name]
            row["points"] += points
            row["games"] += 1
            row["wins"] += name == record["winner"]
            values = recent[name]
            if len(values) == window:
                recent_totals[name] -= values[0]
            values.append(points)
            recent_totals[name] += points

        # Include stationary values for rounds where a given bot did not play.
        for name in names:
            series[name].append(rows[name]["points"])
            played = len(recent[name])
            avgs[name].append(recent_totals[name] / played if played else 0)

    result = sorted(rows.values(), key=lambda row: (-row["points"], row["name"]))
    for row in result:
        name = row["name"]
        played = len(recent[name])
        row["avg_recent"] = recent_totals[name] / played if played else 0
        row["points_per_game"] = row["points"] / row["games"] if row["games"] else 0
        if window == 50:
            row["avg50"] = row["avg_recent"]  # Compatibility with older clients.

    data = dict(
        rows=result,
        series={n: list(v) for n, v in series.items()},
        avgseries={n: list(v) for n, v in avgs.items()},
        matches=recent_history[-50:][::-1],
        window=window,
        league=league,
    )
    with lock:
        if len(history) == len(recent_history) and metadata_version == cache_key[3]:
            board_cache[cache_key] = data
            if len(board_cache) > 25:
                board_cache.clear()
                board_cache[cache_key] = data
    return data

def matches_page(offset=0, limit=40):
    # Page through all recorded matches, newest first (without loading them all in the browser).
    with lock:
        count = len(history)
        page = list(history[max(0, count-offset-limit):max(0, count-offset)])[::-1]
    return {"total": count, "offset": offset, "matches": [
        {**r, "replay": os.path.isfile(os.path.join(REPLAYS, r["id"] + ".json.gz"))}
        for r in page]}


def replay_frame(g, action=None):
    """Freeze a spectator view after each action for browser playback."""
    return dict(names=g.names, you=None, turn=g.turn, round=g.round,
                bid=g.bid[:] if g.bid is not None else None, bidder=g.bidder,
                must_raise=g.must_raise, shown=[h[:] for h in g.shown],
                hidden_counts=[len(h) for h in g.hidden],
                all_hidden=[h[:] for h in g.hidden], winner=g.winner,
                log=g.log[-60:].copy(), action=action)

def run_game(gid):
    global sandbox_retry_after
    m = games[gid]; g, h = m["game"], m["human"]
    procs = {}
    completed = False
    try:
        # Docker Desktop startup is relatively expensive; initialize workers
        # concurrently without ever sharing code or files between containers.
        competitors = [(i, n) for i, n in enumerate(m["names"]) if i != h]
        errors = []
        with ThreadPoolExecutor(max_workers=min(6, len(competitors))) as pool:
            futures = {pool.submit(BotProc, n): i for i, n in competitors}
            for future in as_completed(futures):
                try:
                    procs[futures[future]] = future.result()
                except SandboxError as exc:
                    errors.append(exc)
        if errors:
            raise errors[0]
        while g.winner is None:
            i = g.turn
            if i == h:
                if time.time() - m["last_act"] > 900: m["status"] = "abandoned"; return
                time.sleep(0.2); continue
            if m.get("debug") and not m.get("auto"):  # debug game: wait for a "Next action" click
                if not m["go"].wait(0.3):
                    if time.time() - m["last_act"] > 900: m["status"] = "abandoned"; return
                    continue
                m["go"].clear()
            else: time.sleep(cfg["delay"])
            with m["lock"]: v = g.view(i)
            a = procs[i].ask(v); note = ""
            with m["lock"]:
                try: g.act(i, a)
                except Exception as e:
                    note = f"invalid move ({e}); fallback played"
                    g.say(f"{g.names[i]} sent an invalid move ({e}); fallback played."); g.act(i, fallback(v))
                track(m)
                m["n"] = m.get("n", 0) + 1  # what the bot saw and answered, shown in the debug panel
                m["trace"] = dict(n=m["n"], bot=g.names[i], response=a, note=note,
                                  state={**{k: x for k, x in v.items() if k not in ("log", "legal_bids")},
                                         "legal_bids": f"{len(v['legal_bids'])} options, lowest {v['legal_bids'][:2]}"})
                if m["frames"] is not None:
                    m["frames"].append(replay_frame(g, dict(bot=g.names[i], response=a, note=note)))
        if not m.get("debug") and h is None: finish(m)  # Human/debug games do not affect rankings.
        completed = True
    except SandboxError as exc:
        sandbox_retry_after = time.monotonic() + SANDBOX_RETRY_SECONDS
        m["status"] = "error"
        print("Bot sandbox failed:", str(exc), file=sys.stderr)
    except Exception as exc:
        m["status"] = "error"
        print("Game error:", repr(exc), file=sys.stderr)
    finally:
        for p in procs.values(): p.close()
        if completed:
            # Keep the match running until all Docker workers have exited.
            m["status"] = "finished"

def start(opp=None, human=False, pick=None, dice=None, chosen_bots=None, league="noncompetitive", owner_id=None):
    """Create a game. In human games choose 1-9 specific or random opponents.

    The total number of starting dice across all players must not exceed 50.
    """
    available = bots(league) if not human and pick is None else bots()
    if pick is not None:                 # Preserve debug-game seating order.
        names = list(pick)
    elif human and chosen_bots is not None:
        if not isinstance(chosen_bots, list) or not 1 <= len(chosen_bots) <= 9:
            raise ValueError("Choose between 1 and 9 bots")
        if len(set(chosen_bots)) != len(chosen_bots):
            raise ValueError("Each bot can be selected only once")
        if any(n not in available for n in chosen_bots):
            raise ValueError("One or more selected bots are no longer available")
        names = list(chosen_bots) + ["You"]
        random.shuffle(names)
    else:
        minimum = 1 if human else 2
        maximum = min(len(available), 9) if human else len(available)
        if maximum < minimum:
            return None
        if opp is None or opp == "":
            count = random.randint(minimum, maximum if human else min(maximum, 10))
        else:
            if type(opp) is not int or not minimum <= opp <= maximum:
                raise ValueError(f"Choose between {minimum} and {maximum} bot opponents")
            count = opp
        names = random.sample(available, count) + (["You"] if human else [])
        random.shuffle(names)

    if len(names) < 2:
        return None
    maximum_dice = MAX_KOCAK_V_HRE // len(names)
    if dice is None or dice == "":
        low, high = min(DICE_RANGE[0], maximum_dice), min(DICE_RANGE[1], maximum_dice)
        dice = random.randint(low, high)
    else:
        if type(dice) is not int or not 1 <= dice <= maximum_dice:
            raise ValueError(f"Choose 1 to {maximum_dice} dice per player ({MAX_KOCAK_V_HRE} total maximum)")

    gid = str(time.time_ns())
    g = Game(names, dice)
    with lock:
        active = [m for m in games.values() if m["status"] == "running"]
        active_workers = sum(len(m["names"]) - (m["human"] is not None) for m in active)
        needed_workers = len(names) - int(human)
        if len(active) >= MAX_ACTIVE_GAMES or active_workers + needed_workers > MAX_CONCURRENT_BOTS:
            raise ValueError("Server ma teraz privela beziach hier; skus neskor.")
        if owner_id is not None and sum(m.get("owner_id") == owner_id for m in active) >= MAX_ACTIVE_GAMES_PER_USER:
            raise ValueError("Mozes mat najviac dve aktivne vlastne hry naraz.")
        games[gid] = dict(id=gid, names=names, human=names.index("You") if human else None, owner_id=owner_id, league=league, status="running",
                          lock=threading.Lock(), game=g, dice=dice, t=time.time(), last_act=time.time(),
                          debug=bool(pick), go=threading.Event(),
                          frames=[replay_frame(g)] if not human and not pick else None)
        for old in sorted(games, reverse=True)[25:]:
            if games[old]["status"] != "running": del games[old]
    threading.Thread(target=run_game, args=(gid,), daemon=True).start()
    return gid

def scheduler():
    previous = "noncompetitive"
    while True:
        if time.monotonic() < sandbox_retry_after:
            time.sleep(1)
            continue
        with lock:
            running = any(m["status"] == "running" and m["human"] is None and not m["debug"]
                          and m.get("auto_scheduled", False) for m in games.values())
        if not running:
            available = [tier for tier in ("competitive", "noncompetitive") if len(bots(tier)) >= 2]
            if available:
                tier = next((tier for tier in available if tier != previous), available[0])
                try:
                    gid = start(league=tier)
                except ValueError:
                    gid = None  # All sandbox worker slots are currently in use.
                if gid:
                    with lock:
                        games[gid]["auto_scheduled"] = True
                    previous = tier
        time.sleep(0.2)

def state(user=None):
    with lock:
        gl = sorted((m for m in games.values() if
                     (m["human"] is None and not m.get("debug")) or
                     (user is not None and m.get("owner_id") == user["id"])),
                    key=lambda m: m["t"], reverse=True)
    info = all_bot_info()
    # Sidebar stats show wins / games across both leagues, not just the
    # last leaderboard processed. Competitive bots can play in both.
    results = {}
    for tier in ("competitive", "noncompetitive"):
        for r in leaderboard(league=tier)["rows"]:
            total = results.setdefault(r["name"], {"games": 0, "wins": 0})
            total["games"] += r["games"]
            total["wins"] += r["wins"]
    return dict(cfg=cfg, bots=[{**b, "games": results.get(b["name"], {}).get("games", 0),
                                 "wins": results.get(b["name"], {}).get("wins", 0)} for b in info],
                games=[dict(id=m["id"], names=m["names"], league=m.get("league", "noncompetitive"),
                            status=m["status"], debug=m.get("debug", False),
                            replay=m["frames"] is not None, dice=m["dice"],
                            human=m["human"] is not None,
                            winner=None if m["game"].winner is None else m["names"][m["game"].winner]) for m in gl])

class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, obj, code=200, ctype="application/json", cookie=None):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def body(self, max_bytes=2_000_000):
        size = int(self.headers.get("Content-Length", 0))
        if size < 0 or size > max_bytes:
            raise ValueError("Príliš veľká požiadavka.")
        return self.rfile.read(size)

    def json_body(self):
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Použi application/json.")
        d = json.loads(self.body(100_000))
        if not isinstance(d, dict):
            raise ValueError("Očakáva sa JSON objekt.")
        return d

    def token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["sid"].value if "sid" in cookie else None
        except Exception:
            return None

    def user(self):
        return session_user(self.token())

    def need_user(self):
        user = self.user()
        if user is None:
            self.reply({"error": "Na túto akciu sa musíš prihlásiť."}, 401)
        return user

    def cookie_header(self, token=None):
        secure = "; Secure" if os.environ.get("KOCKY_SECURE_COOKIE") == "1" else ""
        if token:
            return f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_DAYS*86400}{secure}"
        return f"sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        p = path.strip("/").split("/")
        if path == "/":
            return self.reply(open(os.path.join(ROOT, "index.html"), "rb").read(),
                              ctype="text/html; charset=utf-8")
        if path == "/api/auth/me":
            return self.reply({"user": self.user()})
        if path == "/api/profile":
            user = self.need_user()
            if not user: return
            return self.reply(profile(user))
        if path == "/api/state":
            return self.reply(state(self.user()))
        if path == "/api/leaderboard":
            try:
                q = parse_qs(u.query)
                window = int(q.get("window", ["50"])[0])
                league = q.get("league", ["noncompetitive"])[0]
                if window not in AVG_WINDOWS: raise ValueError("Neplatný počet hier.")
                if league not in ("competitive", "noncompetitive"): raise ValueError("Neplatný leaderboard.")
            except (ValueError, TypeError) as exc:
                return self.reply({"error": str(exc)}, 400)
            return self.reply(leaderboard(window, league))
        if path == "/api/matches":
            try:
                offset = max(0, int(parse_qs(u.query).get("offset", ["0"])[0]))
            except ValueError:
                return self.reply({"error": "Neplatná stránka."}, 400)
            return self.reply(matches_page(offset))
        if len(p) == 4 and p[:2] == ["api", "bot"] and p[3] == "download":
            user = self.need_user()
            if not user: return
            name = p[2]
            bot = next((b for b in all_bot_info() if b["name"] == name and b["owner_id"] == user["id"]), None)
            if not bot:
                return self.reply({"error": "Nie si vlastníkom bota."}, 403)
            body = open(os.path.join(BOTS, name + ".py"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/x-python; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="' + bot["display"] + '.py"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(body)
        if path == "/api/template":
            filename = os.path.join(BOTS, "def.py")
            if not os.path.isfile(filename):
                return self.reply({"error": "Chýba predvolený bot def.py."}, 404)
            body = open(filename, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/x-python; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="def.py"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if p[:2] == ["api", "game"] and len(p) == 4 and p[3] == "replay":
            gid = p[2]
            if not re.fullmatch(r"[0-9]+", gid):
                return self.reply({"error": "Invalid match ID"}, 400)
            m = games.get(gid)
            if m is not None and m["frames"] is not None:
                with m["lock"]:
                    return self.reply({"id": m["id"], "status": m["status"], "frames": m["frames"]})
            source = os.path.join(REPLAYS, gid + ".json.gz")
            if os.path.isfile(source):
                with gzip.open(source, "rt", encoding="utf-8") as f:
                    return self.reply(json.load(f))
            return self.reply({"error": "Bez zaznamenaného replaya."}, 404)
        if p[:2] == ["api", "game"] and len(p) == 3 and p[2] in games:
            m = games[p[2]]
            if m["human"] is not None and m.get("owner_id") != (self.user() or {}).get("id"):
                return self.reply({"error": "Táto súkromná hra patrí inému účtu."}, 403)
            g, h = m["game"], m["human"]
            with m["lock"]:
                v = g.view(h) if h is not None and g.winner is None else g.view(h, spectate=True)
                v.update(id=m["id"], status=m["status"], debug=m.get("debug", False),
                         auto=m.get("auto", False), trace=m.get("trace"))
                return self.reply(v)
        return self.reply({"error": "not found"}, 404)

    def do_POST(self):
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin and origin not in ("http://" + host, "https://" + host):
            return self.reply({"error": "Zakázaná požiadavka z inej stránky."}, 403)
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.strip("/").split("/")
        try:
            if u.path == "/api/auth/register":
                j = self.json_body()
                user = register_user(j.get("username"), j.get("password"), j.get("invite"))
                return self.reply({"user": user}, cookie=self.cookie_header(create_session(user["id"])))
            if u.path == "/api/auth/login":
                j = self.json_body()
                user = login_user(j.get("username"), j.get("password"))
                if not user:
                    return self.reply({"error": "Nesprávne meno alebo heslo."}, 401)
                return self.reply({"user": user}, cookie=self.cookie_header(create_session(user["id"])))
            if u.path == "/api/auth/logout":
                expire_session(self.token())
                return self.reply({"ok": True}, cookie=self.cookie_header())
            user = self.need_user()
            if not user: return
            if u.path == "/api/upload":
                name = q.get("name", [""])[0]
                filename = upload_bot(user, name, self.body())
                return self.reply({"ok": True, "name": filename})
            if u.path == "/api/delete":
                delete_my_bot(user, q.get("name", [""])[0])
                return self.reply({"ok": True})
            if u.path == "/api/bots/claim":
                j = self.json_body()
                claim_legacy_bot(user, j.get("name"))
                return self.reply({"ok": True})
            if u.path == "/api/bots/competitive":
                j = self.json_body()
                set_competitive(user, j.get("name"), j.get("competitive"))
                return self.reply({"ok": True})
            if u.path == "/api/debug":
                j = self.json_body()
                pick = list(dict.fromkeys(n for n in j.get("bots", []) if n in bots()))
                if len(pick) < 2:
                    raise ValueError("Pick at least 2 bots")
                return self.reply({"id": start(pick=pick, dice=j.get("dice"), owner_id=user["id"])})
            if u.path in ("/api/run", "/api/play"):
                j = self.json_body()
                human = u.path == "/api/play"
                gid = start(j.get("opponents"), human=human, dice=j.get("dice"),
                            chosen_bots=j.get("bots") if human and "bots" in j else None,
                            owner_id=user["id"])
                if not gid:
                    raise ValueError("Najprv nahraj ďalších botov (aspoň 2 na simuláciu, 1 na vlastnú hru).")
                return self.reply({"id": gid})
            if len(p) == 4 and p[:2] == ["api", "game"] and p[2] in games and p[3] in ("step", "auto"):
                m = games[p[2]]
                if not m.get("debug") or m.get("owner_id") != user["id"]:
                    return self.reply({"error": "Nemáš oprávnenie ovládať túto hru."}, 403)
                m["last_act"] = time.time()
                if p[3] == "auto": m["auto"] = True
                m["go"].set()
                return self.reply({"ok": True})
            if len(p) == 4 and p[:2] == ["api", "game"] and p[2] in games and p[3] == "act":
                m = games[p[2]]
                if m.get("owner_id") != user["id"] or m["human"] is None:
                    return self.reply({"error": "Nemáš oprávnenie ovládať túto hru."}, 403)
                a = self.json_body()
                with m["lock"]:
                    m["game"].act(m["human"], a)
                    m["last_act"] = time.time()
                    track(m)
                return self.reply({"ok": True})
            return self.reply({"error": "not found"}, 404)
        except (ValueError, json.JSONDecodeError, UnicodeError, SyntaxError) as exc:
            return self.reply({"error": str(exc)}, 400)
        except Exception as exc:
            # Never leak database paths or stack traces to arbitrary clients.
            print("Request failed:", repr(exc), file=sys.stderr)
            return self.reply({"error": "Interná chyba servera."}, 500)


def sandbox_selftest():
    """Run a benign probe in a REAL container; never execute this probe on the host."""
    global BOTS
    script = '''def decide(state):
    import os, socket
    # Other bots, the project database, and host files were NOT mounted.
    for path in ("/sandbox/other_bot.py", "/sandbox/server.py",
                 "/sandbox/accounts.sqlite3", "/host/etc/passwd"):
        try:
            with open(path, "rb") as f: f.read(1)
            return {"action": "unsafe_read"}
        except OSError:
            pass
    # Neither our own source nor container OS files may be modified.
    for path in ("/sandbox/bot.py", "/sandbox/runner.py", "/etc/passwd"):
        try:
            with open(path, "ab") as f: f.write(b"x")
            return {"action": "unsafe_write"}
        except OSError:
            pass
    # With --network=none, only the local loopback interface is visible.
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        return {"action": "unsafe_network"}
    count, face = state["legal_bids"][0]
    return {"action": "bid", "count": count, "face": face}
'''
    with tempfile.TemporaryDirectory(prefix="kocky-sandbox-test-") as tempdir:
        name = "sandbox_probe"
        with open(os.path.join(tempdir, name + ".py"), "w", encoding="utf-8") as file:
            file.write(script)
        old_bot_dir = BOTS
        BOTS = tempdir
        try:
            probe = BotProc(name)
            try:
                from engine import Game
                state = Game([name, "other"], dice=2, seed=1).view(0)
                response = probe.ask(state)
                validate_bot_action(response, state)
                if response["action"] != "bid":
                    raise SandboxError("Sandbox probe did not return the expected action")
            finally:
                probe.close()
        finally:
            BOTS = old_bot_dir
    print("Sandbox test PASS: no host-project reads, no writes, no external network.")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--check-sandbox":
        try:
            check_docker_sandbox()
            sandbox_selftest()
        except (SandboxError, ValueError) as exc:
            raise SystemExit("Sandbox test FAILED: " + str(exc))
        raise SystemExit(0)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    try:
        check_docker_sandbox()
    except SandboxError as exc:
        raise SystemExit("BEZPECNOST: " + str(exc) + "\nNespustam server, lebo boti nesmu bezat mimo sandboxu.")
    print("Registračný kód (zdieľaj iba s dôveryhodnými účastníkmi):", REGISTRATION_CODE)
    print("Bot security: Docker Linux sandbox, isolated per bot, no network, read-only mounts.")
    threading.Thread(target=scheduler, daemon=True).start()
    print(f"Liar's Dice listening on port {port}; http://localhost:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
