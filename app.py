"""
보안 강화 사내 메모장 백엔드 (Flask + MariaDB)

레거시 엔드포인트·응답 형식은 그대로 유지하고, 내부 구현과 보안만 교체했다.
  GET  /             메모장 화면 (templates/index.html)
  POST /api/login    {message, student_name, github_id}  + JWT 는 HttpOnly 쿠키로만
  GET  /api/memos    [{id, author, content}]  (전체 사용자 메모)
  POST /api/memos    {message, memo: {id, author, content}}  (201)
  GET  /health       DB 연결까지 확인 (CI/CD 헬스체크용)
  추가: GET /api/csrf, GET /api/me, POST /api/logout

보안
- 인증   : Stateless JWT(HS256, 15분) → HttpOnly / SameSite=Lax / Path=/ 쿠키, Secure 는 COOKIE_SECURE
- CSRF   : 서명된 Double Submit Cookie(csrf_token) + X-CSRF-Token 헤더 hmac.compare_digest 비교
- Replay : jti 블랙리스트 테이블 + 요청별 Nonce(1회용, DB 저장) / Timestamp(±30초)
- XSS    : 저장 시 html.escape, 프론트는 textContent 만 사용, CSP(script-src 'self')
- 설정   : DB 정보·비밀키는 전부 os.environ.get() (하드코딩 없음)
"""
import hashlib
import hmac
import html
import logging
import os
import random
import re
import secrets
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
import pymysql
from flask import Flask, g, jsonify, render_template, request

try:  # .env 파일이 있으면 환경변수로 올려준다 (없어도 동작)
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("secure-memo")


# ─────────────────────────────────────────────
# 1. 환경변수 설정 (하드코딩 금지)
# ─────────────────────────────────────────────
def env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"필수 환경변수 {name} 가 설정되지 않았습니다. (.env.example 참고)")
    return value


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DB_CONFIG = {
    "host": env_required("DB_HOST"),
    "port": env_int("DB_PORT", 3306),
    "user": env_required("DB_USER"),
    "password": env_required("DB_PASSWORD"),
    "database": env_required("DB_NAME"),
}

JWT_SECRET_KEY = env_required("JWT_SECRET_KEY")
CSRF_SECRET_KEY = env_required("CSRF_SECRET_KEY")
if len(JWT_SECRET_KEY) < 32 or len(CSRF_SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY / CSRF_SECRET_KEY 는 32자 이상이어야 합니다.")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "secure-memo")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "secure-memo-web")
ACCESS_TOKEN_MINUTES = env_int("ACCESS_TOKEN_MINUTES", 15)  # 짧은 만료시간

REPLAY_WINDOW_SECONDS = env_int("REPLAY_WINDOW_SECONDS", 30)  # Timestamp 허용 오차 ±30초
COOKIE_SECURE = env_bool("COOKIE_SECURE", False)  # Nginx 가 HTTP 80 일 수 있어 기본 false
TRUSTED_ORIGINS = {o.strip() for o in os.environ.get("TRUSTED_ORIGINS", "").split(",") if o.strip()}

SEED_USERNAME = os.environ.get("SEED_USERNAME", "tester")
SEED_PASSWORD = env_required("SEED_PASSWORD")
SEED_DISPLAY_NAME = os.environ.get("SEED_DISPLAY_NAME", "유형환")
SEED_GITHUB_ID = env_required("SEED_GITHUB_ID")

# 레거시의 "시스템" 초기 메모용 계정 (무작위 비밀번호 + 로그인 자체 차단)
SYSTEM_USERNAME = "system"
SYSTEM_AUTHOR = "시스템"
INITIAL_MEMO = "초기 테스트 메모입니다."

MEMO_MAX_LENGTH = 2000
INIT_LOCK_NAME = "secure_memo_init"
ACCESS_COOKIE = "access_token"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
NONCE_HEADER = "X-Request-Nonce"
TIMESTAMP_HEADER = "X-Request-Timestamp"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
NONCE_RE = re.compile(r"^[A-Za-z0-9-]{16,64}$")

app = Flask(__name__, static_folder="static", static_url_path="/static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 요청 본문 16KB 제한
app.json.ensure_ascii = False

if env_bool("TRUST_PROXY", False):
    # Nginx 뒤에서 실행될 때: X-Forwarded-For/Proto/Host 를 프록시 1단계만 신뢰
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ─────────────────────────────────────────────
# 2. DB 연결 / 스키마 / 시드 데이터
# ─────────────────────────────────────────────
def _connect():
    return pymysql.connect(
        **DB_CONFIG,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=5,
    )


def get_db():
    if "db" not in g:
        g.db = _connect()
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try:
            if exc is not None:
                db.rollback()
        finally:
            db.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(100) NOT NULL,
        created_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE TABLE IF NOT EXISTS profiles (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL UNIQUE,
        display_name VARCHAR(50) NOT NULL,
        github_id VARCHAR(39) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE TABLE IF NOT EXISTS memos (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    # 로그아웃·폐기된 JWT 의 jti 블랙리스트 (토큰 만료 시각까지만 보관)
    """CREATE TABLE IF NOT EXISTS revoked_tokens (
        jti CHAR(36) NOT NULL PRIMARY KEY,
        expires_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    # 이미 사용된 요청 Nonce. 메모리가 아닌 DB 라서 멀티워커에서도 공유됨
    """CREATE TABLE IF NOT EXISTS request_nonces (
        nonce VARCHAR(64) NOT NULL PRIMARY KEY,
        expires_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


def utcnow() -> datetime:
    """DB에는 UTC 기준 naive datetime 으로 저장한다."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ensure_user(cur, username: str, password: str | bytes, name: str, github_id: str) -> int:
    """유저 + 프로필이 없을 때만 생성하고 user id 를 돌려준다 (멱등)."""
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    if row is None:
        raw = password.encode("utf-8") if isinstance(password, str) else password
        pw_hash = bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode()
        cur.execute(
            "INSERT IGNORE INTO users (username, password_hash, created_at) VALUES (%s, %s, %s)",
            (username, pw_hash, utcnow()),
        )
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        log.info("시드: 계정 '%s' 생성", username)
    cur.execute(
        "INSERT IGNORE INTO profiles (user_id, display_name, github_id) VALUES (%s, %s, %s)",
        (row["id"], name, github_id),
    )
    return row["id"]


def seed_data(cur):
    # 테스트 계정 + 내 프로필 (student_name / github_id)
    _ensure_user(cur, SEED_USERNAME, SEED_PASSWORD, SEED_DISPLAY_NAME, SEED_GITHUB_ID)

    # 레거시와 같은 "시스템" 초기 메모. 시스템 계정은 아무도 모르는 무작위 비밀번호이고
    # login() 에서 이 계정의 로그인 자체를 막는다.
    system_id = _ensure_user(cur, SYSTEM_USERNAME, secrets.token_bytes(32), SYSTEM_AUTHOR, "")
    cur.execute("SELECT 1 FROM memos WHERE user_id = %s LIMIT 1", (system_id,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO memos (user_id, content, created_at) VALUES (%s, %s, %s)",
            (system_id, escape_html(INITIAL_MEMO), utcnow()),
        )
        log.info("시드: 초기 메모 생성")


def init_db(retries: int = 10, delay: float = 3.0):
    """앱 시작 시 테이블 생성 + 시드.

    - DB 가 늦게 뜨는 경우를 대비해 연결 재시도
    - Gunicorn 워커 여러 개가 동시에 실행해도 MariaDB 이름 잠금(GET_LOCK)으로
      한 번에 한 프로세스만 초기화하고, 나머지는 기다렸다가 "이미 있음"을 보고 건너뛴다.
    """
    for attempt in range(1, retries + 1):
        try:
            conn = _connect()
            break
        except pymysql.err.OperationalError as e:
            log.warning("DB 연결 실패 (%d/%d): %s", attempt, retries, e)
            if attempt == retries:
                raise
            time.sleep(delay)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT GET_LOCK(%s, %s) AS got", (INIT_LOCK_NAME, 60))
            if not cur.fetchone()["got"]:
                raise RuntimeError("DB 초기화 잠금을 얻지 못했습니다.")
            try:
                for stmt in SCHEMA:
                    cur.execute(stmt)
                seed_data(cur)
                conn.commit()
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s) AS released", (INIT_LOCK_NAME,))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cleanup_expired(conn):
    """만료된 nonce / 폐기 토큰 정리 (요청의 약 2%에서만 실행)."""
    if random.random() > 0.02:
        return
    with conn.cursor() as cur:
        now = utcnow()
        cur.execute("DELETE FROM request_nonces WHERE expires_at < %s", (now,))
        cur.execute("DELETE FROM revoked_tokens WHERE expires_at < %s", (now,))
    conn.commit()


# ─────────────────────────────────────────────
# 3. 보안 유틸: CSRF / Replay / JWT / 쿠키
# ─────────────────────────────────────────────
class SecurityError(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.message = message
        self.status = status


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _csrf_sign(raw: str) -> str:
    return hmac.new(CSRF_SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()


def new_csrf_token() -> str:
    """서명된 CSRF 토큰: <랜덤>.<HMAC>. 공격자가 쿠키에 임의 값을 심어도 서명이 안 맞아 거부된다."""
    raw = secrets.token_urlsafe(32)
    return f"{raw}.{_csrf_sign(raw)}"


def csrf_signature_ok(token: str) -> bool:
    raw, _, sig = token.partition(".")
    return bool(raw and sig) and hmac.compare_digest(sig, _csrf_sign(raw))


def check_origin():
    """Origin 헤더가 있으면 같은 출처인지 확인 (브라우저의 교차 출처 POST 차단)."""
    allowed = TRUSTED_ORIGINS or {request.host_url.rstrip("/")}
    origin = request.headers.get("Origin")
    if origin and origin.rstrip("/") not in allowed:
        raise SecurityError("허용되지 않은 출처의 요청입니다.")


def check_csrf(bound_hash: str | None = None):
    """Double Submit Cookie: 쿠키 값 == X-CSRF-Token 헤더 값 (hmac.compare_digest) + 서명 + JWT 바인딩."""
    check_origin()
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get(CSRF_HEADER, "")
    if not cookie_token or not header_token:
        raise SecurityError("CSRF 토큰이 없습니다.")
    if not hmac.compare_digest(cookie_token, header_token):
        raise SecurityError("CSRF 토큰이 일치하지 않습니다.")
    if not csrf_signature_ok(cookie_token):
        raise SecurityError("CSRF 토큰 서명이 올바르지 않습니다.")
    if bound_hash is not None and not hmac.compare_digest(bound_hash, _sha256(cookie_token)):
        raise SecurityError("세션과 CSRF 토큰이 일치하지 않습니다.")


def check_replay():
    """Timestamp ±30초 + 1회용 Nonce(MariaDB 저장). 같은 Nonce 가 다시 오면 403."""
    ts_raw = request.headers.get(TIMESTAMP_HEADER, "")
    nonce = request.headers.get(NONCE_HEADER, "")
    try:
        ts = int(ts_raw)
    except ValueError:
        raise SecurityError("요청 타임스탬프가 없거나 형식이 잘못됐습니다.", 401)
    if abs(time.time() - ts) > REPLAY_WINDOW_SECONDS:
        raise SecurityError("요청 시간이 허용 범위를 벗어났습니다. (재전송 의심)", 401)
    if not NONCE_RE.match(nonce):
        raise SecurityError("요청 Nonce 가 없거나 형식이 잘못됐습니다.", 401)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # PRIMARY KEY 라서 같은 nonce 는 어느 워커에서 들어와도 두 번째부터 실패
            cur.execute(
                "INSERT INTO request_nonces (nonce, expires_at) VALUES (%s, %s)",
                (nonce, utcnow() + timedelta(seconds=REPLAY_WINDOW_SECONDS * 2)),
            )
        conn.commit()
    except pymysql.err.IntegrityError:
        conn.rollback()
        raise SecurityError("이미 처리된 요청입니다. (재전송 공격 차단)", 403)
    cleanup_expired(conn)


def issue_access_token(user_id: int, csrf_token: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "jti": str(uuid.uuid4()),  # 토큰 고유 ID → 로그아웃 시 블랙리스트 등록
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "csh": _sha256(csrf_token),  # 이 JWT 와 함께 발급한 CSRF 토큰에 묶음
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],  # alg 고정 ('none' 등 다운그레이드 차단)
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "jti", "sub", "csh"]},
        )
    except jwt.ExpiredSignatureError:
        raise SecurityError("로그인이 만료되었습니다. 다시 로그인해 주세요.", 401)
    except jwt.InvalidTokenError:
        raise SecurityError("유효하지 않은 인증 토큰입니다.", 401)

    with get_db().cursor() as cur:
        cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = %s", (claims["jti"],))
        if cur.fetchone():
            raise SecurityError("로그아웃된 토큰입니다.", 401)
    return claims


def set_access_cookie(resp, token: str):
    resp.set_cookie(
        ACCESS_COOKIE,
        token,
        max_age=ACCESS_TOKEN_MINUTES * 60,
        httponly=True,  # JS 에서 document.cookie 로 읽을 수 없음
        secure=COOKIE_SECURE,
        samesite="Lax",
        path="/",
    )


def set_csrf_cookie(resp, token: str):
    # JS 가 읽어서 X-CSRF-Token 헤더에 실어야 하므로 HttpOnly=False (값은 서명돼 있어 위조 불가)
    resp.set_cookie(CSRF_COOKIE, token, httponly=False, secure=COOKIE_SECURE, samesite="Strict", path="/")


def login_required(view):
    """유효한 JWT 쿠키 필수. 상태 변경 요청(POST)이면 CSRF + Replay 검증까지."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.cookies.get(ACCESS_COOKIE)
        if not token:
            raise SecurityError("로그인이 필요합니다.", 401)
        claims = decode_access_token(token)
        if request.method not in SAFE_METHODS:
            check_csrf(bound_hash=claims["csh"])
            check_replay()
        g.user_id = int(claims["sub"])
        g.claims = claims
        return view(*args, **kwargs)

    return wrapper


# ─────────────────────────────────────────────
# 4. 입력 검증 / XSS 이스케이프
# ─────────────────────────────────────────────
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: str) -> str:
    """유니코드 정규화 + 제어문자 제거 (줄바꿈/탭은 유지)."""
    return _CONTROL_CHARS.sub("", unicodedata.normalize("NFC", value)).strip()


def escape_html(value: str) -> str:
    """< > & " ' 를 HTML 엔티티로 바꿔 브라우저가 태그·스크립트로 해석하지 못하게 함."""
    return html.escape(value, quote=True)


def get_json_body() -> dict:
    body = request.get_json(silent=True)  # Content-Type: application/json 이 아니면 None
    if not isinstance(body, dict):
        raise SecurityError("JSON 형식의 요청이 필요합니다.", 400)
    return body


def memo_json(row) -> dict:
    """레거시와 같은 메모 형식 {id, author, content}."""
    return {
        "id": row["id"],
        "author": escape_html(row["author"]),  # 이름은 조회 시 이스케이프
        "content": row["content"],  # 저장 시 이미 이스케이프됨 (이중 이스케이프 방지)
    }


# ─────────────────────────────────────────────
# 5. 응답 보안 헤더 / 에러 핸들러 (레거시처럼 {"error": "..."})
# ─────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/") or request.path == "/health":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(SecurityError)
def handle_security_error(e: SecurityError):
    log.warning("보안 검증 실패 %s %s: %s", request.method, request.path, e.message)
    return jsonify(error=e.message), e.status


@app.errorhandler(404)
def handle_404(_):
    return jsonify(error="찾을 수 없습니다."), 404


@app.errorhandler(405)
def handle_405(_):
    return jsonify(error="허용되지 않은 메서드입니다."), 405


@app.errorhandler(413)
def handle_413(_):
    return jsonify(error="요청 본문이 너무 큽니다."), 413


@app.errorhandler(Exception)
def handle_unexpected(e):
    log.exception("처리되지 않은 오류")
    return jsonify(error="서버 오류가 발생했습니다."), 500  # 내부 정보 노출 안 함


# ─────────────────────────────────────────────
# 6. 라우트
# ─────────────────────────────────────────────
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    """CI/CD·컨테이너 헬스체크: 앱이 떠 있고 DB 에 실제로 쿼리가 되면 200."""
    try:
        with get_db().cursor() as cur:
            cur.execute("SELECT 1 AS ok", ())
            cur.fetchone()
        return jsonify(status="ok", db="ok"), 200
    except Exception as e:  # DB 다운 등 → 503 (세부 원인은 로그에만)
        log.warning("헬스체크 실패: %s", e)
        return jsonify(status="error", db="unreachable"), 503


@app.get("/api/csrf")
def csrf():
    """CSRF 쿠키 발급 (유효한 게 이미 있으면 유지). 화면이 처음 열릴 때 호출."""
    token = request.cookies.get(CSRF_COOKIE, "")
    resp = jsonify(message="csrf ready")
    if not token or not csrf_signature_ok(token):
        set_csrf_cookie(resp, new_csrf_token())
    return resp


# 존재하지 않는 계정이어도 bcrypt 비교 시간을 똑같이 써서 계정 존재 여부 유추 차단
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(rounds=12))


@app.post("/api/login")
def login():
    # 로그인은 레거시처럼 JSON 만 보내면 되게 두고, 브라우저의 교차 출처 요청만 Origin 으로 차단
    check_origin()

    body = get_json_body()
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise SecurityError("아이디 또는 비밀번호가 올바르지 않습니다.", 401)
    username = clean_text(username)
    if not (1 <= len(username) <= 50) or not (1 <= len(password) <= 128):
        raise SecurityError("아이디 또는 비밀번호가 올바르지 않습니다.", 401)

    with get_db().cursor() as cur:
        cur.execute(
            "SELECT u.id, u.password_hash, p.display_name, p.github_id "
            "FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.username = %s",
            (username,),
        )
        user = cur.fetchone()

    stored = user["password_hash"].encode() if user else _DUMMY_HASH
    password_ok = bcrypt.checkpw(password.encode("utf-8"), stored)  # 항상 비교해서 응답 시간 동일
    if user is None or not password_ok or username == SYSTEM_USERNAME:
        raise SecurityError("아이디 또는 비밀번호가 올바르지 않습니다.", 401)

    # JWT 는 응답 바디에 넣지 않고 쿠키로만. 로그인 때 CSRF 토큰도 새로 발급(고정 공격 방지)
    csrf_token = new_csrf_token()
    resp = jsonify(
        message="로그인 성공",
        student_name=escape_html(user["display_name"] or ""),
        github_id=escape_html(user["github_id"] or ""),
    )
    set_access_cookie(resp, issue_access_token(user["id"], csrf_token))
    set_csrf_cookie(resp, csrf_token)
    log.info("로그인 성공 user_id=%s", user["id"])
    return resp


@app.post("/api/logout")
def logout():
    """현재 JWT 의 jti 를 블랙리스트에 넣고 쿠키 삭제."""
    check_csrf()
    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        try:
            claims = decode_access_token(token)
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT IGNORE INTO revoked_tokens (jti, expires_at) VALUES (%s, %s)",
                    (claims["jti"], datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)),
                )
            conn.commit()
        except SecurityError:
            pass  # 이미 만료·무효인 토큰이면 쿠키만 지운다
    resp = jsonify(message="로그아웃 완료")
    resp.delete_cookie(ACCESS_COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="Lax")
    set_csrf_cookie(resp, new_csrf_token())
    return resp


@app.get("/api/me")
@login_required
def me():
    """새로고침해도 상단에 이름·GitHub ID 를 다시 띄우기 위한 조회."""
    with get_db().cursor() as cur:
        cur.execute(
            "SELECT p.display_name, p.github_id FROM users u "
            "LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = %s",
            (g.user_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise SecurityError("사용자를 찾을 수 없습니다.", 401)
    return jsonify(
        student_name=escape_html(row["display_name"] or ""),
        github_id=escape_html(row["github_id"] or ""),
    )


@app.get("/api/memos")
@login_required
def list_memos():
    # 레거시처럼 전체 사용자의 메모를 [{id, author, content}] 배열로, 오래된 순 (최근 200개)
    with get_db().cursor() as cur:
        cur.execute(
            "SELECT m.id, m.content, COALESCE(p.display_name, u.username) AS author "
            "FROM memos m JOIN users u ON u.id = m.user_id "
            "LEFT JOIN profiles p ON p.user_id = m.user_id "
            "ORDER BY m.id DESC LIMIT 200",
            (),
        )
        rows = list(reversed(cur.fetchall()))
    return jsonify([memo_json(r) for r in rows])


@app.post("/api/memos")
@login_required
def create_memo():
    body = get_json_body()
    content = body.get("content")
    if not isinstance(content, str):
        raise SecurityError("메모 내용을 입력해 주세요.", 400)
    content = clean_text(content)
    if not (1 <= len(content) <= MEMO_MAX_LENGTH):
        raise SecurityError(f"메모는 1~{MEMO_MAX_LENGTH}자로 작성해 주세요.", 400)

    safe_content = escape_html(content)  # 저장 시 이스케이프
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO memos (user_id, content, created_at) VALUES (%s, %s, %s)",
            (g.user_id, safe_content, utcnow()),
        )
        memo_id = cur.lastrowid
        cur.execute(
            "SELECT COALESCE(p.display_name, u.username) AS author FROM users u "
            "LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = %s",
            (g.user_id,),
        )
        author = cur.fetchone()["author"]
    conn.commit()
    memo = memo_json({"id": memo_id, "author": author, "content": safe_content})
    return jsonify(message="메모 등록 완료", memo=memo), 201


# ─────────────────────────────────────────────
# 7. 시작 시 DB 초기화 (워커마다 실행돼도 잠금 + IF NOT EXISTS 로 안전)
# ─────────────────────────────────────────────
if env_bool("INIT_DB_ON_STARTUP", True):
    init_db()

if __name__ == "__main__":
    # 개발용 실행. 운영은 Gunicorn (2단계 Dockerfile)
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=env_int("FLASK_PORT", 5000),
        debug=env_bool("FLASK_DEBUG", False),
    )
