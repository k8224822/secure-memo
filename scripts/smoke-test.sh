#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 로컬 점검 스크립트 (1·2단계)
#   사용법:  ./scripts/smoke-test.sh                 # 기본 http://localhost
#            BASE=http://localhost:8080 ./scripts/smoke-test.sh
#   필요:   curl, python3  (Docker 점검은 docker compose 가 있을 때만 실행)
# ─────────────────────────────────────────────────────────────
set -u

BASE="${BASE:-http://localhost}"
USER_ID="${TEST_USER:-tester}"
USER_PW="${TEST_PW:-test1234!}"

# 로그인 JSON 은 미리 만들어 둠 (macOS 기본 bash 3.2 는 "$( ... \" ... )" 안의 따옴표를 깨뜨림)
LOGIN_JSON="$(python3 -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))' "$USER_ID" "$USER_PW")"

JAR="$(mktemp)"; HDR="$(mktemp)"; BODY="$(mktemp)"
trap 'rm -f "$JAR" "$HDR" "$BODY"' EXIT

PASS=0; FAIL=0
ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (기대 $3, 실제 $2)"; fi; }

uuid()  { python3 -c 'import uuid; print(uuid.uuid4())'; }
now()   { date +%s; }
cookie(){ awk -v n="$1" '$6==n {v=$7} END {print v}' "$JAR"; }   # 쿠키 jar 에서 값 꺼내기

# curl 래퍼: 상태코드만 출력, 헤더는 $HDR, 바디는 $BODY 에 저장
req() { curl -s -o "$BODY" -D "$HDR" -w '%{http_code}' -b "$JAR" -c "$JAR" "$@"; }

post_memo() {  # $1=content  $2=csrf  $3=nonce  $4=timestamp
  local data
  data="$(python3 -c 'import json,sys; print(json.dumps({"content": sys.argv[1]}))' "$1")"
  req -X POST "$BASE/api/memos" -H 'Content-Type: application/json' \
      -H "X-CSRF-Token: $2" -H "X-Request-Nonce: $3" -H "X-Request-Timestamp: $4" \
      --data "$data"
}

echo "== 대상: $BASE"

echo "[1] 기본 동작"
check "GET /health"                       "$(req "$BASE/health")" 200
grep -q '"db": *"ok"' "$BODY" && ok "/health 가 DB 연결까지 확인" || bad "/health 응답: $(cat "$BODY")"
check "GET / 화면"                          "$(req "$BASE/")" 200
grep -qi "content-security-policy: .*script-src 'self'" "$HDR" && ok "CSP 헤더 적용" || bad "CSP 헤더 없음"

echo "[2] 인증"
check "로그인 없이 메모 조회 → 401"           "$(req "$BASE/api/memos")" 401
check "틀린 비밀번호 → 401"                   "$(req -X POST "$BASE/api/login" -H 'Content-Type: application/json' --data '{"username":"tester","password":"wrong"}')" 401
check "교차 출처 로그인 → 403"                "$(req -X POST "$BASE/api/login" -H 'Content-Type: application/json' -H 'Origin: https://evil.example' --data "$LOGIN_JSON")" 403
LOGIN_STATUS="$(req -X POST "$BASE/api/login" -H 'Content-Type: application/json' --data "$LOGIN_JSON")"
check "정상 로그인 → 200"                     "$LOGIN_STATUS" 200
echo "     응답: $(cat "$BODY")"
if [ "$LOGIN_STATUS" != "200" ]; then
  echo "  ⛔ 로그인이 안 돼서 [3]~[6] 은 의미가 없어 건너뜁니다. (위 응답과 docker compose logs app 확인)"
  SKIP_AUTH=1
fi
grep -q '"student_name"' "$BODY" && grep -q '"github_id"' "$BODY" && ok "응답에 student_name, github_id" || bad "로그인 응답 형식"
grep -q 'eyJ' "$BODY" && bad "JWT 가 응답 바디에 노출됨" || ok "JWT 가 응답 바디에 없음"
AT_LINE="$(grep -i '^set-cookie: access_token=' "$HDR")"
echo "     $(echo "$AT_LINE" | sed 's/access_token=[^;]*/access_token=***/' | tr -d '\r')"
echo "$AT_LINE" | grep -qi 'httponly' && echo "$AT_LINE" | grep -qi 'samesite=lax' && echo "$AT_LINE" | grep -qi 'path=/' \
  && ok "JWT 쿠키 HttpOnly · SameSite=Lax · Path=/" || bad "JWT 쿠키 속성"
CSRF="$(cookie csrf_token)"; [ -n "$CSRF" ] && ok "csrf_token 쿠키 발급" || bad "csrf_token 쿠키 없음"
ACCESS="$(cookie access_token)"

if [ -z "${SKIP_AUTH:-}" ]; then
echo "[3] 메모 (레거시 형식 + XSS)"
check "메모 목록 → 200"                       "$(req "$BASE/api/memos")" 200
python3 - "$BODY" <<'EOF' && ok "목록 = [{id, author, content}] + 시스템 초기 메모" || bad "목록 형식: $(head -c 200 "$BODY")"
import json, sys
d = json.load(open(sys.argv[1]))
assert isinstance(d, list) and d and sorted(d[0]) == ["author", "content", "id"]
assert d[0]["author"] == "시스템" and d[0]["content"] == "초기 테스트 메모입니다."
EOF
check "메모 작성 → 201"                       "$(post_memo '<script>alert(1)</script>' "$CSRF" "$(uuid)" "$(now)")" 201
grep -q '&lt;script&gt;' "$BODY" && ok "XSS 이스케이프 저장" || bad "이스케이프 안 됨: $(cat "$BODY")"

echo "[4] CSRF"
check "CSRF 헤더 없음 → 403"                  "$(req -X POST "$BASE/api/memos" -H 'Content-Type: application/json' -H "X-Request-Nonce: $(uuid)" -H "X-Request-Timestamp: $(now)" --data '{"content":"x"}')" 403
check "CSRF 값 위조 → 403"                    "$(post_memo x "fake.token" "$(uuid)" "$(now)")" 403

echo "[5] Replay"
N="$(uuid)"; T="$(now)"
check "첫 요청 → 201"                         "$(post_memo once "$CSRF" "$N" "$T")" 201
check "같은 Nonce 재전송 → 403"               "$(post_memo once "$CSRF" "$N" "$T")" 403
check "Timestamp 60초 전 → 401"               "$(post_memo old "$CSRF" "$(uuid)" "$(( $(now) - 60 ))")" 401

echo "[6] 로그아웃 후 토큰 재사용"
req -X POST "$BASE/api/logout" -H "X-CSRF-Token: $CSRF" >/dev/null
check "폐기된 JWT 로 조회 → 401"              "$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: access_token=$ACCESS" "$BASE/api/memos")" 401
fi

# ── Docker 점검 (compose 프로젝트 폴더에서 실행할 때) ──
if command -v docker >/dev/null 2>&1 && docker compose ps >/dev/null 2>&1; then
  echo "[7] 컨테이너 / 네트워크 격리"
  for s in memo-db memo-app; do
    check "$s 상태" "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$s" 2>/dev/null | tr -d '\r\n')" healthy
  done
  check "memo-nginx 상태" "$(docker inspect -f '{{.State.Status}}' memo-nginx 2>/dev/null | tr -d '\r\n')" running
  check "app 실행 유저 UID (non-root)" "$(docker compose exec -T app id -u | tr -d '\r')" 10001
  docker compose exec -T app sh -c 'ls -A /app' | grep -q '\.env' && bad ".env 가 이미지 안에 있음" || ok ".env 가 이미지 안에 없음"
  docker compose exec -T nginx sh -c 'wget -q -T 2 -O /dev/null http://db:3306' >/dev/null 2>&1 \
    && bad "nginx → db 접근 가능" || ok "nginx → db 접근 불가 (다른 네트워크)"
  [ -z "$(docker port memo-db 2>/dev/null)" ] && ok "db 컨테이너가 호스트에 포트를 공개하지 않음" || bad "db 포트 공개됨: $(docker port memo-db)"
  if command -v nc >/dev/null 2>&1 && nc -z -w 2 127.0.0.1 3306 >/dev/null 2>&1; then
    echo "  ⚠️  호스트 3306 은 다른 프로그램이 쓰는 중 (우리 db 아님). 확인: lsof -nP -iTCP:3306 -sTCP:LISTEN"
  fi
  docker compose exec -T db bash -c 'timeout 3 bash -c "</dev/tcp/1.1.1.1/53"' >/dev/null 2>&1 \
    && bad "db 가 인터넷에 나갈 수 있음" || ok "db → 인터넷 차단 (internal 네트워크)"
  SEEDS="$(docker compose logs app 2>/dev/null | grep -c "계정 '$USER_ID' 생성")"
  [ "$SEEDS" -le 1 ] && ok "시드 생성 로그 ${SEEDS}회 (멀티워커 중복 없음)" || bad "시드가 ${SEEDS}번 생성됨"
else
  echo "[7] docker compose 를 찾지 못해 컨테이너 점검은 건너뜀 (프로젝트 폴더에서 실행하세요)"
fi

echo
echo "결과: 통과 $PASS / 실패 $FAIL"
[ "$FAIL" -eq 0 ]
