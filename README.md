# 클라우드 보안 메모장 (레거시 Flask → 보안 강화 3-Tier)

강사님이 준 레거시 Flask 메모장을 **엔드포인트·응답 형식은 그대로** 두고,
내부 구현·보안·인프라만 프로덕션 수준으로 바꾼 프로젝트입니다.

## 디렉토리 구조

```
secure-memo/
├── app.py                    # [1단계] Flask 백엔드 + 보안 (JWT·CSRF·Replay·XSS, DB 초기화/시드, /health)
├── requirements.txt          # [1단계]
├── templates/
│   └── index.html            # [1단계] GET / 화면 (인라인 스크립트 없음)
├── static/
│   ├── app.js                # [1단계] CSRF·Nonce·Timestamp 헤더, textContent 출력
│   └── style.css             # [1단계]
├── Dockerfile                # [2단계] python:3.11-slim, non-root, Gunicorn --preload
├── docker-compose.yml        # [2단계] nginx / app / db, 네트워크 분리, Named Volume, healthcheck
├── nginx.conf                # [2단계] 리버스 프록시 (쿠키·보안 헤더 전달)
├── .env.example              # [2단계] 환경변수 템플릿
├── .gitignore                # [2단계] .env 등 민감 파일 Git 제외
├── .dockerignore             # [2단계] .env 등 민감 파일 이미지 제외
├── scripts/
│   └── smoke-test.sh         # 로컬 점검 스크립트 (보안·네트워크 격리 자동 확인)
└── .github/workflows/
    └── deploy.yml            # [3단계] main push → Docker Hub → SSH 배포 → 헬스체크·롤백
```

## API (레거시 호환)

| 메서드 | 경로 | 인증 | 추가 헤더 | 응답 |
|---|---|---|---|---|
| GET | `/` | - | - | 메모장 화면 |
| POST | `/api/login` | - | - | `{message, student_name, github_id}` + JWT 쿠키 |
| GET | `/api/memos` | JWT 쿠키 | - | `[{id, author, content}]` (전체 사용자) |
| POST | `/api/memos` | JWT 쿠키 | `X-CSRF-Token`, `X-Request-Nonce`, `X-Request-Timestamp` | `{message, memo}` (201) |
| GET | `/health` | - | - | DB 쿼리 성공 시 200, 실패 시 503 |
| GET | `/api/csrf` | - | - | CSRF 쿠키 발급 (추가) |
| GET | `/api/me` | JWT 쿠키 | - | `{student_name, github_id}` (추가, 새로고침용) |
| POST | `/api/logout` | - | `X-CSRF-Token` | jti 블랙리스트 등록 (추가) |

오류 응답은 레거시처럼 `{"error": "..."}` 입니다.

## 네트워크 구조

```
[인터넷] ──:80──> nginx ──(frontend-net)──> app ──(backend-net, internal)──> db
```

| 컨테이너 | frontend-net | backend-net | 외부 포트 |
|---|---|---|---|
| nginx | O | X | 80 |
| app | O | O | 없음 |
| db | X | O | 없음 |

## 로컬 실행 (Docker)

```bash
cp .env.example .env              # 빈 값 채우기 (아래 체크리스트 참고)
docker compose up -d --build
docker compose ps                 # db → app → nginx 순서로 (healthy) 가 되면 준비 완료
curl -i http://localhost/health   # {"db":"ok","status":"ok"}
# 브라우저: http://localhost   (tester / test1234!)
```

자동 점검 (프로젝트 폴더에서)

```bash
chmod +x scripts/smoke-test.sh
./scripts/smoke-test.sh           # 마지막 줄 "결과: 통과 N / 실패 0" 이면 OK
```

자주 쓰는 명령

```bash
docker compose logs -f app                      # 앱 로그 (시드 생성 여부 확인)
docker compose exec db mariadb -u root -p       # DB 직접 보기 (호스트 포트가 없으므로 이 방법만 가능)
docker compose down                             # 중지 (메모 유지)
docker compose down -v                          # 중지 + 볼륨 삭제 (메모 전부 삭제!)
```

## 배포 (GitHub Actions) — 3단계

`main` 에 push 하면 `.github/workflows/deploy.yml` 이 자동으로 실행됩니다.

1. **validate**: `app.py` 문법, `docker-compose.yml` 설정 검사
2. **build**: Docker Hub 에 `<아이디>/secure-memo:latest` + `:<커밋SHA>` 푸시 (amd64·arm64 둘 다)
3. **deploy** (SSH)
   1. 서버 `.env` 존재 확인 (없으면 중단)
   2. **지금 돌고 있는 이미지 백업** → `.prev_image`
   3. 새 SHA 이미지 pull → `docker compose up -d --force-recreate --remove-orphans app nginx`
   4. `curl -f http://localhost/health` 를 **5초 간격 10회** 재시도
   5. 성공 → 완료 / 끝까지 실패 → **백업 이미지로 자동 롤백 후 워크플로 실패(exit 1)**
   6. 마지막에 `.env` 해시를 비교해 **배포가 .env 를 건드리지 않았는지** 확인

이미지 태그는 `docker-compose.yml` 의 `${IMAGE_TAG}` 로 받고, 워크플로가 **셸 환경변수로만** 넘깁니다.
서버 `.env` 는 업로드·수정·삭제하지 않습니다 (scp 대상은 `docker-compose.yml`, `nginx.conf` 두 개뿐).

### 레포 Settings → Secrets and variables → Actions → New repository secret

| 이름 | 필수 | 넣을 값 |
|---|---|---|
| `DOCKERHUB_USERNAME` | O | Docker Hub 아이디 |
| `DOCKERHUB_TOKEN` | O | Docker Hub → Account settings → Personal access tokens 에서 만든 토큰 (권한 Read & Write). **계정 비밀번호 X** |
| `SSH_HOST` | O | 운영 서버 공인 IP (또는 도메인) |
| `SSH_USER` | O | 서버 접속 유저 (예: `ubuntu`) |
| `SSH_PRIVATE_KEY` | O | 배포 전용 SSH 개인키 **전체** (`-----BEGIN OPENSSH PRIVATE KEY-----` 줄부터 `-----END ...-----` 줄까지) |
| `DEPLOY_PATH` | O | 서버의 배포 폴더 **절대경로** (예: `/home/ubuntu/secure-memo`) |
| `SSH_PORT` | 선택 | SSH 포트가 22 가 아닐 때만 |
| `SSH_FINGERPRINT` | 권장 | 서버 호스트키 **ECDSA** 지문 (가짜 서버 접속 방지, `SHA256:...` 형식). 서버에서 `ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ecdsa_key.pub \| awk '{print $2}'`. ED25519 지문은 appleboy 액션에서 검증 실패 사례가 있어 ECDSA 사용. 배포가 지문 오류로 실패하면 이 Secret 을 지워도 동작함 |

### 서버 사전 준비 체크리스트 (최초 1회)

- [ ] **Docker Engine + Compose v2 플러그인** 설치 → `docker compose version` 이 출력되는지 (`docker-compose` v1 아님)
- [ ] **curl** 설치 확인 → `curl --version` (헬스체크에 사용)
- [ ] 배포 유저를 docker 그룹에 추가 → `sudo usermod -aG docker $USER` 후 **재접속**, `docker ps` 가 sudo 없이 되는지
- [ ] 배포 전용 SSH 키 등록 (내 PC 에서)
  ```bash
  ssh-keygen -t ed25519 -f ~/.ssh/secure_memo_deploy -C "github-actions-deploy" -N ""
  ssh-copy-id -i ~/.ssh/secure_memo_deploy.pub 유저@서버IP
  ssh -i ~/.ssh/secure_memo_deploy 유저@서버IP 'docker ps'      # 접속 + docker 권한 확인
  cat ~/.ssh/secure_memo_deploy                                  # 이 내용 전체를 SSH_PRIVATE_KEY 에
  ```
- [ ] 배포 폴더와 **운영용 .env** 생성 (깃·Actions 로 보내지 않고 서버에만 둠)
  ```bash
  mkdir -p /home/ubuntu/secure-memo && cd /home/ubuntu/secure-memo
  nano .env            # .env.example 내용을 운영용 값으로 채워서 저장 (로컬과 다른 비밀키 사용!)
  chmod 600 .env
  ```
- [ ] 방화벽 / 클라우드 보안그룹: **80(웹), 22(SSH)만** 허용. 3306 은 열지 않음
- [ ] 서버 80 포트를 다른 프로그램(기존 nginx, apache 등)이 쓰고 있지 않은지 → `sudo lsof -iTCP:80 -sTCP:LISTEN`

### 배포 전 체크리스트 (push 직전)

- [ ] Secrets 6개(+선택 2개) 이름 오타 없이 등록
- [ ] `git status` 에 `.env` 가 없는지 (`.gitignore` 동작 확인)
- [ ] 로컬에서 `./scripts/smoke-test.sh` 전부 통과
- [ ] 서버 CPU 가 amd64 또는 arm64 인지 (`uname -m` → `x86_64` 또는 `aarch64`, 둘 다 지원)
- [ ] push 후 GitHub → **Actions** 탭에서 validate → build → deploy 가 모두 초록색인지
- [ ] 배포 후 브라우저로 `http://서버IP` 접속 + 로그인 확인

### 서버에서 직접 다룰 때

```bash
cd /home/ubuntu/secure-memo
cat image.env                  # 지금 서비스 중인 이미지
cat .prev_image                # 직전 배포 때 백업한 이미지

# 지금 이미지 그대로 다시 올리기 (compose 명령엔 항상 image.env 를 같이 줘야 함)
docker compose --env-file .env --env-file image.env up -d --no-build

# 특정 버전으로 수동 롤백 (커밋 SHA 지정)
APP_IMAGE=<도커허브ID>/secure-memo IMAGE_TAG=<커밋SHA> docker compose up -d --no-build --force-recreate app nginx
```

> `image.env` 없이 `docker compose up` 을 하면 기본값 `secure-memo-app:latest` 를 찾다가 실패합니다.
> 서버 재부팅 시에는 `restart: unless-stopped` 로 **기존 컨테이너가 그대로** 다시 뜨므로 신경 쓸 필요 없습니다.

## 주의사항 체크리스트

### 처음 띄우기 전
- [ ] `.env` 의 빈 값 채우기: `MARIADB_ROOT_PASSWORD`, `MARIADB_PASSWORD`, `JWT_SECRET_KEY`, `CSRF_SECRET_KEY`, `SEED_GITHUB_ID`
  - 비어 있으면 compose 가 "어떤 값이 빠졌는지" 알려주며 실행을 거부함
- [ ] `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` 는 **각각 32자 이상, 서로 다르게** (`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`)
- [ ] `git status` 에 `.env` 가 안 보이는지 확인

### 띄운 뒤 확인
- [ ] `docker compose ps` 에서 세 컨테이너 모두 `(healthy)`
- [ ] `docker compose logs app` 에 "시드: 계정 'tester' 생성" (두 번째부터는 생성 로그 없음 = 정상)
- [ ] 로그인 → 상단에 이름·GitHub ID, 목록 첫 줄에 "시스템 / 초기 테스트 메모입니다."

### 기동 순서 / 초기화
- 첫 실행은 MariaDB 볼륨 초기화 때문에 30초~1분 걸릴 수 있음 (healthcheck `start_period: 60s`)
- DB 가 healthy 가 되기 전엔 app 이 아예 시작되지 않고, app 이 healthy 가 되기 전엔 nginx 가 시작되지 않음
- DB 초기화는 Gunicorn `--preload` 로 마스터에서 1번만 실행 + app.py 의 MariaDB `GET_LOCK` 으로 이중 방어

### 데이터
- `docker compose down` 은 안전 (메모 유지). **`down -v` 는 볼륨까지 지워 메모가 전부 사라짐**
- `MARIADB_USER` / `MARIADB_PASSWORD` 는 **볼륨이 처음 만들어질 때만** 적용 → 나중에 `.env` 에서 바꾸면 접속 실패. DB 안에서 `ALTER USER` 로 같이 바꾸거나 볼륨을 새로 만들어야 함
- 시드는 "없을 때만" 생성 → 띄운 뒤 `SEED_GITHUB_ID`·이름을 바꿔도 반영 안 됨 (profiles 행 수정 필요)
- DB 를 직접 조회하면 메모가 `&lt;script&gt;` 처럼 보이는 게 정상 (저장 시 이스케이프)

### 쿠키 / 헤더 / HTTPS
- 지금은 HTTP 80 이라 `COOKIE_SECURE=false`. HTTPS 를 붙이면 반드시 `true`
- 다른 도메인·프록시 뒤에서 로그인/메모 작성이 403 이면 `TRUSTED_ORIGINS=https://실제주소`
- 커스텀 헤더를 새로 추가할 땐 하이픈(`X-My-Header`)만 사용. 밑줄(`X_My_Header`)은 Nginx 가 버림
- PC 시계가 30초 이상 틀리면 메모 작성이 401 (Timestamp ±30초 검증)
- 로그인은 IP당 초당 5회 초과 시 429 (Nginx rate limit)
- 로그인은 15분 후 만료 → 다시 로그인

### 보안 구조 (의도된 동작)
- 외부 공개 포트는 Nginx 80 하나뿐. DB 3306 은 호스트에서도 접속 불가
- backend-net 은 `internal: true` → DB 컨테이너는 인터넷으로 못 나감
- app / nginx 컨테이너는 읽기 전용 파일시스템 (`read_only: true`)
- `.env` 는 `.gitignore` + `.dockerignore` 양쪽에서 제외되고, Dockerfile 도 필요한 파일만 COPY

## 레거시 문제점 → 해결

| 레거시 문제 | 위험 | 해결 |
|---|---|---|
| 평문 비밀번호 | 코드 유출 = 비번 유출 | DB 에 bcrypt 해시, 시드 비번은 환경변수 |
| 서명 없는 쿠키 (`session_user=tester`) | 쿠키 값만 바꾸면 로그인 우회 | 서명된 JWT, HttpOnly·SameSite=Lax·Path=/ |
| `innerHTML` 출력 | DOM XSS | 저장 시 `html.escape`, `textContent` 출력, CSP |
| `debug=True` + `0.0.0.0` | 디버거 원격 코드 실행 | debug 끔, Gunicorn 실행 |
| 메모리 저장 (`MEMOS` 리스트) | 재시작 시 소실, 워커마다 다른 데이터 | MariaDB + Named Volume |
| CSRF·재전송 방어 없음 | 대리 요청, 요청 재전송 | Double Submit Cookie, Nonce(DB)·Timestamp(±30초), jti 블랙리스트 |
