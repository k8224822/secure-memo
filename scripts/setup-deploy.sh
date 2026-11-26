#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 최초 1회 배포 설정 스크립트 (Mac 에서 프로젝트 폴더 안에서 실행)
#
#   ./scripts/setup-deploy.sh
#
# 하는 일
#   1. 필요한 도구 확인 (git, ssh, python3, gh)
#   2. GitHub Actions 전용 배포 SSH 키 생성 → 서버에 등록
#   3. 서버에 Docker + Compose v2 설치
#   4. 서버에 배포 폴더 + 운영용 .env 생성 (비밀값은 랜덤 생성, 화면에 출력 안 함)
#      → 서버에 .env 가 이미 있으면 절대 건드리지 않음
#   5. GitHub 레포 생성 + Secrets 등록 (gh CLI)
#   6. 확인 후 main 에 push → 첫 자동 배포 시작
#
# 몇 번을 다시 실행해도 안전함 (이미 된 단계는 건너뜀)
# ─────────────────────────────────────────────────────────────
set -eu

# ── 기본값 (실행 중에 엔터만 치면 이 값 사용) ──
DEFAULT_HOST="210.109.54.59"
DEFAULT_USER="ubuntu"
DEFAULT_ADMIN_KEY="$HOME/.ssh/hyunghwan-key.pem"
DEFAULT_REPO="secure-memo"
DEPLOY_KEY="$HOME/.ssh/secure_memo_deploy"

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
ok()   { printf '  ✅ %s\n' "$1"; }
die()  { printf '  ❌ %s\n' "$1" >&2; exit 1; }
ask()  {  # ask "질문" 기본값 → 입력값(없으면 기본값)
  local answer
  read -r -p "  $1 [$2]: " answer
  printf '%s' "${answer:-$2}"
}

[ -f docker-compose.yml ] && [ -f .github/workflows/deploy.yml ] \
  || die "secure-memo 프로젝트 폴더 안에서 실행하세요. (cd ~/.../secure-memo)"

# ─────────────────────────────────────────────
step "1. 필요한 도구 확인"
for cmd in git ssh ssh-keygen python3; do
  command -v "$cmd" >/dev/null 2>&1 || die "$cmd 가 없습니다."
done
if ! command -v gh >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || die "GitHub CLI(gh)가 없습니다. https://cli.github.com 에서 설치 후 다시 실행하세요."
  info "GitHub CLI(gh) 설치 중 (brew install gh)..."
  brew install gh
fi
if ! gh auth status >/dev/null 2>&1; then
  info "GitHub 로그인이 필요합니다. 브라우저 안내를 따라 로그인하세요."
  gh auth login --hostname github.com --git-protocol https --web --scopes "repo,workflow"
fi
# .github/workflows 를 push 하려면 workflow 권한이 필요
if ! gh auth status 2>&1 | grep -q "workflow"; then
  info "GitHub 토큰에 workflow 권한 추가 (브라우저 확인)"
  gh auth refresh --hostname github.com --scopes "workflow"
fi
gh auth setup-git >/dev/null 2>&1 || true
GH_LOGIN="$(gh api user --jq .login)"
ok "GitHub 로그인: $GH_LOGIN"

# ─────────────────────────────────────────────
step "2. 입력값"
HOST="$(ask "서버 퍼블릭 IP" "$DEFAULT_HOST")"
SSH_USER="$(ask "서버 접속 유저" "$DEFAULT_USER")"
ADMIN_KEY="$(ask "서버 접속 키(.pem) 경로" "$DEFAULT_ADMIN_KEY")"
DEPLOY_PATH="$(ask "서버 배포 폴더(절대경로)" "/home/$SSH_USER/secure-memo")"
REPO_NAME="$(ask "만들 GitHub 레포 이름" "$DEFAULT_REPO")"
SEED_GH_ID="$(ask "화면에 표시할 내 GitHub ID" "$GH_LOGIN")"
DH_USER="$(ask "Docker Hub 아이디" "")"
[ -n "$DH_USER" ] || die "Docker Hub 아이디가 필요합니다."
read -r -s -p "  Docker Hub 토큰 (입력해도 화면에 안 보임): " DH_TOKEN; echo
[ -n "$DH_TOKEN" ] || die "Docker Hub 토큰이 필요합니다. (hub.docker.com → Account settings → Personal access tokens)"
REPO="$GH_LOGIN/$REPO_NAME"

[ -f "$ADMIN_KEY" ] || die "키 파일이 없습니다: $ADMIN_KEY"
chmod 400 "$ADMIN_KEY"
SSH_ADMIN=(ssh -i "$ADMIN_KEY" -o BatchMode=yes -o ConnectTimeout=10 "$SSH_USER@$HOST")
"${SSH_ADMIN[@]}" true || die "서버 접속 실패 ($SSH_USER@$HOST). 먼저 ssh -i $ADMIN_KEY $SSH_USER@$HOST 로 한 번 접속해 yes 를 입력하세요."
ok "서버 접속 확인"

# ─────────────────────────────────────────────
step "3. GitHub Actions 전용 배포 키"
if [ ! -f "$DEPLOY_KEY" ]; then
  ssh-keygen -t ed25519 -f "$DEPLOY_KEY" -C "github-actions-secure-memo" -N "" >/dev/null
  ok "배포 키 생성: $DEPLOY_KEY"
else
  ok "배포 키 이미 있음: $DEPLOY_KEY"
fi
PUBKEY="$(cat "$DEPLOY_KEY.pub")"
# 이미 등록돼 있으면 다시 추가하지 않음
"${SSH_ADMIN[@]}" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (grep -qxF '$PUBKEY' ~/.ssh/authorized_keys || echo '$PUBKEY' >> ~/.ssh/authorized_keys)"
ssh -i "$DEPLOY_KEY" -o BatchMode=yes -o ConnectTimeout=10 "$SSH_USER@$HOST" true || die "배포 키로 접속 실패"
ok "배포 키로 서버 접속 확인"
# appleboy ssh/scp-action 은 ED25519 지문으로는 검증에 실패하는 사례가 있어 ECDSA 호스트키 지문을 씀 (SHA256:... 형식)
FINGERPRINT="$("${SSH_ADMIN[@]}" "ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ecdsa_key.pub" | awk '{print $2}')"
case "$FINGERPRINT" in SHA256:*) ok "서버 호스트키(ECDSA) 지문: $FINGERPRINT" ;; *) die "호스트키 지문을 읽지 못했습니다." ;; esac

# ─────────────────────────────────────────────
step "4. 서버에 Docker + Compose v2 설치"
if "${SSH_ADMIN[@]}" "docker compose version" >/dev/null 2>&1; then
  ok "이미 설치됨: $("${SSH_ADMIN[@]}" "docker compose version" | head -1)"
else
  info "설치 중 (1~3분)..."
  "${SSH_ADMIN[@]}" "curl -fsSL https://get.docker.com | sudo sh" >/dev/null \
    || die "Docker 설치 실패. 서버가 인터넷에 나갈 수 있는지(보안 그룹 아웃바운드) 확인하세요."
  ok "Docker 설치 완료"
fi
"${SSH_ADMIN[@]}" "sudo usermod -aG docker $SSH_USER"
"${SSH_ADMIN[@]}" "command -v curl >/dev/null || (sudo apt-get update -qq && sudo apt-get install -y -qq curl)"
# 새 SSH 세션부터 docker 그룹이 적용됨 → 배포 키로 새로 접속해서 sudo 없이 docker 가 되는지 확인
ssh -i "$DEPLOY_KEY" -o BatchMode=yes "$SSH_USER@$HOST" "docker ps >/dev/null" || die "docker 권한 확인 실패 (docker 그룹)"
ok "sudo 없이 docker 실행 가능, curl 있음, 서버 CPU: $("${SSH_ADMIN[@]}" uname -m)"

# ─────────────────────────────────────────────
step "5. 서버 배포 폴더 + 운영용 .env"
"${SSH_ADMIN[@]}" "mkdir -p '$DEPLOY_PATH'"
if "${SSH_ADMIN[@]}" "test -f '$DEPLOY_PATH/.env'"; then
  ok "서버에 .env 가 이미 있음 → 그대로 둠 (덮어쓰지 않음)"
else
  # .env.example 을 바탕으로 비밀값만 새로 랜덤 생성 → 화면에 찍지 않고 바로 서버로 전송
  python3 - "$SEED_GH_ID" <<'PY' | "${SSH_ADMIN[@]}" "umask 077; cat > '$DEPLOY_PATH/.env'"
import secrets, sys
fill = {
    "MARIADB_ROOT_PASSWORD": secrets.token_urlsafe(24),
    "MARIADB_PASSWORD": secrets.token_urlsafe(24),
    "JWT_SECRET_KEY": secrets.token_urlsafe(48),
    "CSRF_SECRET_KEY": secrets.token_urlsafe(48),
    "SEED_GITHUB_ID": sys.argv[1],
    "COOKIE_SECURE": "false",
}
for line in open(".env.example", encoding="utf-8"):
    key = line.split("=", 1)[0].strip()
    if "=" in line and not line.lstrip().startswith("#") and key in fill:
        line = f"{key}={fill[key]}\n"
    sys.stdout.write(line)
PY
  ok "서버 .env 생성 (권한 600, 비밀번호·비밀키는 랜덤 생성되어 서버에만 있음)"
fi

# ─────────────────────────────────────────────
step "6. 로컬 git 준비"
[ -d .git ] || git init -q
# git 사용자 정보가 없으면 커밋이 실패하므로, 이 레포에만 GitHub 계정 정보로 설정
if [ -z "$(git config user.email || true)" ]; then
  git config user.name "$GH_LOGIN"
  git config user.email "$(gh api user --jq .id)+$GH_LOGIN@users.noreply.github.com"
  info "git 사용자 정보가 없어 이 레포에만 설정: $GH_LOGIN"
fi
git check-ignore -q .env || die ".gitignore 가 .env 를 막지 못하고 있습니다. 중단합니다."
git add -A
if git diff --cached --name-only | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$'; then
  die "커밋 대상에 .env 파일이 있습니다. 중단합니다."
fi
git diff --cached --quiet || git commit -q -m "보안 강화 메모장: 3-Tier 컨테이너 + CI/CD"
git branch -M main
ok "커밋 준비 완료 (.env 제외 확인)"

# ─────────────────────────────────────────────
step "7. GitHub 레포 + Secrets"
if gh repo view "$REPO" >/dev/null 2>&1; then
  ok "레포 이미 있음: $REPO"
else
  gh repo create "$REPO" --private >/dev/null
  ok "레포 생성 (private): https://github.com/$REPO"
fi
git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"

# 값은 인자 대신 표준입력으로 넘겨서 프로세스 목록·화면에 남지 않게
printf '%s' "$DH_USER"     | gh secret set DOCKERHUB_USERNAME --repo "$REPO"
printf '%s' "$DH_TOKEN"    | gh secret set DOCKERHUB_TOKEN    --repo "$REPO"
printf '%s' "$HOST"        | gh secret set SSH_HOST           --repo "$REPO"
printf '%s' "$SSH_USER"    | gh secret set SSH_USER           --repo "$REPO"
printf '%s' "$DEPLOY_PATH" | gh secret set DEPLOY_PATH        --repo "$REPO"
printf '%s' "$FINGERPRINT" | gh secret set SSH_FINGERPRINT    --repo "$REPO"
gh secret set SSH_PRIVATE_KEY --repo "$REPO" < "$DEPLOY_KEY"
unset DH_TOKEN
ok "Secrets 7개 등록: $(gh secret list --repo "$REPO" --json name --jq '[.[].name] | join(", ")')"

# ─────────────────────────────────────────────
step "8. push (첫 자동 배포 시작)"
read -r -p "  main 에 push 하면 바로 빌드·배포가 시작됩니다. 진행할까요? (y/N): " GO
if [ "${GO:-N}" = "y" ] || [ "${GO:-N}" = "Y" ]; then
  git push -u origin main
  ok "push 완료"
  info "진행 상황: https://github.com/$REPO/actions"
  info "또는 터미널에서: gh run watch --repo $REPO"
  info "배포가 끝나면: http://$HOST  (tester / test1234!)"
else
  info "push 는 건너뜀. 준비되면: git push -u origin main"
fi
