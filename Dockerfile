# ── Flask(Gunicorn) 애플리케이션 이미지 ──
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# non-root 전용 유저 (고정 UID/GID, 로그인 셸 없음)
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# 작업 디렉터리를 만들고 소유자를 app 유저로 (권한 에러 방지)
WORKDIR /app
RUN chown app:app /app

# 의존성 먼저 설치 → 소스만 바뀌면 이 레이어는 캐시 재사용
COPY --chown=app:app requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 필요한 파일만 명시적으로 복사 (.env 등은 .dockerignore 로도 막지만, 애초에 COPY 대상이 아님)
COPY --chown=app:app app.py .
COPY --chown=app:app templates/ ./templates/
COPY --chown=app:app static/ ./static/

USER app

EXPOSE 5000

# 컨테이너 헬스체크: /health 는 DB 쿼리까지 성공해야 200
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).status == 200 else 1)"

# --preload : 마스터 프로세스에서 app.py 를 한 번만 import → DB 초기화·시드가 딱 1회 실행된 뒤 워커 fork
#             (app.py 안의 MariaDB GET_LOCK 과 함께 이중으로 경합 방지)
# --worker-tmp-dir /dev/shm : 컨테이너를 읽기 전용(read_only)으로 띄워도 Gunicorn 이 동작
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "2", \
     "--preload", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
