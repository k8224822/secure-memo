"use strict";

// ─── 공통 요청 헬퍼 ─────────────────────────────────────────
// access_token(JWT) 쿠키는 HttpOnly 라서 JS 가 읽을 수 없고, 브라우저가 자동으로 실어 보낸다.
// JS 가 하는 일은 CSRF 토큰(쿠키 → 헤더 복사)과 요청별 Nonce/Timestamp 를 붙이는 것뿐이다.

function readCookie(name) {
  const hit = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : "";
}

function newNonce() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// opts.protect: CSRF 헤더 첨부, opts.replay: Nonce/Timestamp 헤더 첨부
async function api(method, url, body, opts = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.protect) headers["X-CSRF-Token"] = readCookie("csrf_token"); // Double Submit Cookie
  if (opts.replay) {
    headers["X-Request-Nonce"] = newNonce(); // 요청마다 새 UUID
    headers["X-Request-Timestamp"] = String(Math.floor(Date.now() / 1000)); // 유닉스 초
  }
  const res = await fetch(url, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* 본문 없음 */ }
  return { status: res.status, ok: res.ok, data };
}

// ─── XSS 안전 렌더링 (innerHTML 사용 안 함) ─────────────────
// 서버는 html.escape 된 문자열(&lt;script&gt; 등)을 준다.
// 그 엔티티만 원래 글자로 되돌린 뒤 textContent 로 넣으므로,
// 브라우저는 어떤 값이 와도 태그로 해석하지 않고 글자 그대로 보여준다.
const ENTITIES = { "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#x27;": "'", "&#39;": "'", "&amp;": "&" };
function unescapeHtml(s) {
  return String(s ?? "").replace(/&(lt|gt|quot|#x27|#39|amp);/g, (m) => ENTITIES[m]);
}
function setText(el, escaped) {
  el.textContent = unescapeHtml(escaped);
}

// ─── 화면 전환 ─────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

function showLogin(message) {
  $("profile").hidden = true;
  $("memo-view").hidden = true;
  $("login-view").hidden = false;
  $("login-error").textContent = message || "";
  $("username").focus();
}

function showProfile(info) {
  setText($("profile-name"), info.student_name);
  setText($("profile-github"), info.github_id);
  $("profile").hidden = false;
  $("login-view").hidden = true;
  $("memo-view").hidden = false;
}

function renderMemo(memo) {
  const li = document.createElement("li");
  li.className = "memo";
  const author = document.createElement("strong");
  author.className = "memo-author";
  setText(author, memo.author);
  const p = document.createElement("p");
  p.className = "memo-body";
  setText(p, memo.content);
  li.append(author, p);
  return li;
}

async function loadMemos() {
  const res = await api("GET", "/api/memos");
  if (res.status === 401) return showLogin(res.data.error);
  const list = $("memo-list");
  // 레거시와 같은 [{id, author, content}] 배열, 오래된 순
  list.replaceChildren(...(Array.isArray(res.data) ? res.data : []).map(renderMemo));
  $("memo-empty").hidden = list.children.length > 0;
}

// 새로고침했을 때: 쿠키가 살아 있으면 바로 메모 화면, 아니면 로그인 화면
async function restoreSession() {
  const me = await api("GET", "/api/me");
  if (!me.ok) return showLogin("");
  showProfile(me.data);
  await loadMemos();
}

// ─── 이벤트 (onclick 대신 addEventListener) ─────────────────
document.addEventListener("DOMContentLoaded", async () => {
  await api("GET", "/api/csrf"); // CSRF 쿠키 먼저 받기

  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("login-error").textContent = "";
    const res = await api("POST", "/api/login", {
      username: $("username").value,
      password: $("password").value,
    });
    $("password").value = "";
    if (!res.ok) {
      $("login-error").textContent = res.data.error || "로그인에 실패했습니다.";
      return;
    }
    showProfile(res.data); // 로그인 응답의 student_name, github_id 로 상단 표시
    await loadMemos();
  });

  $("memo-input").addEventListener("input", (e) => {
    $("memo-count").textContent = e.target.value.length;
  });

  $("memo-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("memo-input");
    $("memo-error").textContent = "";
    const res = await api("POST", "/api/memos", { content: input.value }, { protect: true, replay: true });
    if (res.status === 401) return showLogin(res.data.error);
    if (!res.ok) {
      $("memo-error").textContent = res.data.error || "저장에 실패했습니다.";
      return;
    }
    input.value = "";
    $("memo-count").textContent = "0";
    $("memo-list").append(renderMemo(res.data.memo));
    $("memo-empty").hidden = true;
    $("memo-list").lastElementChild.scrollIntoView({ block: "nearest" });
  });

  $("logout-btn").addEventListener("click", async () => {
    await api("POST", "/api/logout", undefined, { protect: true });
    $("memo-list").replaceChildren();
    showLogin();
  });

  await restoreSession();
});
