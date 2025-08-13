# bot.py
import json  # JSON 파일을 읽고 쓰기 위해 사용
import requests  # API 서버와 HTTP 요청/응답을 주고받기 위해 사용
from slack_bolt import App  # Slack 앱을 구성하기 위한 라이브러리
from slack_bolt.adapter.socket_mode import SocketModeHandler
from bs4 import BeautifulSoup
from config import conf

SLACK_API_TOKEN = conf["slack"]
OAUTH_TOKEN = conf["oAuth"]
API_BASE_URL = conf.get("API_BASE_URL", "http://localhost:8000")

app = App(token=OAUTH_TOKEN)

BASE_URL = "https://kitribob.wiki/wiki/"



names = [
    "강대현", "계찬서", "고남현", "곽나영", "김수민2(14기)", "김정택", "김주영", "김주은",
    "김학범", "김혜민", "남보현", "류기현", "류현", "문채영", "박선하", "박수성", "박원경",
    "박정빈", "서민재(14기)", "서정민", "성호건", "송지호", "신찬희", "양수빈", "양승원",
    "이동우", "이상호", "이수현", "이유빈", "이학성", "전도현", "정윤성", "정지효",
    "정진호(14기)", "최민석", "최은지", "최준혁", "하준수", "한고원", "한상우"
]

import re
import json
import requests

API_BASE = "http://localhost:8080"  # FastAPI 서버 베이스 URL


def _extract_domain_from_text(text: str) -> str:
    """Slack 메시지에서 '명령어 + 공백 + 토큰' 형태의 도메인 추출 + 링크 포맷 제거"""
    token = text.split(" ", 1)[1].strip() if " " in text else ""
    token = re.sub(r"^<|>$", "", token)            # <...> 제거
    token = token.split("|")[0]                    # <http://x|표시값> 형태일 때 좌측 값
    token = token.replace("http://", "").replace("https://", "")
    token = token.strip("/")
    return token


# -------------------------
# 1) VirusTotal 핸들러
# -------------------------
def handle_cmd_virus(text: str, say):
    domain = _extract_domain_from_text(text)
    if not domain:
        say("조회할 도메인을 입력하세요. 예: `virus naver.com`")
        return

    try:
        r = requests.get(f"{API_BASE}/ioc/check", params={"domain": domain}, timeout=15)
        if r.status_code != 200:
            say(f"API 오류: {r.status_code} - {r.text}")
            return

        data = r.json()
        # IoCout: { domain, m_stats, analysis_results } 가 올 수 있으나, 요구에 따라 요약만 표시
        m_stats = data.get("m_stats", 0)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "VirusTotal 결과"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*도메인*\n`{domain}`"},
                {"type": "mrkdwn", "text": f"*악성 탐지 횟수*\n`{m_stats}`"},
            ]},
        ]
        say(blocks=blocks, text=f"VirusTotal 결과 - {domain}")
    except Exception as e:
        say(f"API 호출 실패: {e}")


# -------------------------
# 2) OTX Passive DNS 핸들러
#    (편의상 /ioc/combined 호출 후 otx.passive_dns만 표시)
# -------------------------
def handle_cmd_otx(text: str, say):
    domain = _extract_domain_from_text(text)
    if not domain:
        say("조회할 도메인을 입력하세요. 예: `otx naver.com`")
        return

    try:
        r = requests.get(f"{API_BASE}/ioc/combined", params={"domain": domain}, timeout=20)
        if r.status_code != 200:
            say(f"API 오류: {r.status_code} - {r.text}")
            return

        data = r.json()
        passive_dns = []
        # /ioc/combined 형태: {"virustotal": {...}, "otx": {"passive_dns": [...]}}
        if isinstance(data, dict):
            passive_dns = (data.get("otx") or {}).get("passive_dns") or []

        # 최대 10개만 표기
        lines = []
        for rec in passive_dns[:10]:
            h = rec.get("hostname")
            a = rec.get("address")
            ls = rec.get("last_seen")
            line = f"• `{h}` → `{a}`" + (f"  (`{ls}`)" if ls else "")
            lines.append(line)

        if not lines:
            lines = ["결과가 없습니다. (Passive DNS 레코드 없음)"]

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "OTX Passive DNS 결과"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*도메인*\n`{domain}`"},
                {"type": "mrkdwn", "text": f"*레코드 수*\n`{len(passive_dns)}`"},
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        ]
        say(blocks=blocks, text=f"OTX Passive DNS 결과 - {domain}")
    except Exception as e:
        say(f"API 호출 실패: {e}")


# -------------------------
# 3) Combined 핸들러 (VT 요약 + OTX Passive DNS 요약)
# -------------------------
def handle_cmd_combined(text: str, say):
    domain = _extract_domain_from_text(text)
    if not domain:
        say("조회할 도메인을 입력하세요. 예: `combined naver.com`")
        return

    try:
        r = requests.get(f"{API_BASE}/ioc/combined", params={"domain": domain}, timeout=25)
        if r.status_code != 200:
            say(f"API 오류: {r.status_code} - {r.text}")
            return

        data = r.json()

        vt = data.get("virustotal") or {}
        vt_m = vt.get("m_stats", 0)

        passive_dns = (data.get("otx") or {}).get("passive_dns") or []
        lines = []
        for rec in passive_dns[:7]:
            h = rec.get("hostname")
            a = rec.get("address")
            ls = rec.get("last_seen")
            line = f"• `{h}` → `{a}`" + (f"  (`{ls}`)" if ls else "")
            lines.append(line)
        if not lines:
            lines = ["결과가 없습니다. (Passive DNS 레코드 없음)"]

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "통합 IoC 결과 (VirusTotal + OTX)"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*도메인*\n`{domain}`"},
                {"type": "mrkdwn", "text": f"*VT 악성 탐지 횟수*\n`{vt_m}`"},
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "*OTX Passive DNS (요약)*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        ]
        say(blocks=blocks, text=f"통합 IoC 결과 - {domain}")
    except Exception as e:
        say(f"API 호출 실패: {e}")

def cruling(text, say):
    if " " in text:
        name = text.split(" ", 1)[1].strip()
    else:
        say("조회할 이름을 입력하세요. 예: `wiki 강대현`")
        return

    # URL 인코딩
    url = BASE_URL + requests.utils.quote(name)
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        say(f"페이지 요청 실패: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    content_div = soup.find("div", {"id": "mw-content-text"})
    if not content_div:
        say(f"페이지를 찾을 수 없습니다: {name}")
        return

    # 링크 제거
    for a_tag in content_div.find_all("a"):
        a_tag.unwrap()

    # script, style 태그 제거
    for tag in content_div(["script", "style"]):
        tag.decompose()

    # HTML 주석 제거
    for comment in content_div.find_all(string=lambda t: isinstance(t, type(soup.comment))):
        comment.extract()

    # 텍스트만 추출
    clean_text = content_div.get_text(separator="\n", strip=True)

    # Slack 메시지 전송 (길이 제한 고려, 3000자 이상일 경우 잘라서)
    if len(clean_text) > 3000:
        clean_text = clean_text[:3000] + "\n...(이하 생략)"
    say(f"*{name}* 위키 내용:\n```\n{clean_text}\n```")

@app.event("message")
def handle_message(body, say):
    event = body.get("event", {})
    user = event.get("user")
    text = (event.get("text") or "").strip()

    if user is None or user == body.get("authorizations", [{}])[0].get("user_id"):
        return
    if not text:
        return

    lower = text.lower()
    try:
        if lower.startswith("virus "):
            handle_cmd_virus(text, say)
        elif lower.startswith("otx "):
            handle_cmd_otx(text, say)
        elif lower.startswith("combined ") or lower.startswith("ioc "):
            handle_cmd_combined(text, say)
        elif lower.startswith("wiki "):
            cruling(text, say)   # ← 추가
        else:
            say(
                "사용법:\n"
                "`virus <domain>` — VirusTotal 요약\n"
                "`otx <domain>` — OTX Passive DNS 요약\n"
                "`combined <domain>` — VT + OTX 통합 요약\n"
                "`wiki <이름>` — kitribob.wiki 인물 페이지 크롤링"
            )
    except Exception as e:
        say(f"처리 중 오류: {e}")


if __name__ == "__main__":
    handle_message = SocketModeHandler(app, SLACK_API_TOKEN)
    handle_message.start()
