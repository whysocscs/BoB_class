# main.py
import uvicorn
import time
import psutil
import subprocess
import sys
from config import conf

LOG = conf['log']
BOT_FILE = "bot.py"

def exist_bot():
    """이미 실행 중인 bot.py 프로세스가 있으면 종료"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            if any(BOT_FILE in str(c) for c in cmdline):
                print(f"기존 bot.py 종료 - PID: {proc.pid}")
                proc.terminate()
                proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def start_bot():
    """bot.py 실행"""
    print('Slack Bot 실행')
    subprocess.Popen([sys.executable, BOT_FILE])

if __name__ == '__main__':
    try:
        # 개발 모드일 경우 기존 봇 종료 후 재시작
        if LOG == 'dev':
            exist_bot()
            start_bot()
            uvicorn.run(
                "api:app",   # api.py 안의 app 실행
                host='0.0.0.0',  # 외부 접속 허용
                port=8080,       # API 서버 포트
                workers=1,       # 프로세스 개수
                log_level='info',
                reload=True,     # 코드 변경 시 자동 재시작
            )
        else:
            # 운영 모드: 봇 실행 + API 실행
            start_bot()
            uvicorn.run(
                "api:app",
                host='0.0.0.0',
                port=8080,
                workers=5,
                log_level='warning',
                reload=False,
            )

    except KeyboardInterrupt:
        print('\n종료 중...\n')
    except Exception as errormain:
        print('API 시작 실패')
        print('='*100)
        print(str(errormain))
        print('='*100)
        print('종료\n')

    # 메인 프로세스 유지
    while True:
        time.sleep(1)
