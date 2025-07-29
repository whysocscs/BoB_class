import uvicorn 
import time
from config import conf


LOG = conf['log']


if __name__ == '__main__':
    try:
        if LOG == 'dev':
            uvicorn.run(
                "api:app",   # api의 app이 뭐냐? 그러면 unicorn이 api.py를 찾아서 app을 실행한다.
                host='0.0.0.0', ## 외부에서도 접근 가능하도록 실행하는 것
                port=8080,  # 포트번호
                workers=1, # 병렬 실행 프로세스 수이다. 
                log_level='info', # 로그 레벨
                reload=True, # 코드 변경 시 자동 재시작.
            )
        else:
            uvicorn.run(
                "api:app",
                host='0.0.0.0',
                port=8080,
                workers=5,
                log_level='warning',
                reload=False,
            )
    except KeyboardInterrupt:                                
        print('\nExiting\n')
    except Exception as errormain:
        print('Failed to Start API')
        print('='*100)
        print(str(errormain))
        print('='*100)
        print('Exiting\n')
    while True:
        time.sleep(1)  # Keep the process running to handle requests