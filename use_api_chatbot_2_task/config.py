## 환경 변수와 설정파일 통합
import os.path
import json
import os

if os.path.isfile('./conf.json') is False:
    with open('./conf.json', 'w') as newconf:
        conf = json.load(newconf)
        conf['dbpassword']  = os.environ['DB_PASSWORD']
        conf['log']  = os.environ['LOG_LVL']
        json.dump(conf, newconf, indent=4)

with open('./conf.json', 'r') as mainconf:
    conf = json.load(mainconf)