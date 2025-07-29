## FASTAPI 라우터/API 정의 파일
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
import schema
import crud
import logging
from database import db
from fastapi import FastAPI, Request, HTTPException
from config import conf
import requests
import json
import random
app = FastAPI() # fastapi app 생성


LOG = conf['log']
api_key = "c845a2530fc7b0624d4982d2dc26a78011d083ccf7fe4596972882114d2fbea7"    



@app.get("/")
async def root():
    logging.info("root api run")
    return {"message": "Hello World"}

@app.post("/users/")
def post_create_user(user: schema.UserCreate, dbsession: Session = Depends(db.get_session)):
    # User Check
    new_user = crud.create_user(dbsession, user)
    # Return Use
    new_log = {
        'userid': new_user.id,
        'access': 'create_user',
        'message': 'User created successfully'

    }
    crud.write_accesslog(dbsession, schema.Accessdata(**new_log))
    return new_user

@app.get("/users/{user_id}", response_model=schema.UserwithAccess)
def get_user(user_id: int, dbsession: Session = Depends(db.get_session)):
    user = crud.get_user_by_id(dbsession, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    log = {
        'userid': user.id,
        'access': f'get_user/{user_id}',
        'message': 'User fetched'
    }
    crud.write_accesslog(dbsession, schema.Accessdata(**log))
    return user


@app.post("/ioc/check", response_model=schema.IoCout)
def check_ioc(domain: str, dbsession: Session = Depends(db.get_session)):
    #외부 서비스인 VirusTotal API를 사용하여 IoC를 확인
    url = f"https://www.virustotal.com/api/v3/search?query={domain}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Error fetching data from VirusTotal")
    data = response.json()
    attributes = data["data"][0]["attributes"]
    analysis_stats = attributes["last_analysis_stats"]
    m_stats = attributes["last_analysis_stats"]['malicious']
    analysis_result = json.dumps(attributes["last_analysis_results"], indent=2)

    result = schema.IoCout(
        domain=domain,
        m_stats=m_stats,
        analysis_results=analysis_result 
    )
    log = {
        "userid": random.randint(1, 1000),  # 임시로 랜덤 사용자 ID 사용
        "access": f"check_ioc/{domain}",
        "message": f"Checked domain IOC: malicious"
    }
    crud.write_accesslog(dbsession, schema.Accessdata(**log))
    crud.IoC(dbsession, result)
    return result


@app.get("/ioc/check", response_model=schema.IoCout)
def check_ioc_get(domain: str, dbsession: Session = Depends(db.get_session)):
    return check_ioc(domain, dbsession)
