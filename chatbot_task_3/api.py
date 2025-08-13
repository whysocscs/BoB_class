from fastapi import Depends
from sqlalchemy.orm import Session
import schema
import crud
import logging
from database import db
from fastapi import FastAPI, HTTPException
from config import conf
import requests
import json
import random
app = FastAPI() # fastapi app 생성


LOG = conf['log']
api_key = conf["victim_token"]
OTX_API_KEY = conf["otx"]
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

def parse_otx_data(data: dict) -> dict:
    """OTX API 원본 데이터를 읽어서 간단하게 요약"""
    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])

    if not pulses:
        return {
            "domain": data.get("indicator", ""),
            "m_stats": 0,
            "analysis_results": "No pulses found"
        }

    # 첫 번째 pulse 기준으로 간략 요약
    first_pulse = pulses[0]
    summary = {
        "domain": data.get("indicator", ""),
        "m_stats": len(pulses),  # 단순히 연관된 pulse 개수를 malicious 개수로 표시
        "analysis_results": json.dumps({
            "name": first_pulse.get("name"),
            "description": first_pulse.get("description"),
            "tags": first_pulse.get("tags", [])[:5],
            "malware_families": [m.get("display_name") for m in first_pulse.get("malware_families", [])][:5],
            "attack_ids": [a.get("display_name") for a in first_pulse.get("attack_ids", [])][:5],
            "references": first_pulse.get("references", [])[:3]
        }, ensure_ascii=False, indent=2)
    }
    return summary


@app.get("/ioc/otx", response_model=schema.IoCout)
def check_otx_get(domain: str):
    return fetch_otx_data(domain)
@app.post("/ioc/otx", response_model=schema.IoCout)
def fetch_otx_data(domain: str, dbsession: Session = Depends(db.get_session)):
    """
    AlienVault OTX API에서 IoC 정보를 가져와 요약 반환
    """
    base_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    response = requests.get(base_url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code,
                            detail=f"Error fetching data from OTX: {response.text}")

    raw_data = response.json()
    parsed = parse_otx_data(raw_data)

    # DB 저장
    result = schema.IoCout(**parsed)
    crud.IoC(dbsession, result)

    return result
@app.get("/ioc/combined")
def check_ioc_combined_get(domain: str, dbsession: Session = Depends(db.get_session)):
    return check_ioc_combined(domain=domain, dbsession=dbsession)

@app.post("/ioc/combined")
def check_ioc_combined(domain: str, dbsession: Session = Depends(db.get_session)):
    # 1. VirusTotal 요청
    vt_url = f"https://www.virustotal.com/api/v3/search?query={domain}"
    vt_headers = {"x-apikey": api_key}
    vt_resp = requests.get(vt_url, headers=vt_headers)
    if vt_resp.status_code != 200:
        raise HTTPException(status_code=vt_resp.status_code, detail="VirusTotal API error")
    vt_data = vt_resp.json()
    vt_attr = vt_data["data"][0]["attributes"]
    m_stats = vt_attr["last_analysis_stats"]['malicious']

    # 2. OTX Passive DNS 요청
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}
    otx_resp = requests.get(otx_url, headers=otx_headers)
    if otx_resp.status_code != 200:
        raise HTTPException(status_code=otx_resp.status_code, detail="OTX API error")
    otx_data = otx_resp.json()

    # passive_dns 중 핵심만 요약
    passive_dns_summary = []
    for record in otx_data.get("passive_dns", [])[:5]:  # 최대 5개만
        passive_dns_summary.append({
            "hostname": record.get("hostname"),
            "address": record.get("address"),
            "last_seen": record.get("last_seen")
        })

    # 3. 통합 응답
    result = {
        "virustotal": {
            "domain": domain,
            "m_stats": m_stats
        },
        "otx": {
            "passive_dns": passive_dns_summary
        }
    }

    # 4. DB 로그 기록
    log = {
        "userid": random.randint(1, 1000),
        "access": f"check_ioc_combined/{domain}",
        "message": f"Checked IoC from VirusTotal & OTX"
    }
    crud.write_accesslog(dbsession, schema.Accessdata(**log))
    return result
@app.get("/ioc/check", response_model=schema.IoCout)
def check_ioc_get(domain: str, dbsession: Session = Depends(db.get_session)):
    return check_ioc(domain, dbsession)