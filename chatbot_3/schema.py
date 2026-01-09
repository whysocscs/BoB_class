## 회원가입 등 클라이언트가 보내는 요청 데이터의 구조를 정의한 클래스

from typing import Optional
from pydantic import BaseModel, EmailStr # pylint: disable=no-name-in-module
from datetime import datetime
##pydantic.BaseModel을 상속받아 요청 데이터의 구조를 정의합니다.
class UserCreate(BaseModel):
    username: str
    email : EmailStr
    password: str

# 나머지 클래스 작성
class Accessdata(BaseModel):
    userid: int
    access: str
    message: str

class UserwithAccess(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    access_logs: list[Accessdata] = [] 

    class Config:
        from_attributes = True

class IoCout(BaseModel):
    domain: str
    m_stats: int
    analysis_results: str

    class Config:
        from_attributes = True