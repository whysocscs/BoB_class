## 실제 DB 조작을 담당하는 함수 집합.
from datetime import datetime
import hashlib
import json
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import os
import hashlib
import base64
import models
import schema
from config import conf

# 패스워드 해싱
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Function to hash a password
def hash_password(password: str) -> tuple:
    # 솔트 생성 (16바이트)
    salt = os.urandom(16)
    # PBKDF2 해싱 (SHA256, 100,000회 반복)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    # Base64 인코딩 (저장 용이하게)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hashed_b64 = base64.b64encode(hashed).decode('utf-8')
    return salt_b64, hashed_b64

def verify_password(password: str, salt_b64: str, hashed_b64: str) -> bool:
    # Base64 디코딩
    salt = base64.b64decode(salt_b64)
    hashed_original = base64.b64decode(hashed_b64)
    # 입력 비밀번호 해싱
    hashed_check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed_check == hashed_original

# 파라미터의 타입 힌트와 리턴값의 타입 힌트를 함께 사용한 타입 주석 문법?
# ->models.UserTable은 화살표 옆에 있는 값이
def create_user(db: Session, user: schema.UserCreate) -> models.UserTable:
    """
    Create a new user in the database.
    """
    salt, hashed_password = hash_password(user.password)
    new_user = models.UserTable(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        salt=salt
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

def write_accesslog(db: Session, access_data: schema.Accessdata)->models.Access:
    new_access = models.Access(
        userid=access_data.userid,
        access=access_data.access,
        message=access_data.message,
        created_at=datetime.utcnow()
    )

    db.add(new_access)
    db.commit()
    db.refresh(new_access)

    return new_access

def get_user_by_id(db: Session, user_id: int) -> models.UserTable:
    return db.query(models.UserTable).filter(models.UserTable.id == user_id).first()

def IoC(db: Session, ioc: schema.IoCout) -> models.IoC:
    new_ioc = models.IoC(
        domain=ioc.domain,
        m_stats=ioc.m_stats,
        analysis_results=ioc.analysis_results
    )

    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    return new_ioc