from sqlalchemy import Column, DateTime, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base

# 유저 정보 테이블
class UserTable(Base):
    __tablename__ = 'UserTable'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False)
    hashed_password = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    salt = Column(String(128), nullable=False)

    # 관계 설정: 유저가 접근한 로그들을 리스트로 가짐
    access_logs = relationship("Access", back_populates="user")


# 접근 로그 테이블
class Access(Base):
    __tablename__ = 'AccessTable'

    id = Column(Integer, primary_key=True)
    userid     = Column(Integer, ForeignKey("UserTable.id"))  # 여기!
    access = Column(String(200), nullable=False)
    message = Column(String(128), default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    ## opupdate를 넣어주면 변경이 일어날때마다 업데이트를 해준다. 
    # 관계 설정: 로그가 어느 유저에 속해있는지
    user = relationship("UserTable", back_populates="access_logs")

class IoC(Base):
    __tablename__ = 'IoCTable'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, default=False)
    m_stats = Column(Integer, nullable=True, default=False)
    analysis_results = Column(String(256), default=False)
    