""" Database connection and session management. """
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.orm import declarative_base
from fastapi import FastAPI
from fastapi.logger import logger

from config import conf

DB_PASSWORD = conf['dbpassword']

# Database connection string
DB_CONN= f'mysql+pymysql://root:{DB_PASSWORD}@localhost:3306/bob'

class SQLAlchemy():
            
    def __init__(self):
        self.engine = create_engine(DB_CONN, pool_pre_ping=True, pool_size=20, max_overflow=0, pool_recycle=3600, connect_args={'connect_timeout': 10})
        self.Session = scoped_session(sessionmaker(bind=self.engine, autoflush=False, autocommit=False))

    def get_session(self):
        db = self.Session()
        try:
            yield db
        finally:
            db.close()

db = SQLAlchemy()  # 파일 읽는 순간 전역으로 설정한 것들은 실행된다. 데이터베이스에 우리가 만든 커넥션 기준으로 만든다.
# declarative 
Base = declarative_base() # pylint: disable=invalid-name