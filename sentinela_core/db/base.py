from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sentinela_core.settings import settings

DATABASE_URL = (
    f"mysql+pymysql://{settings.DB_USER}:{settings.DB_PASSWORD}"
    f"@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
)

engine = create_engine(
    DATABASE_URL,
    echo=True,      
    future=True
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()
