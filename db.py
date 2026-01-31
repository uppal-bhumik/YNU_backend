import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var not set")

class Base(DeclarativeBase):
    pass

connect_args = {}
if "sqlite" in DATABASE_URL:
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL, 
    future=True, 
    pool_pre_ping=True, 
    connect_args=connect_args,
    pool_recycle=300,  # Recycle connections every 5 minutes
    pool_timeout=30,   # Wait up to 30 seconds for a connection
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# Retry logic for Neon cold starts (free tier auto-suspend)
def init_db_with_retry(max_retries=3, delay=5):
    """Initialize database with retry logic for Neon cold starts."""
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[DB] Attempting to connect (attempt {attempt}/{max_retries})...")
            Base.metadata.create_all(bind=engine)
            print("[DB] Connected successfully!")
            return
        except OperationalError as e:
            if attempt < max_retries:
                print(f"[DB] Connection failed, retrying in {delay}s... (Neon may be waking up)")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                print(f"[DB] Failed to connect after {max_retries} attempts")
                raise

init_db_with_retry()

def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

@contextmanager
def get_db_context():
    """
    Context manager for database session, useful for scripts/CLI.
    Do NOT use this with FastAPI Depends(), use get_db instead.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
