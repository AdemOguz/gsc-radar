import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Priority: DATABASE_URL -> POSTGRES_* vars -> local default.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    pg_user = os.getenv("POSTGRES_USER", "postgres")
    pg_password = os.getenv("POSTGRES_PASSWORD", "postgres123")
    pg_host = os.getenv("POSTGRES_HOST", "localhost")
    pg_port = os.getenv("POSTGRES_PORT", "5432")
    pg_db = os.getenv("POSTGRES_DB", "appdb")
    DATABASE_URL = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_db}"

if not DATABASE_URL.startswith("postgresql"):
    raise ValueError("Only PostgreSQL is supported. Set DATABASE_URL to a postgresql:// URL.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
