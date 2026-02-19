from database import SessionLocal
from fastapi import Request, HTTPException, Depends
from datetime import datetime, timezone
from models import UserSession, User


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Login gerekli")

    sess = (
        db.query(UserSession)
        .filter(UserSession.token == token)
        .first()
    )
    if not sess:
        raise HTTPException(status_code=401, detail="Gecersiz oturum")

    now = datetime.now(timezone.utc)
    expires_at = sess.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(status_code=401, detail="Oturum suresi dolmus")

    user = db.query(User).filter(User.id == sess.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Kullanici bulunamadi")

    return user
