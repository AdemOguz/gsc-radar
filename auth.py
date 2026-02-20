from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import os
import requests
from urllib.parse import urlencode, quote
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta, date
from deps import get_db, get_current_user
from models import OAuthToken, User, UserSession, UserOAuthToken
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pydantic import BaseModel, EmailStr
import hashlib
import secrets
import hmac

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = (os.getenv("GOOGLE_REDIRECT_URI") or "").strip()
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "1") == "1"
OAUTH_STATE_COOKIE = "oauth_state_token"
OAUTH_STATE_TTL_SEC = 600


SCOPES = [
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/analytics.readonly",
]

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GSC_BASE = "https://searchconsole.googleapis.com/webmasters/v3"
SESSION_DAYS = 14


class RegisterIn(BaseModel):
    email: EmailStr
    name: str
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


def hash_password(password: str) -> str:
    salt = os.getenv("APP_PASSWORD_SALT", "gsc-radar-default-salt")
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def create_session_token() -> str:
    return secrets.token_urlsafe(48)


def require_env():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET env degiskenleri eksik."
        )
    if not REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="GOOGLE_REDIRECT_URI env degiskeni eksik."
        )


def get_refresh_token(db: Session, user_id: str = None) -> str:
    if user_id:
        row = (
            db.query(UserOAuthToken)
            .filter(
                UserOAuthToken.user_id == user_id,
                UserOAuthToken.provider == "google"
            )
            .first()
        )
        if row and row.refresh_token:
            return row.refresh_token
        raise HTTPException(
            status_code=401,
            detail="Bu kullanici icin Google hesabi bagli degil."
        )

    # Backward compatibility: eski global token yapi
    legacy = db.query(OAuthToken).filter(OAuthToken.provider == "google").first()
    if legacy and legacy.refresh_token:
        return legacy.refresh_token

    raise HTTPException(
        status_code=401,
        detail="Google hesabi bagli degil. Once login olun ve Google baglayin."
    )


def refresh_access_token(refresh_token: str) -> str:
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    r = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=30, verify=False)
    token_data = r.json()

    if r.status_code != 200 or "access_token" not in token_data:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Access token uretilemedi",
                "google_response": token_data
            }
        )

    return token_data["access_token"]


def gsc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


@router.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Bu email zaten kayitli")

    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Sifre en az 6 karakter olmali")

    user = User(
        email=email,
        name=(payload.name or "User").strip() or "User",
        password_hash=hash_password(payload.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email, "name": user.name}


@router.post("/auth/login")
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email veya sifre hatali")

    token = create_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    session = UserSession(user_id=user.id, token=token, expires_at=expires_at)
    db.add(session)
    db.commit()

    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        max_age=SESSION_DAYS * 24 * 60 * 60,
        path="/",
    )
    return {
        "message": "Login basarili",
        "user": {"id": user.id, "email": user.email, "name": user.name}
    }


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("session_token")
    if token:
        db.query(UserSession).filter(UserSession.token == token).delete()
        db.commit()
    response.delete_cookie("session_token", path="/")
    return {"message": "Logout basarili"}


@router.get("/auth/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    connected = (
        db.query(UserOAuthToken)
        .filter(
            UserOAuthToken.user_id == user.id,
            UserOAuthToken.provider == "google"
        )
        .first()
    ) is not None
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "google_connected": connected
    }


@router.get("/auth/google/login")
def google_login(user: User = Depends(get_current_user)):
    require_env()
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    url = GOOGLE_AUTH_URL + "?" + urlencode(params)
    response = RedirectResponse(url)
    response.set_cookie(
        key=OAUTH_STATE_COOKIE,
        value=state,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        max_age=OAUTH_STATE_TTL_SEC,
        path="/",
    )
    return response


@router.get("/auth/google/callback")
def google_callback(
    code: str,
    state: str = "",
    request: Request = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_env()
    expected_state = (request.cookies.get(OAUTH_STATE_COOKIE) if request else "")
    if not expected_state or not state or not hmac.compare_digest(state, expected_state):
        raise HTTPException(status_code=400, detail="OAuth state dogrulanamadi. Tekrar Google baglantisi baslatin.")

    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }

    r = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=30)
    token_data = r.json()

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail=token_data)

    refresh_token = token_data.get("refresh_token")
    row = (
        db.query(UserOAuthToken)
        .filter(
            UserOAuthToken.user_id == user.id,
            UserOAuthToken.provider == "google"
        )
        .first()
    )

    if not refresh_token:
        if row:
            response = RedirectResponse("/static/site-select.html")
            response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
            return response
        raise HTTPException(
            status_code=400,
            detail="refresh_token gelmedi. Google login ekraninda prompt=consent olmali."
        )

    if not row:
        row = UserOAuthToken(
            user_id=user.id,
            provider="google",
            refresh_token=refresh_token
        )
        db.add(row)
    else:
        row.refresh_token = refresh_token
        row.updated_at = datetime.now(timezone.utc)

    db.commit()
    response = RedirectResponse("/static/site-select.html")
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    return response


@router.get("/gsc/sites")
def list_gsc_sites(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    refresh_token = get_refresh_token(db, user_id=user.id)
    access_token = refresh_access_token(refresh_token)

    url = f"{GSC_BASE}/sites"
    r = requests.get(url, headers=gsc_headers(access_token), timeout=30)

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    return r.json()


@router.get("/gsc/performance")
def gsc_performance(
    site_url: str,
    start_date: str,
    end_date: str,
    dimensions: str = "query",
    row_limit: int = 50,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    refresh_token = get_refresh_token(db, user_id=user.id)
    access_token = refresh_access_token(refresh_token)

    encoded_site = quote(site_url, safe="")
    url = f"{GSC_BASE}/sites/{encoded_site}/searchAnalytics/query"

    payload = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": [d.strip() for d in dimensions.split(",") if d.strip()],
        "rowLimit": row_limit,
    }

    r = requests.post(url, headers=gsc_headers(access_token), json=payload, timeout=30)

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    return r.json()


def fetch_gsc_summary(
    site_url: str,
    start_date: str,
    end_date: str,
    db: Session,
    user_id: str = None
) -> dict:
    rows = fetch_gsc_rows(
        site_url=site_url,
        start_date=start_date,
        end_date=end_date,
        dimensions=[],
        row_limit=25000,
        db=db,
        user_id=user_id,
    )
    totals = {
        "clicks": 0,
        "impressions": 0,
        "ctr": 0,
        "position": 0,
        "rows": len(rows)
    }

    if not rows:
        return totals

    for row in rows:
        totals["clicks"] += row.get("clicks", 0)
        totals["impressions"] += row.get("impressions", 0)
        totals["ctr"] += row.get("ctr", 0)
        totals["position"] += row.get("position", 0)

    totals["ctr"] = totals["ctr"] / totals["rows"]
    totals["position"] = totals["position"] / totals["rows"]
    return totals


def fetch_gsc_rows(
    site_url: str,
    start_date: str,
    end_date: str,
    dimensions: list,
    row_limit: int,
    db: Session,
    user_id: str = None,
    dimension_filter_groups: list = None,
    data_state: str = "all",
):
    refresh_token = get_refresh_token(db, user_id=user_id)
    access_token = refresh_access_token(refresh_token)

    payload = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": dimensions,
        "rowLimit": row_limit,
        "dataState": data_state,
    }
    if dimension_filter_groups:
        payload["dimensionFilterGroups"] = dimension_filter_groups

    candidates = [site_url]
    normalized = (site_url or "").strip()
    if normalized.startswith("sc-domain:"):
        domain = normalized.replace("sc-domain:", "").strip().strip("/")
        if domain:
            candidates.append(f"https://{domain}/")
    elif normalized.startswith("http://") or normalized.startswith("https://"):
        host = (urlparse(normalized).hostname or "").strip()
        if host:
            candidates.append(f"sc-domain:{host}")
            candidates.append(f"https://{host}/")

    # duplicate candidate temizligi
    uniq = []
    seen = set()
    for c in candidates:
        if c and c not in seen:
            uniq.append(c)
            seen.add(c)

    last_response = None
    for candidate in uniq:
        encoded_site = quote(candidate, safe="")
        url = f"{GSC_BASE}/sites/{encoded_site}/searchAnalytics/query"
        r = requests.post(
            url,
            headers=gsc_headers(access_token),
            json=payload,
            timeout=30
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("rows", [])
        last_response = r
        # 401/403 disindaki hatalarda fallback denemeye gerek yok
        if r.status_code not in (401, 403):
            break

    if last_response is not None:
        raise HTTPException(status_code=last_response.status_code, detail=last_response.text)
    raise HTTPException(status_code=500, detail="GSC sorgusu yapilamadi")


@router.get("/gsc/summary")
def gsc_summary(
    site_url: str,
    start_date: str,
    end_date: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return fetch_gsc_summary(site_url, start_date, end_date, db, user_id=user.id)


def test_gsc_fetch(access_token: str, property_url: str):
    creds = Credentials(token=access_token)

    service = build(
        "searchconsole",
        "v1",
        credentials=creds
    )

    body = {
        "startDate": (date.today() - timedelta(days=7)).isoformat(),
        "endDate": (date.today() - timedelta(days=1)).isoformat(),
        "rowLimit": 5
    }

    return service.searchanalytics().query(
        siteUrl=property_url,
        body=body
    ).execute()


def get_access_token_from_refresh(refresh_token: str) -> str:
    payload = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    response = requests.post(GOOGLE_TOKEN_URL, data=payload)
    response.raise_for_status()

    return response.json()["access_token"]

