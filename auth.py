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
import threading


router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth/google/callback"

SCOPES = [
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/analytics.readonly",
]

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GSC_BASE = "https://searchconsole.googleapis.com/webmasters/v3"
SESSION_DAYS = 14
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
SESSION_COOKIE_NAME = "session_token"
OAUTH_STATE_COOKIE = "oauth_state_token"
OAUTH_STATE_TTL_SEC = 600
PASSWORD_HASH_ITERATIONS = max(100_000, int(os.getenv("APP_PASSWORD_HASH_ITERATIONS", "210000")))
LOGIN_RATE_LIMIT_WINDOW_SEC = max(60, int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SEC", "900")))
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = max(3, int(os.getenv("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "6")))
_LOGIN_ATTEMPTS = {}
_LOGIN_ATTEMPTS_LOCK = threading.Lock()


class RegisterIn(BaseModel):
    email: EmailStr
    name: str
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


def _hash_password_legacy(password: str) -> str:
    salt = os.getenv("APP_PASSWORD_SALT", "gsc-radar-default-salt")
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${digest}"


def _verify_pbkdf2_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_txt, salt, saved_digest = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_txt)
        check_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations
        ).hex()
        return hmac.compare_digest(saved_digest, check_digest)
    except Exception:
        return False


def verify_password(password: str, password_hash: str) -> bool:
    if (password_hash or "").startswith("pbkdf2_sha256$"):
        return _verify_pbkdf2_password(password, password_hash)
    return hmac.compare_digest(_hash_password_legacy(password), password_hash or "")


def _is_legacy_password_hash(password_hash: str) -> bool:
    return not (password_hash or "").startswith("pbkdf2_sha256$")


def create_session_token() -> str:
    return secrets.token_urlsafe(48)


def _login_attempt_key(email: str, request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    client_ip = forwarded_for or (request.client.host if request.client else "unknown")
    return f"{email}|{client_ip}"


def _check_login_rate_limit(key: str):
    now = datetime.now(timezone.utc)
    with _LOGIN_ATTEMPTS_LOCK:
        row = _LOGIN_ATTEMPTS.get(key)
        if not row:
            return
        blocked_until = row.get("blocked_until")
        if blocked_until and blocked_until > now:
            wait_sec = int((blocked_until - now).total_seconds())
            raise HTTPException(
                status_code=429,
                detail=f"Cok fazla hatali giris denemesi. {wait_sec} saniye sonra tekrar deneyin."
            )
        first_attempt = row.get("first_attempt")
        if first_attempt and (now - first_attempt).total_seconds() > LOGIN_RATE_LIMIT_WINDOW_SEC:
            _LOGIN_ATTEMPTS.pop(key, None)


def _record_login_failure(key: str):
    now = datetime.now(timezone.utc)
    with _LOGIN_ATTEMPTS_LOCK:
        row = _LOGIN_ATTEMPTS.get(key)
        if not row:
            _LOGIN_ATTEMPTS[key] = {
                "first_attempt": now,
                "count": 1,
                "blocked_until": None,
            }
            return
        first_attempt = row.get("first_attempt") or now
        if (now - first_attempt).total_seconds() > LOGIN_RATE_LIMIT_WINDOW_SEC:
            row["first_attempt"] = now
            row["count"] = 1
            row["blocked_until"] = None
            return
        row["count"] = int(row.get("count", 0)) + 1
        if row["count"] >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            row["blocked_until"] = now + timedelta(seconds=LOGIN_RATE_LIMIT_WINDOW_SEC)


def _clear_login_failures(key: str):
    with _LOGIN_ATTEMPTS_LOCK:
        _LOGIN_ATTEMPTS.pop(key, None)


def require_env():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET env degiskenleri eksik."
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
    r = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=30)
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
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    key = _login_attempt_key(email, request)
    _check_login_rate_limit(key)
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        _record_login_failure(key)
        raise HTTPException(status_code=401, detail="Email veya sifre hatali")
    _clear_login_failures(key)

    if _is_legacy_password_hash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        db.commit()

    token = create_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    session = UserSession(user_id=user.id, token=token, expires_at=expires_at)
    db.add(session)
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        path="/",
        max_age=SESSION_DAYS * 24 * 60 * 60
    )
    return {
        "message": "Login basarili",
        "user": {"id": user.id, "email": user.email, "name": user.name}
    }


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        db.query(UserSession).filter(UserSession.token == token).delete()
        db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
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

    data = r.json() or {}
    entries = data.get("siteEntry") or []

    # Sadece gercekten yetkili olunan property'leri goster.
    allowed_permissions = {"siteOwner", "siteFullUser", "siteRestrictedUser"}
    filtered_entries = [
        x for x in entries
        if str((x or {}).get("permissionLevel") or "").strip() in allowed_permissions
    ]
    data["siteEntry"] = filtered_entries
    return data


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


def fetch_ga4_rows(
    property_id: str,
    start_date: str,
    end_date: str,
    dimensions: list,
    metrics: list,
    db: Session,
    user_id: str = None,
    row_limit: int = 10000,
    dimension_filter: dict = None,
):
    refresh_token = get_refresh_token(db, user_id=user_id)
    access_token = refresh_access_token(refresh_token)

    clean_property = str(property_id or "").strip().replace("properties/", "")
    if not clean_property:
        raise HTTPException(status_code=400, detail="GA4 property_id gerekli")

    payload = {
        "dateRanges": [{"startDate": start_date, "endDate": end_date}],
        "dimensions": [{"name": d} for d in (dimensions or [])],
        "metrics": [{"name": m} for m in (metrics or [])],
        "limit": str(int(row_limit)),
    }
    if dimension_filter:
        payload["dimensionFilter"] = dimension_filter

    url = f"https://analyticsdata.googleapis.com/v1beta/properties/{clean_property}:runReport"
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )
    data = r.json() if r.text else {}
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=data or r.text)

    out = []
    for row in (data.get("rows") or []):
        dvals = row.get("dimensionValues") or []
        mvals = row.get("metricValues") or []
        out.append({
            "dimensions": [v.get("value", "") for v in dvals],
            "metrics": [v.get("value", "") for v in mvals],
        })
    return out


def fetch_ga4_properties(db: Session, user_id: str = None):
    refresh_token = get_refresh_token(db, user_id=user_id)
    access_token = refresh_access_token(refresh_token)

    headers = {"Authorization": f"Bearer {access_token}"}
    props = []
    page_token = None

    for _ in range(8):
        url = "https://analyticsadmin.googleapis.com/v1beta/accountSummaries?pageSize=200"
        if page_token:
            url += f"&pageToken={quote(page_token, safe='')}"
        r = requests.get(url, headers=headers, timeout=30)
        data = r.json() if r.text else {}
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=data or r.text)

        for acc in (data.get("accountSummaries") or []):
            account_name = (acc.get("displayName") or "").strip()
            for p in (acc.get("propertySummaries") or []):
                prop = (p.get("property") or "").strip()
                prop_id = prop.replace("properties/", "").strip()
                if not prop_id:
                    continue
                props.append({
                    "property": prop,
                    "property_id": prop_id,
                    "display_name": (p.get("displayName") or "").strip(),
                    "property_type": (p.get("propertyType") or "").strip(),
                    "parent_account": account_name,
                })

        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return props


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

    response = requests.post(GOOGLE_TOKEN_URL, data=payload, timeout=30)
    response.raise_for_status()

    return response.json()["access_token"]
