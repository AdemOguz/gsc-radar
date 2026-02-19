from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
import uuid
import hashlib
import json
from datetime import datetime, timezone, date, timedelta, time
from auth import (
    fetch_gsc_summary,
    test_gsc_fetch,
    get_access_token_from_refresh,
    fetch_gsc_rows,
    fetch_ga4_rows,
    fetch_ga4_properties,
)
from database import engine
from models import (
    Base,
    Site,
    Alert,
    HealthSnapshot,
    OAuthToken,
    KeywordSnapshot,
    User,
    UserSession,
    UserActivityLog,
    UserOAuthToken,
    BacklinkSnapshot,
    BacklinkWatchConfig,
    SeoChangeLog,
    CtrExperiment,
    CtrExperimentMetric,
    KpiGoal,
    DailyHealthJobConfig,
    PdfReportTemplate,
    DashboardPreference,
    ReportNote,
)
from deps import get_db, get_current_user
from keywords import fetch_keywords_from_gsc, save_keyword_snapshots, get_keyword_history, analyze_keyword_trends
from pydantic import BaseModel, Field
import random
import re
import math
from collections import Counter, defaultdict
from html import escape
import requests
import os
import threading
import time as time_mod
from urllib.parse import urlparse
import socket
import ipaddress
from analytics import analyze_trend, detect_anomalies, save_alerts_if_new, get_page_performance
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from database import SessionLocal





app = FastAPI(title="GSC Radar")

app.mount("/static", StaticFiles(directory="static"), name="static")


def _default_status_message_tr(status_code: int) -> str:
    return {
        400: "Gecersiz istek. Lutfen gonderdiginiz verileri kontrol edin.",
        401: "Kimlik dogrulamasi gerekli. Lutfen tekrar giris yapin.",
        403: "Bu islem icin yetkiniz yok.",
        404: "Istenen kaynak bulunamadi.",
        409: "Cakisma olustu. Veri zaten mevcut olabilir.",
        422: "Gonderilen veriler gecersiz. Lutfen alanlari kontrol edin.",
        429: "Cok fazla istek gonderdiniz. Lutfen biraz sonra tekrar deneyin.",
        500: "Sunucuda beklenmeyen bir hata olustu. Lutfen daha sonra tekrar deneyin.",
        502: "Harici servisten gecersiz yanit alindi.",
        503: "Hizmet gecici olarak kullanilamiyor. Lutfen daha sonra tekrar deneyin.",
    }.get(int(status_code or 500), "Islem sirasinda bir hata olustu.")


def _safe_json_loads(value: str):
    try:
        return json.loads(value)
    except Exception:
        return None


def _extract_error_message(detail) -> str:
    if detail is None:
        return ""
    if isinstance(detail, str):
        txt = detail.strip()
        if txt.startswith("{") or txt.startswith("["):
            parsed = _safe_json_loads(txt)
            if parsed is not None:
                extracted = _extract_error_message(parsed)
                if extracted:
                    return extracted
        return txt
    if isinstance(detail, list):
        parts = [_extract_error_message(x) for x in detail]
        parts = [p for p in parts if p]
        return "; ".join(parts)
    if isinstance(detail, dict):
        if isinstance(detail.get("message"), str):
            return detail.get("message", "").strip()
        if isinstance(detail.get("msg"), str):
            return detail.get("msg", "").strip()
        if "error" in detail:
            nested = _extract_error_message(detail.get("error"))
            if nested:
                return nested
        if "detail" in detail:
            nested = _extract_error_message(detail.get("detail"))
            if nested:
                return nested
        if "errors" in detail:
            nested = _extract_error_message(detail.get("errors"))
            if nested:
                return nested
        return json.dumps(detail, ensure_ascii=False)
    return str(detail)


def _contains_any(text: str, patterns: List[str]) -> bool:
    return any((p or "") in text for p in (patterns or []))


def _translate_message_tr(message: str, status_code: int = 500) -> str:
    msg = (message or "").strip()
    if not msg:
        return _default_status_message_tr(status_code)

    low = re.sub(r"\s+", " ", msg.lower()).strip()

    # Google API / OAuth / GA4 / GSC
    if _contains_any(low, [
        "user does not have sufficient permissions for this property",
        "insufficient permissions for this property",
        "not have sufficient permissions for this property",
    ]):
        return (
            "Bu GA4 property icin yeterli yetkiniz yok. "
            "Dogru Property ID kullandiginizi ve Google Analytics tarafinda en az Viewer yetkisi oldugunu kontrol edin."
        )
    if _contains_any(low, [
        "request had insufficient authentication scopes",
        "insufficient authentication scopes",
        "insufficient permissions",
        "insufficient permission",
    ]):
        return "Google erisim izni yetersiz. Google hesabinizi tekrar baglayip gerekli izinleri verin."
    if _contains_any(low, [
        "invalid_grant",
        "token has been expired or revoked",
        "token is expired",
        "token revoked",
        "access token uretilemedi",
    ]):
        return "Google oturumu gecersiz veya suresi dolmus. Google hesabinizi yeniden baglayin."
    if (
        "analytics admin api has not been used" in low
        or (
            "analyticsadmin.googleapis.com" in low
            and _contains_any(low, ["service_disabled", "disabled"])
        )
    ):
        return "Google Analytics Admin API aktif degil. Google Cloud'da analyticsadmin.googleapis.com servisini etkinlestirin."
    if (
        "analytics data api has not been used" in low
        or (
            "analyticsdata.googleapis.com" in low
            and _contains_any(low, ["service_disabled", "disabled"])
        )
    ):
        return "Google Analytics Data API aktif degil. Google Cloud'da analyticsdata.googleapis.com servisini etkinlestirin."
    if (
        _contains_any(low, ["search console api has not been used", "webmasters api has not been used"])
        or (
            "searchconsole.googleapis.com" in low
            and _contains_any(low, ["service_disabled", "disabled"])
        )
    ):
        return "Google Search Console API aktif degil. Google Cloud'da searchconsole.googleapis.com servisini etkinlestirin."
    if _contains_any(low, [
        "to learn more about property id",
        "property id",
        "property_id gerekli",
        "ga4 property bulunamadi",
        "uygun ga4 property secilemedi",
    ]):
        return "GA4 Property ID gecersiz veya erisiminiz olmayan bir property secildi. Dogru Property ID degerini girin."

    # Authentication / Authorization
    if _contains_any(low, ["permission denied", "forbidden", "caller does not have permission"]):
        return "Erisim izni reddedildi. Hesap yetkilerinizi kontrol edin."
    if _contains_any(low, ["unauthenticated", "invalid credentials", "authentication required", "gecersiz oturum", "oturum suresi dolmus"]):
        return "Kimlik dogrulamasi basarisiz. Lutfen yeniden giris yapin."
    if _contains_any(low, ["login gerekli", "once login olun"]):
        return "Bu islem icin giris yapmaniz gerekiyor."

    # Resource / conflict / format
    if _contains_any(low, ["not found", "bulunamadi", "template bulunamadi", "ctr test bulunamadi"]):
        return "Istenen kaynak bulunamadi."
    if _contains_any(low, ["already exists", "zaten kayitli", "zaten mevcut", "duplicate", "unique constraint"]):
        return "Kayit zaten mevcut."
    if _contains_any(low, ["invalid argument", "invalid request", "bad request", "invalid"]):
        if status_code == 422:
            return "Gonderilen veriler gecersiz. Lutfen alanlari kontrol edin."
        return "Gecersiz parametre gonderildi. Lutfen girdileri kontrol edin."
    if _contains_any(low, ["month yyyy-mm", "date format", "date parsing", "tarih formati"]):
        return "Tarih formati gecersiz. Lutfen belirtilen formati kullanin."

    # Network / timeout / upstream failures
    if _contains_any(low, [
        "timeout",
        "timed out",
        "deadline exceeded",
        "readtimeout",
        "connecttimeout",
    ]):
        return "Dis servis zaman asimina ugradi. Lutfen biraz sonra tekrar deneyin."
    if _contains_any(low, [
        "name or service not known",
        "temporary failure in name resolution",
        "failed to resolve",
        "nodename nor servname provided",
    ]):
        return "Alan adi cozumlenemedi. URL veya DNS ayarini kontrol edin."
    if _contains_any(low, [
        "connection refused",
        "max retries exceeded",
        "connection error",
        "newconnectionerror",
        "remote disconnected",
    ]):
        return "Hedef servise baglanti kurulamadi. Ag ve servis erisiminizi kontrol edin."
    if _contains_any(low, ["ssl", "certificate verify failed", "tls"]):
        return "SSL/TLS baglantisi kurulurken hata olustu. Sertifika ayarlarini kontrol edin."
    if _contains_any(low, [
        "service unavailable",
        "bad gateway",
        "upstream",
        "http 502",
        "http 503",
        "http 504",
        "status code 502",
        "status code 503",
        "status code 504",
    ]):
        return "Harici servis gecici olarak kullanilamiyor. Lutfen daha sonra tekrar deneyin."

    # Quota / rate limit
    if _contains_any(low, [
        "quota exceeded",
        "quota has been exceeded",
        "user rate limit exceeded",
        "rate limit exceeded",
        "too many requests",
        "resource_exhausted",
    ]):
        return "Servis kullanim limiti asildi. Bir sure bekleyip tekrar deneyin."

    # Internal / server
    if _contains_any(low, ["internal server error", "server error", "traceback", "exception"]):
        return "Sunucu tarafinda beklenmeyen bir hata olustu."

    # Pydantic/FastAPI validation (fallback)
    if "input should be greater than or equal to" in low:
        m = re.search(r"greater than or equal to\s+([0-9\.-]+)", low)
        return f"Deger en az {m.group(1)} olmali." if m else "Deger izin verilen minimum degerden kucuk."
    if "input should be greater than" in low:
        m = re.search(r"greater than\s+([0-9\.-]+)", low)
        return f"Deger {m.group(1)} degerinden buyuk olmali." if m else "Deger daha buyuk olmali."
    if "input should be less than or equal to" in low:
        m = re.search(r"less than or equal to\s+([0-9\.-]+)", low)
        return f"Deger en fazla {m.group(1)} olmali." if m else "Deger izin verilen maksimum degerden buyuk."
    if "input should be less than" in low:
        m = re.search(r"less than\s+([0-9\.-]+)", low)
        return f"Deger {m.group(1)} degerinden kucuk olmali." if m else "Deger daha kucuk olmali."
    if "field required" in low:
        return "Zorunlu alan eksik."
    if _contains_any(low, ["input should be a valid", "value is not a valid", "json decode error"]):
        return "Gonderilen veri formati gecersiz."

    # "HTTP 404" gibi ham fallback metinleri icin
    http_m = re.match(r"^http\s+(\d{3})$", low)
    if http_m:
        code = int(http_m.group(1))
        return f"Istek basarisiz oldu (HTTP {code})."

    # Genel fallback: 5xx hatalarda ham mesaji sizdirma.
    if int(status_code or 500) >= 500:
        return _default_status_message_tr(status_code)

    return msg


def _format_error_location(loc) -> str:
    if not isinstance(loc, (list, tuple)) or not loc:
        return "genel"
    labels = {
        "body": "govde",
        "query": "sorgu",
        "path": "yol",
        "header": "baslik",
        "cookie": "cerez",
    }
    normalized = [labels.get(str(x), str(x)) for x in loc]
    if len(normalized) > 1:
        return ".".join(normalized[1:])
    return normalized[0]


def _translate_validation_item(err: dict) -> dict:
    err = err or {}
    err_type = str(err.get("type") or "").lower()
    ctx = err.get("ctx") or {}
    field = _format_error_location(err.get("loc"))

    if "missing" in err_type:
        msg = "Bu alan zorunludur."
    elif err_type == "greater_than_equal":
        msg = f"Deger en az {ctx.get('ge')} olmali."
    elif err_type == "greater_than":
        msg = f"Deger {ctx.get('gt')} degerinden buyuk olmali."
    elif err_type == "less_than_equal":
        msg = f"Deger en fazla {ctx.get('le')} olmali."
    elif err_type == "less_than":
        msg = f"Deger {ctx.get('lt')} degerinden kucuk olmali."
    elif err_type in {"string_too_short", "too_short"}:
        min_len = ctx.get("min_length") or ctx.get("min_items")
        msg = f"Uzunluk en az {min_len} olmali." if min_len is not None else "Gonderilen metin cok kisa."
    elif err_type in {"string_too_long", "too_long"}:
        max_len = ctx.get("max_length") or ctx.get("max_items")
        msg = f"Uzunluk en fazla {max_len} olmali." if max_len is not None else "Gonderilen metin cok uzun."
    elif err_type in {"int_parsing", "int_type"}:
        msg = "Bu alan sayi (tam sayi) olmalidir."
    elif err_type in {"float_parsing", "float_type"}:
        msg = "Bu alan sayi olmalidir."
    elif err_type in {"bool_parsing", "bool_type"}:
        msg = "Bu alan dogru/yanlis (boolean) olmalidir."
    elif err_type in {"date_parsing", "date_from_datetime_parsing"}:
        msg = "Tarih formati gecersiz. YYYY-MM-DD formatini kullanin."
    elif err_type in {"datetime_parsing"}:
        msg = "Tarih-saat formati gecersiz."
    elif err_type == "literal_error":
        expected = ctx.get("expected")
        msg = f"Deger izin verilen seceneklerden biri olmali: {expected}" if expected else "Deger izin verilen seceneklerden biri olmali."
    else:
        raw_msg = str(err.get("msg") or "").strip()
        msg = _translate_message_tr(raw_msg, 422) if raw_msg else "Gecersiz veri gonderildi."

    user_msg = msg if field in {"", "genel"} else f"'{field}' alani: {msg}"
    return {
        "field": field,
        "message": user_msg,
        "type": err_type or "validation_error",
    }


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    translated = [_translate_validation_item(e) for e in exc.errors()]
    detail = (
        translated[0]["message"]
        if len(translated) == 1
        else "Gonderilen veriler gecersiz. Lutfen alanlari kontrol edin."
    )
    return JSONResponse(
        status_code=422,
        content={
            "detail": detail,
            "errors": translated,
        },
    )


@app.exception_handler(HTTPException)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler_tr(request: Request, exc: Exception):
    status_code = int(getattr(exc, "status_code", 500) or 500)
    raw_detail = getattr(exc, "detail", "")
    extracted = _extract_error_message(raw_detail)
    translated = _translate_message_tr(extracted, status_code)
    return JSONResponse(status_code=status_code, content={"detail": translated})


@app.exception_handler(Exception)
async def unhandled_exception_handler_tr(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": _default_status_message_tr(500)},
    )


def _admin_email_set() -> set:
    raw = os.getenv("ADMIN_EMAILS")
    if raw is None:
        raw = "ademoguz12@gmail.com"
    return {x.strip().lower() for x in raw.split(",") if x.strip()}


def _is_admin_user(user: User) -> bool:
    admins = _admin_email_set()
    if not admins:
        return False
    return (user.email or "").strip().lower() in admins


def _require_admin(user: User):
    if not _is_admin_user(user):
        raise HTTPException(status_code=403, detail="Bu alan sadece yonetici icin acik")
    return user


def _is_authenticated_request(request: Request) -> bool:
    token = request.cookies.get("session_token")
    if not token:
        return False
    db = SessionLocal()
    try:
        from models import UserSession
        sess = db.query(UserSession).filter(UserSession.token == token).first()
        if not sess:
            return False
        exp = sess.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp >= datetime.now(timezone.utc)
    finally:
        db.close()


@app.middleware("http")
async def require_login_middleware(request: Request, call_next):
    path = request.url.path

    public_prefixes = (
        "/auth/",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/robots.txt",
        "/sitemap.xml",
    )
    public_static_html = {
        "/static/login.html",
        "/static/home.html",
    }

    if path == "/":
        return await call_next(request)

    if any(path.startswith(p) for p in public_prefixes):
        return await call_next(request)

    if path.startswith("/static/"):
        if path.endswith(".html") and path not in public_static_html:
            if not _is_authenticated_request(request):
                return RedirectResponse("/static/login.html")
        return await call_next(request)

    if not _is_authenticated_request(request):
        return JSONResponse(status_code=401, content={"detail": "Login gerekli"})

    return await call_next(request)


@app.middleware("http")
async def security_headers_and_csrf_middleware(request: Request, call_next):
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
    if request.method in unsafe_methods:
        expected_origin = f"{request.url.scheme}://{request.url.netloc}"
        origin = (request.headers.get("origin") or "").strip().rstrip("/")
        referer = (request.headers.get("referer") or "").strip()
        if origin and origin.lower() != expected_origin.lower():
            return JSONResponse(status_code=403, content={"detail": "Gecersiz Origin"})
        if not origin and referer and not referer.lower().startswith(expected_origin.lower()):
            return JSONResponse(status_code=403, content={"detail": "Gecersiz Referer"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://searchconsole.googleapis.com https://analyticsdata.googleapis.com "
        "https://analyticsadmin.googleapis.com https://oauth2.googleapis.com https://accounts.google.com"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    path = request.url.path or "/"
    public_indexable = {"/", "/static/home.html"}
    if path in public_indexable:
        response.headers["X-Robots-Tag"] = "index, follow"
    else:
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@app.middleware("http")
async def activity_log_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path or "/"
    method = (request.method or "GET").upper()

    # Static/public noise'i loglama
    if (
        method == "OPTIONS"
        or path.startswith("/static/")
        or path.startswith("/docs")
        or path.startswith("/redoc")
        or path == "/openapi.json"
        or path == "/robots.txt"
        or path == "/sitemap.xml"
    ):
        return response

    token = request.cookies.get("session_token")
    if not token:
        return response

    # Sadece API/islem odakli pathleri logla
    if not (path.startswith("/sites/") or path.startswith("/auth/") or path.startswith("/admin/")):
        return response

    db = SessionLocal()
    try:
        sess = db.query(UserSession).filter(UserSession.token == token).first()
        if not sess:
            return response
        ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if not ip:
            ip = request.client.host if request.client else ""
        db.add(UserActivityLog(
            user_id=sess.user_id,
            method=method,
            path=path,
            query_string=(request.url.query or "")[:1000],
            status_code=int(getattr(response, "status_code", 200) or 200),
            ip_address=(ip or "")[:120],
            user_agent=(request.headers.get("user-agent") or "")[:1000],
        ))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return response



def ensure_utc(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def get_site_owned(site_id: str, user: User, db: Session) -> Site:
    site = (
        db.query(Site)
        .filter(
            Site.id == site_id,
            Site.user_id == user.id
        )
        .first()
    )
    if not site:
        raise HTTPException(status_code=404, detail="Site bulunamadi veya erisim yok")
    return site

def calculate_health(site_id: str, db: Session):
    alerts = (
        db.query(Alert)
        .filter(Alert.site_id == site_id)
        .all()
    )

    score = 100
    breakdown = []
    now = datetime.now(timezone.utc)

    for a in alerts:
        created_at = a.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        days_old = (now - created_at).days

        # --- zaman etkisi ---
        if days_old <= 7:
            time_factor = 1.0
        elif days_old <= 14:
            time_factor = 0.7
        elif days_old <= 30:
            time_factor = 0.4
        else:
            continue  # çok eski alarm → yok say

        # --- baz etki ---
        impact = 0

        if a.metric == "impressions":
            impact = 30 if a.severity == 3 else 18
        elif a.metric == "clicks":
            impact = 25 if a.severity == 3 else 15
        elif a.metric == "ctr":
            impact = 12 if a.severity == 3 else 7
        else:
            impact = 3

        final_impact = int(impact * time_factor)
        score -= final_impact

        breakdown.append({
            "alert_type": a.alert_type,
            "metric": a.metric,
            "severity": (
                "critical" if a.severity == 3
                else "warning" if a.severity == 2
                else "info"
            ),
            "impact": -final_impact,
            "delta_pct": a.delta_pct,
            "days_old": days_old,
            "created_at": a.created_at
        })

    score = max(score, 0)

    if score >= 85:
        status = "Healthy"
    elif score >= 65:
        status = "Risk"
    else:
        status = "Critical"

    return {
        "score": score,
        "status": status,
        "alerts": len(breakdown),
        "breakdown": breakdown
    }

def calculate_health_at_date(site_id: str, db: Session, ref_date: datetime):
    alerts = (
        db.query(Alert)
        .filter(
            Alert.site_id == site_id,
            Alert.created_at <= ref_date
        )
        .all()
    )

    score = 100
    now = ref_date.replace(tzinfo=timezone.utc)
    alerts_count = 0

    for a in alerts:
        created_at = a.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        days_old = (now - created_at).days

        if days_old <= 7:
            time_factor = 1.0
        elif days_old <= 14:
            time_factor = 0.7
        elif days_old <= 30:
            time_factor = 0.4
        else:
            continue

        if a.metric == "impressions":
            impact = 30 if a.severity == 3 else 18
        elif a.metric == "clicks":
            impact = 25 if a.severity == 3 else 15
        elif a.metric == "ctr":
            impact = 12 if a.severity == 3 else 7
        else:
            impact = 3

        score -= int(impact * time_factor)
        alerts_count += 1

    score = max(score, 0)

    if score >= 85:
        status = "Healthy"
    elif score >= 65:
        status = "Risk"
    else:
        status = "Critical"

    return score, status, alerts_count



def _run_single_health_snapshot(site: Site, user: User, db: Session, days: int = 1) -> dict:
    if not site.gsc_property_url:
        return {"site_id": site.id, "status": "skipped", "reason": "missing_gsc_property"}

    end_date = (date.today() - timedelta(days=1)).isoformat()
    start_date = (date.today() - timedelta(days=days)).isoformat()
    gsc_data = fetch_gsc_summary(
        site_url=site.gsc_property_url,
        start_date=start_date,
        end_date=end_date,
        db=db,
        user_id=user.id,
    )

    clicks = gsc_data.get("clicks", 0)
    impressions = gsc_data.get("impressions", 0)
    ctr = round((clicks / impressions), 3) if impressions > 0 else 0.0
    confidence = round(min(1.0, impressions / 1000), 2)
    score = round((ctr * 100) * 0.6 + (confidence * 100) * 0.4, 2)
    if score >= 80:
        status = "Healthy"
    elif score >= 60:
        status = "Risk"
    else:
        status = "Critical"

    snapshot = HealthSnapshot(
        site_id=site.id,
        created_at=datetime.now(timezone.utc),
        score=score,
        status=status,
        clicks=clicks,
        impressions=impressions,
        ctr=ctr,
        confidence=confidence,
        alerts_count=0,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)

    detected_alerts = detect_anomalies(site.id, db)
    new_alerts_count = save_alerts_if_new(detected_alerts, db)
    snapshot.alerts_count = new_alerts_count
    db.commit()

    return {
        "site_id": site.id,
        "status": "ok",
        "score": score,
        "clicks": clicks,
        "impressions": impressions,
        "ctr": ctr,
        "alerts_detected": new_alerts_count,
    }


def _run_due_daily_health_jobs_once():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due_configs = (
            db.query(DailyHealthJobConfig, Site, User)
            .join(Site, Site.id == DailyHealthJobConfig.site_id)
            .join(User, User.id == Site.user_id)
            .filter(DailyHealthJobConfig.enabled == True)  # noqa: E712
            .all()
        )
        for cfg, site, user in due_configs:
            hour_match = int(cfg.run_hour_utc or 3) == now.hour
            already_today = bool(cfg.last_run_at and ensure_utc(cfg.last_run_at).date() == now.date())
            if (not hour_match) or already_today:
                continue
            try:
                _run_single_health_snapshot(site, user, db, days=1)
                cfg.last_run_at = now
                db.commit()
            except Exception:
                db.rollback()
    finally:
        db.close()


def _daily_health_worker_loop():
    while True:
        try:
            _run_due_daily_health_jobs_once()
        except Exception:
            pass
        time_mod.sleep(300)


_daily_worker_started = False


@app.on_event("startup")
def on_startup():
    global _daily_worker_started
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":
        with engine.connect() as conn:
            has_col = conn.execute(text("""
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'sites' AND column_name = 'ga4_property_id'
                LIMIT 1
            """)).first()
            if not has_col:
                conn.execute(text("ALTER TABLE sites ADD COLUMN ga4_property_id VARCHAR"))
                conn.commit()

    if os.getenv("ENABLE_DAILY_HEALTH_WORKER", "0") == "1" and not _daily_worker_started:
        worker = threading.Thread(target=_daily_health_worker_loop, daemon=True)
        worker.start()
        _daily_worker_started = True

@app.get("/")
def login_page():
    return RedirectResponse("/static/home.html")


def _public_base_url(request: Request) -> str:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme or "https"
    host = forwarded_host or request.headers.get("host") or request.url.netloc or "localhost:8000"
    return f"{scheme}://{host}".rstrip("/")


@app.get("/robots.txt")
def robots_txt(request: Request):
    base = _public_base_url(request)
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /auth/\n"
        "Disallow: /docs\n"
        "Disallow: /redoc\n"
        "Disallow: /openapi.json\n"
        "Disallow: /sites/\n"
        "Disallow: /jobs/\n"
        "Disallow: /static/login.html\n"
        "Disallow: /static/site-select.html\n"
        "Disallow: /static/health-dashboard.html\n"
        "Disallow: /static/advanced-dashboard.html\n"
        "Disallow: /static/keywords-dashboard.html\n"
        "Disallow: /static/monthly-seo-report.html\n"
        f"Sitemap: {base}/sitemap.xml\n"
    )
    return Response(content=body, media_type="text/plain; charset=utf-8")


@app.get("/sitemap.xml")
def sitemap_xml(request: Request):
    base = _public_base_url(request)
    today = datetime.now(timezone.utc).date().isoformat()
    urls = [
        {"loc": f"{base}/", "changefreq": "weekly", "priority": "1.0"},
        {"loc": f"{base}/static/home.html", "changefreq": "weekly", "priority": "0.9"},
    ]
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    ]
    for u in urls:
        lines.append("  <url>")
        lines.append(f"    <loc>{escape(u['loc'])}</loc>")
        lines.append(f"    <lastmod>{today}</lastmod>")
        lines.append(f"    <changefreq>{u['changefreq']}</changefreq>")
        lines.append(f"    <priority>{u['priority']}</priority>")
        lines.append("  </url>")
    lines.append("</urlset>")
    return Response(content="\n".join(lines), media_type="application/xml; charset=utf-8")

class GscSiteIn(BaseModel):
    # gsc_property_url: sc-domain:example.com OR https://example.com/
    gsc_property_url: str = None
    # backward-compat (eski frontend)
    site_url: str = None


class CompetitorInput(BaseModel):
    name: str
    clicks: float = 0
    impressions: float = 0
    ctr: float = 0.0  # percent
    avg_position: float = 0.0
    top10_share: float = 0.0  # percent
    indexed_pages: int = 0
    backlinks: int = 0
    priority_keywords: List[str] = []


class CompetitorAnalysisRequest(BaseModel):
    month: Optional[str] = None  # YYYY-MM
    objective: Optional[str] = "traffic_growth"
    competitors: List[CompetitorInput] = []


class BacklinkInput(BaseModel):
    source_url: str
    target_url: str
    anchor_text: Optional[str] = ""
    domain_authority: float = 0.0
    spam_score: float = 0.0
    is_active: bool = True
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class BacklinkSnapshotRequest(BaseModel):
    snapshot_date: Optional[str] = None
    backlinks: List[BacklinkInput] = []


class ContentAuditRequest(BaseModel):
    page_url: str
    title: Optional[str] = ""
    h1: Optional[str] = ""
    headings: List[str] = []
    entities: List[str] = []
    target_keyword: Optional[str] = None
    days: int = 28


class SeoChangeLogIn(BaseModel):
    change_type: str
    title: str
    description: Optional[str] = ""
    page_url: Optional[str] = ""
    impact_scope: Optional[str] = "site"
    changed_at: Optional[str] = None


class CtrExperimentIn(BaseModel):
    page_url: str
    variant_name: str
    title_variant: Optional[str] = ""
    meta_variant: Optional[str] = ""
    hypothesis: Optional[str] = ""
    status: Optional[str] = "running"
    started_at: Optional[str] = None
    ended_at: Optional[str] = None


class CtrSnapshotIn(BaseModel):
    start_date: str
    end_date: str


class CrawlRequest(BaseModel):
    urls: List[str] = Field(default_factory=list)
    timeout_sec: int = 12


class BacklinkWatchConfigIn(BaseModel):
    webhook_url: Optional[str] = None
    notify_new: bool = True
    notify_lost: bool = True
    notify_toxic: bool = True
    enabled: bool = False


class PdfTemplateIn(BaseModel):
    name: str
    theme: str = "agency"
    include_sections: List[str] = Field(default_factory=lambda: [
        "overview",
        "alerts",
        "keywords",
        "backlinks",
        "recommendations",
    ])


class KpiGoalIn(BaseModel):
    metric: str  # clicks/impressions/ctr/position/visibility
    target_value: float
    start_date: str
    end_date: str
    note: Optional[str] = ""


class DailyHealthConfigIn(BaseModel):
    enabled: bool = True
    run_hour_utc: int = Field(default=3, ge=0, le=23)


class DashboardPreferencesIn(BaseModel):
    order: List[str] = Field(default_factory=list)
    hidden: List[str] = Field(default_factory=list)


class SerpSnippetScoreIn(BaseModel):
    title: str = Field(min_length=1, max_length=220)
    meta_description: Optional[str] = Field(default="", max_length=420)
    keyword: Optional[str] = Field(default="", max_length=140)
    page_url: Optional[str] = Field(default="", max_length=1000)


class ReportNoteIn(BaseModel):
    month: str = Field(min_length=7, max_length=7)
    note_type: str = Field(default="team", max_length=20)
    content: str = Field(min_length=1, max_length=8000)


STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "your", "have", "are", "you",
    "ile", "icin", "ve", "bir", "gibi", "daha", "son", "olarak", "neden", "nasil",
    "site", "sayfa", "seo", "www", "com", "net", "org"
}


def _parse_iso_dt_or_none(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    txt = str(value).strip()
    if not txt:
        return None
    try:
        if len(txt) == 10:
            return datetime.fromisoformat(txt + "T00:00:00+00:00")
        dt = datetime.fromisoformat(txt.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _safe_date_str(value: Optional[str], fallback: date) -> str:
    dt = _parse_iso_dt_or_none(value)
    if not dt:
        return fallback.isoformat()
    return dt.date().isoformat()


def _pct_delta(curr: float, prev: float) -> float:
    if prev in (0, None):
        return 0.0
    return round(((curr - prev) / prev) * 100, 2)


def _mean_std(values: List[float]):
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var)


def _tr_lower(value: str) -> str:
    # Turkish-aware casing: I -> ı and İ -> i
    return (value or "").translate(str.maketrans({"I": "ı", "İ": "i"})).lower()


def _normalize_text(value: str) -> str:
    txt = _tr_lower(value)
    # Keep Unicode letters/digits (including Turkish chars), remove punctuation/symbols.
    txt = re.sub(r"[^\w\s]", " ", txt, flags=re.UNICODE)
    txt = txt.replace("_", " ")
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt


def _extract_meta_content(html: str, meta_name: str) -> str:
    pattern = r'<meta[^>]+name=[\"\\\']' + re.escape(meta_name) + r'[\"\\\'][^>]+content=[\"\\\']([^\"\\\']*)[\"\\\']'
    m = re.search(pattern, html, flags=re.IGNORECASE)
    if not m:
        # also handle content before name ordering
        pattern_rev = r'<meta[^>]+content=[\"\\\']([^\"\\\']*)[\"\\\'][^>]+name=[\"\\\']' + re.escape(meta_name) + r'[\"\\\']'
        m = re.search(pattern_rev, html, flags=re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\\s+", " ", (m.group(1).strip() if m else ""))


def _extract_canonical(html: str) -> str:
    m = re.search(r'<link[^>]+rel=[\"\\\']canonical[\"\\\'][^>]+href=[\"\\\']([^\"\\\']+)[\"\\\']', html, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'<link[^>]+href=[\"\\\']([^\"\\\']+)[\"\\\'][^>]+rel=[\"\\\']canonical[\"\\\']', html, flags=re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _is_noindex(html: str) -> bool:
    robots = _extract_meta_content(html, "robots").lower()
    googlebot = _extract_meta_content(html, "googlebot").lower()
    return ("noindex" in robots) or ("noindex" in googlebot)


def _is_private_or_local_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if not host:
        return True
    if host in {"localhost"}:
        return True

    def _blocked_ip(ip_txt: str) -> bool:
        ip = ipaddress.ip_address(ip_txt)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    try:
        return _blocked_ip(host)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True

    for info in infos:
        ip_txt = info[4][0]
        try:
            if _blocked_ip(ip_txt):
                return True
        except ValueError:
            return True
    return False


def _is_public_http_url(url: str) -> bool:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.hostname:
        return False
    return not _is_private_or_local_host(parsed.hostname)


def _normalize_host(host: str) -> str:
    txt = (host or "").strip().lower().strip(".")
    return txt[4:] if txt.startswith("www.") else txt


def _is_allowed_site_url(url: str, site_domain: str) -> bool:
    parsed = urlparse((url or "").strip())
    target_host = _normalize_host(parsed.hostname or "")
    site_raw = (site_domain or "").strip()
    site_host = _normalize_host(urlparse(site_raw if "://" in site_raw else f"https://{site_raw}").hostname or site_raw)
    if not target_host or not site_host:
        return False
    return target_host == site_host or target_host.endswith("." + site_host)


def _is_safe_webhook_url(url: str) -> bool:
    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https":
        return False
    return _is_public_http_url(url)


def _send_webhook(url: str, payload: dict):
    if not url:
        return
    if not _is_safe_webhook_url(url):
        return
    try:
        requests.post(url, json=payload, timeout=10, allow_redirects=False)
    except Exception:
        # webhook hatalari ana akis icin hard-fail olmamali
        pass


def _extract_terms(value: str) -> List[str]:
    txt = _normalize_text(value)
    if not txt:
        return []
    parts = txt.split(" ")
    return [p for p in parts if len(p) >= 3 and p not in STOPWORDS]


def _classify_keyword_intent(keyword: str) -> str:
    txt = _normalize_text(keyword or "")
    if not txt:
        return "informational"
    words = set(txt.split(" "))

    transactional = {
        "satin", "al", "buy", "teklif", "fiyat", "ucret", "randevu", "kayit", "sepete",
        "indirim", "kupon", "kampanya", "rezervasyon", "book"
    }
    commercial = {
        "en", "iyi", "karsilastirma", "yorum", "review", "alternatif", "vs", "fiyatlari",
        "oneri", "listesi", "tavsiye"
    }
    navigational = {
        "giris", "login", "iletisim", "contact", "hakkimizda", "about", "adres", "telefon",
        "musteri", "panel", "dashboard"
    }
    informational = {
        "nedir", "nasil", "ne", "why", "what", "rehber", "guide", "ornek", "ipuclari",
        "aciklama", "anlami", "ogren", "egitim"
    }

    if words & transactional:
        return "transactional"
    if words & commercial:
        return "commercial"
    if words & navigational:
        return "navigational"
    if words & informational:
        return "informational"
    return "informational"


def _smart_recommendation_for_alert(metric: str, reason: str, delta_pct: float) -> dict:
    metric_txt = (metric or "").strip().lower()
    reason_txt = _normalize_text(reason or "")
    drop = float(delta_pct or 0) < 0
    if "page" in metric_txt or "anomali" in reason_txt:
        return {
            "root_cause": "Sayfa, ziyaretcinin bekledigi cevabi tam vermiyor olabilir",
            "action": "Sayfanin ana basligini ve icerigini daha anlasilir yapin, eksik sorulari ekleyin.",
            "window": "24-72 saat"
        }
    if "ctr" in metric_txt:
        return {
            "root_cause": "Insanlar sizi goruyor ama daha az tikliyor",
            "action": "Baslik ve aciklama metnini daha net hale getirin. Iki farkli metin deneyip sonucu karsilastirin.",
            "window": "3-7 gun"
        }
    if "impression" in metric_txt:
        return {
            "root_cause": "Bazi aramalarda daha az gorunmeye basladiniz",
            "action": "Eksik kalan sorgulari belirleyin, yeni icerik bolumleri ekleyin ve ilgili sayfalardan baglanti verin.",
            "window": "3-10 gun"
        }
    if "click" in metric_txt:
        return {
            "root_cause": "Tiklama dususu var, birden fazla neden olabilir",
            "action": "En cok dusen sayfalari guncelleyip baslik/aciklama metinlerini iyilestirin.",
            "window": "24-72 saat"
        }
    if "score" in metric_txt or "status" in metric_txt:
        return {
            "root_cause": "Genel performansta bozulma var",
            "action": "Kritik uyarilardan baslayin ve sorunlu sayfalari sirayla duzeltin.",
            "window": "Acil"
        }
    return {
        "root_cause": "Metrik dalgalanmasi",
        "action": ("Dusus trendi devam ediyorsa haftalik aksiyon plani olusturun."
                   if drop else "Degisimi 2-3 gun daha izleyip kalici aksiyon alin."),
        "window": "2-5 gun"
    }


def _build_page_map(rows: List[dict]) -> dict:
    out = {}
    for r in rows:
        keys = r.get("keys") or []
        if not keys:
            continue
        page = str(keys[0]).strip()
        if not page:
            continue
        impressions = float(r.get("impressions", 0) or 0)
        clicks = float(r.get("clicks", 0) or 0)
        ctr = float(r.get("ctr", 0) or 0)
        position = float(r.get("position", 0) or 0)
        out[page] = {
            "clicks": clicks,
            "impressions": impressions,
            "ctr": ctr if ctr > 0 else (clicks / impressions if impressions > 0 else 0.0),
            "position": position,
        }
    return out


def _median(values: List[float]) -> float:
    vals = sorted([float(v) for v in values if v is not None])
    if not vals:
        return 0.0
    mid = len(vals) // 2
    if len(vals) % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


def _url_to_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return "/"
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urlparse(raw)
        path = (p.path or "/").strip() or "/"
    else:
        path = raw.split("?")[0].strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def _resolve_ga4_property_id(
    site: Site,
    user: User,
    db: Session,
    provided_property_id: Optional[str] = None,
) -> (str, str):
    manual = (provided_property_id or "").strip().replace("properties/", "")
    if manual:
        if site.ga4_property_id != manual:
            site.ga4_property_id = manual
            db.commit()
        return manual, "manual"

    if site.ga4_property_id:
        return site.ga4_property_id, "saved"

    try:
        props = fetch_ga4_properties(db=db, user_id=user.id)
    except HTTPException as e:
        msg = str(e.detail or "")
        if e.status_code == 403 and ("analyticsadmin.googleapis.com" in msg or "SERVICE_DISABLED" in msg):
            raise HTTPException(
                status_code=400,
                detail=(
                    "GA4 otomatik property secimi icin Google Analytics Admin API aktif degil. "
                    "Iki secenek var: (1) analyticsadmin.googleapis.com API'sini acin, "
                    "(2) Growth Tools ekraninda GA4 Property ID'yi manuel girin."
                ),
            )
        raise
    if not props:
        raise HTTPException(status_code=400, detail="GA4 property bulunamadi. Google Analytics erisimi gerekli.")

    domain = (site.domain or "").strip().lower()
    domain_core = domain.split(".")[0] if domain else ""

    def score_prop(p: dict) -> float:
        name = (p.get("display_name") or "").lower()
        score = 0.0
        if domain and domain in name:
            score += 3.0
        if domain_core and domain_core in name:
            score += 2.0
        return score

    ranked = sorted(props, key=score_prop, reverse=True)
    best = ranked[0]
    selected = best.get("property_id")
    if not selected:
        raise HTTPException(status_code=400, detail="Uygun GA4 property secilemedi.")

    site.ga4_property_id = selected
    db.commit()
    return selected, "auto"


def _page_query_losses(
    site_url: str,
    page_url: str,
    current_start: str,
    current_end: str,
    prev_start: str,
    prev_end: str,
    user_id: str,
    db: Session,
) -> List[dict]:
    filter_page = [{"filters": [{"dimension": "page", "operator": "equals", "expression": page_url}]}]
    current_q = fetch_gsc_rows(
        site_url=site_url,
        start_date=current_start,
        end_date=current_end,
        dimensions=["query"],
        row_limit=250,
        dimension_filter_groups=filter_page,
        db=db,
        user_id=user_id,
    )
    prev_q = fetch_gsc_rows(
        site_url=site_url,
        start_date=prev_start,
        end_date=prev_end,
        dimensions=["query"],
        row_limit=250,
        dimension_filter_groups=filter_page,
        db=db,
        user_id=user_id,
    )

    def as_map(rows: List[dict]):
        m = {}
        for r in rows:
            keys = r.get("keys") or []
            if not keys:
                continue
            q = str(keys[0]).strip().lower()
            if not q:
                continue
            m[q] = float(r.get("impressions", 0) or 0)
        return m

    cm = as_map(current_q)
    pm = as_map(prev_q)
    losses = []
    for q, prev_imp in pm.items():
        curr_imp = cm.get(q, 0.0)
        delta = curr_imp - prev_imp
        if delta < 0:
            losses.append({"query": q, "impression_delta": round(delta, 2)})
    losses.sort(key=lambda x: x["impression_delta"])
    return losses[:8]


def _estimate_page_reason(click_delta: float, imp_delta: float, ctr_delta: float, pos_delta: float, losses: List[dict]) -> str:
    if imp_delta <= -30 and pos_delta >= 2:
        return "Sayfa arama sonuclarinda geri dusmus."
    if click_delta <= -25 and abs(imp_delta) < 10 and ctr_delta <= -20:
        return "Gorunurluk benzer ama tiklama dusuk; baslik ve aciklama iyilestirilmeli."
    if imp_delta <= -25 and abs(pos_delta) < 1.5:
        return "Bu donemde aranma ilgisi azalmis olabilir."
    if losses:
        return "Bazi sorgularda gorunurluk kaybi var."
    return "Neden net degil; sayfayi guncelleyip tekrar olcum yapin."


def _backlink_risk(anchor_text: str, domain_authority: float, spam_score: float) -> float:
    anchor = (anchor_text or "").lower()
    toxic_terms = ("casino", "bet", "viagra", "loan", "porn", "adult")
    risk = 0.0
    if spam_score >= 60:
        risk += 0.65
    elif spam_score >= 40:
        risk += 0.4
    if domain_authority <= 10:
        risk += 0.2
    elif domain_authority <= 20:
        risk += 0.1
    if any(t in anchor for t in toxic_terms):
        risk += 0.35
    return round(min(1.0, risk), 2)


DASHBOARD_CARD_KEYS = [
    "health_score",
    "clicks",
    "impressions",
    "ctr",
    "critical_alerts",
    "warning_alerts",
]


def _normalize_dashboard_preferences(order: List[str], hidden: List[str]) -> dict:
    valid = set(DASHBOARD_CARD_KEYS)
    clean_order = []
    for key in order or []:
        k = (key or "").strip()
        if k and k in valid and k not in clean_order:
            clean_order.append(k)
    for k in DASHBOARD_CARD_KEYS:
        if k not in clean_order:
            clean_order.append(k)

    clean_hidden = []
    for key in hidden or []:
        k = (key or "").strip()
        if k and k in valid and k not in clean_hidden:
            clean_hidden.append(k)
    return {"order": clean_order, "hidden": clean_hidden}


def _safe_month_or_400(value: str) -> str:
    raw = (value or "").strip()
    if not re.match(r"^\d{4}-\d{2}$", raw):
        raise HTTPException(status_code=400, detail="month YYYY-MM formatinda olmali")
    year = int(raw[:4])
    month = int(raw[5:7])
    if year < 2000 or year > 2100 or month < 1 or month > 12:
        raise HTTPException(status_code=400, detail="month YYYY-MM formatinda olmali")
    return raw


def _classify_page_drop_reason(click_delta_pct: float, imp_delta_pct: float, ctr_delta_pct: float, pos_delta: float) -> str:
    if imp_delta_pct <= -15 and pos_delta >= 1.0:
        return "Siralama gerilemesi"
    if ctr_delta_pct <= -12 and abs(imp_delta_pct) < 8:
        return "Tiklama orani dususu"
    if imp_delta_pct <= -15 and abs(pos_delta) < 1.0:
        return "Arama ilgisi azalmis"
    if pos_delta >= 1.5 and imp_delta_pct <= -5:
        return "Sonuclarda geri dusme"
    return "Birden fazla etki olabilir"


def _build_serp_snippet_score(payload: SerpSnippetScoreIn) -> dict:
    title = (payload.title or "").strip()
    meta = (payload.meta_description or "").strip()
    keyword = _normalize_text(payload.keyword or "")
    page_url = (payload.page_url or "").strip()

    score = 100
    suggestions = []

    t_len = len(title)
    if t_len < 38:
        score -= 14
        suggestions.append("Title cok kisa, 45-60 karakter araligina yakinlastirin.")
    elif t_len > 62:
        score -= 14
        suggestions.append("Title cok uzun, kesilme riskini azaltmak icin kisaltin.")
    else:
        score += 5

    m_len = len(meta)
    if m_len < 90:
        score -= 12
        suggestions.append("Meta aciklama kisa, fayda onerisi ve CTA ekleyin.")
    elif m_len > 165:
        score -= 10
        suggestions.append("Meta aciklama uzun, 120-155 karaktere yakinlayin.")
    else:
        score += 5

    title_norm = _normalize_text(title)
    meta_norm = _normalize_text(meta)
    url_norm = _normalize_text(page_url)
    if keyword:
        if keyword in title_norm:
            score += 12
        else:
            score -= 14
            suggestions.append("Anahtar kelime title icinde gecmiyor.")
        if keyword in meta_norm:
            score += 8
        else:
            score -= 8
            suggestions.append("Anahtar kelime meta aciklamada gecmiyor.")
        if keyword in url_norm:
            score += 4

    power_words = {"hizli", "ucretsiz", "en iyi", "kapsamli", "rehber", "cozum", "fiyat", "analiz"}
    if any(p in title_norm for p in power_words):
        score += 4
    else:
        score -= 4
        suggestions.append("Title'a guclu bir deger ifadesi ekleyin.")

    if not re.search(r"\d", title):
        score -= 2
    if not meta.endswith(".") and m_len > 0:
        score -= 1

    score = max(0, min(100, int(round(score))))
    grade = "Yuksek"
    if score < 80:
        grade = "Orta"
    if score < 60:
        grade = "Dusuk"

    display_url = page_url or "https://example.com/sayfa"
    title_preview = title if len(title) <= 62 else (title[:59] + "...")
    meta_preview = meta if len(meta) <= 160 else (meta[:157] + "...")
    if not title_preview:
        title_preview = "Title giriniz"
    if not meta_preview:
        meta_preview = "Meta aciklama giriniz"

    return {
        "ctr_score": score,
        "grade": grade,
        "signals": {
            "title_length": t_len,
            "meta_length": m_len,
            "keyword_in_title": bool(keyword and keyword in title_norm),
            "keyword_in_meta": bool(keyword and keyword in meta_norm),
            "keyword_in_url": bool(keyword and keyword in url_norm),
        },
        "suggestions": suggestions[:6],
        "preview": {
            "display_url": display_url,
            "title": title_preview,
            "meta_description": meta_preview,
        }
    }

@app.post("/sites/from-gsc")
def create_or_get_site_from_gsc(
    payload: GscSiteIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Hangi parametrenin geldiğini kontrol et
    property_url = payload.gsc_property_url or payload.site_url
    if not property_url:
        raise HTTPException(status_code=400, detail="gsc_property_url veya site_url gerekli")
    
    # Kullaniciya ait mevcut site var mi kontrol et
    site = db.query(Site).filter(
        Site.gsc_property_url == property_url,
        Site.user_id == user.id
    ).first()

    if site:
        return {
            "site_id": site.id,
            "domain": site.domain,
            "gsc_property_url": site.gsc_property_url
        }

    # Global kayitta ayni property varsa kontrollu ele al
    global_site = db.query(Site).filter(Site.gsc_property_url == property_url).first()
    if global_site:
        # Eski veride user_id bos ise bu kullaniciya sahiplen
        if not global_site.user_id:
            global_site.user_id = user.id
            db.commit()
            db.refresh(global_site)
            return {
                "site_id": global_site.id,
                "domain": global_site.domain,
                "gsc_property_url": global_site.gsc_property_url
            }
        # Baska kullanicida varsa 500 yerine acik hata don
        raise HTTPException(
            status_code=409,
            detail="Bu GSC property baska bir hesapta kayitli."
        )

    # Domain'i property URL'den çıkar
    if property_url.startswith("sc-domain:"):
        domain = property_url.replace("sc-domain:", "").strip()
    else:
        # URL parse et
        domain = property_url.replace("https://", "").replace("http://", "").strip("/")
        # Eğer path varsa sadece hostname'i al
        if "/" in domain:
            domain = domain.split("/")[0]

    # Yeni site oluştur (ID otomatik oluşacak)
    new_site = Site(
        id=str(uuid.uuid4()),  # Kesin ID oluştur
        domain=domain,
        gsc_property_url=property_url,
        user_id=user.id
    )

    db.add(new_site)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(Site).filter(Site.gsc_property_url == property_url).first()
        if existing and existing.user_id == user.id:
            return {
                "site_id": existing.id,
                "domain": existing.domain,
                "gsc_property_url": existing.gsc_property_url
            }
        raise HTTPException(
            status_code=409,
            detail="Bu GSC property zaten kayitli."
        )
    db.refresh(new_site)

    return {
        "site_id": new_site.id,
        "domain": new_site.domain,
        "gsc_property_url": new_site.gsc_property_url
    }


# ---------- SITES ----------

@app.post("/sites")
def create_site(
    domain: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    existing = db.query(Site).filter(Site.domain == domain, Site.user_id == user.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Site already exists")

    global_domain = db.query(Site).filter(Site.domain == domain).first()
    if global_domain and global_domain.user_id != user.id:
        raise HTTPException(status_code=409, detail="Bu domain baska bir hesapta kayitli")

    site = Site(id=str(uuid.uuid4()), domain=domain, user_id=user.id)
    db.add(site)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(Site).filter(Site.domain == domain, Site.user_id == user.id).first()
        if existing:
            return {"id": existing.id, "domain": existing.domain, "created_at": existing.created_at}
        raise HTTPException(status_code=409, detail="Bu domain zaten kayitli")
    db.refresh(site)

    return {"id": site.id, "domain": site.domain, "created_at": site.created_at}


@app.get("/sites")
def list_sites(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sites = db.query(Site).filter(Site.user_id == user.id).all()
    return [{"id": s.id, "domain": s.domain, "created_at": s.created_at} for s in sites]


@app.get("/sites/{site_id}/dashboard/preferences")
def get_dashboard_preferences(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    row = (
        db.query(DashboardPreference)
        .filter(DashboardPreference.site_id == site_id, DashboardPreference.user_id == user.id)
        .first()
    )
    if not row:
        prefs = _normalize_dashboard_preferences([], [])
        return {
            "site_id": site_id,
            "preferences": prefs,
            "updated_at": None,
        }
    try:
        order = json.loads(row.card_order or "[]")
    except Exception:
        order = []
    try:
        hidden = json.loads(row.hidden_cards or "[]")
    except Exception:
        hidden = []
    prefs = _normalize_dashboard_preferences(order, hidden)
    return {
        "site_id": site_id,
        "preferences": prefs,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.post("/sites/{site_id}/dashboard/preferences")
def save_dashboard_preferences(
    site_id: str,
    payload: DashboardPreferencesIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    prefs = _normalize_dashboard_preferences(payload.order, payload.hidden)
    row = (
        db.query(DashboardPreference)
        .filter(DashboardPreference.site_id == site_id, DashboardPreference.user_id == user.id)
        .first()
    )
    if not row:
        row = DashboardPreference(
            site_id=site_id,
            user_id=user.id,
        )
        db.add(row)
    row.card_order = json.dumps(prefs["order"], ensure_ascii=False)
    row.hidden_cards = json.dumps(prefs["hidden"], ensure_ascii=False)
    db.commit()
    db.refresh(row)
    return {
        "ok": True,
        "site_id": site_id,
        "preferences": prefs,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.get("/admin/users")
def admin_list_users(
    limit: int = Query(200, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    _require_admin(user)
    users = db.query(User).order_by(User.created_at.desc()).limit(limit).all()
    out = []
    for u in users:
        last_log = (
            db.query(UserActivityLog)
            .filter(UserActivityLog.user_id == u.id)
            .order_by(UserActivityLog.created_at.desc())
            .first()
        )
        log_count = db.query(UserActivityLog).filter(UserActivityLog.user_id == u.id).count()
        out.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "activity_count": int(log_count),
            "last_activity_at": (last_log.created_at.isoformat() if last_log and last_log.created_at else None),
            "last_activity": (
                {
                    "method": last_log.method,
                    "path": last_log.path,
                    "status_code": last_log.status_code,
                } if last_log else None
            )
        })
    return {
        "admin_email": user.email,
        "total_users": len(out),
        "users": out
    }


@app.get("/admin/users/{member_user_id}/activities")
def admin_user_activities(
    member_user_id: str,
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    _require_admin(user)
    member = db.query(User).filter(User.id == member_user_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Kullanici bulunamadi")
    rows = (
        db.query(UserActivityLog)
        .filter(UserActivityLog.user_id == member_user_id)
        .order_by(UserActivityLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "user": {
            "id": member.id,
            "email": member.email,
            "name": member.name,
        },
        "count": len(rows),
        "activities": [
            {
                "id": r.id,
                "method": r.method,
                "path": r.path,
                "query_string": r.query_string or "",
                "status_code": r.status_code,
                "ip_address": r.ip_address or "",
                "user_agent": r.user_agent or "",
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }




# ---------- SCORE ----------

@app.get("/sites/{site_id}/score")
def radar_score(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    alerts = db.query(Alert).filter(Alert.site_id == site_id).all()

    score = 100
    critical = 0
    warning = 0

    for a in alerts:
        if a.severity == 3:
            score -= 15
            critical += 1
        elif a.severity == 2:
            score -= 5
            warning += 1

    score = max(score, 0)

    status = "Healthy"
    if score < 85:
        status = "Risk"
    if score < 65:
        status = "Critical"

    return {
        "site_id": site_id,
        "score": score,
        "status": status,
        "breakdown": {
            "critical": critical,
            "warning": warning,
            "total_alerts": len(alerts),
        },
    }

from auth import router as auth_router
app.include_router(auth_router)

from datetime import date, timedelta
import uuid
import hashlib

@app.post("/radar/analyze")
def radar_analyze(
    site_id: str,
    site_url: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    site = get_site_owned(site_id, user, db)
    effective_site_url = site.gsc_property_url or site_url
    if not effective_site_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    today = date.today()

    current_start = today - timedelta(days=7)
    current_end = today - timedelta(days=1)

    baseline_start = today - timedelta(days=14)
    baseline_end = today - timedelta(days=8)

    current = fetch_gsc_summary(
        effective_site_url,
        current_start.isoformat(),
        current_end.isoformat(),
        db,
        user_id=user.id
    )

    baseline = fetch_gsc_summary(
        effective_site_url,
        baseline_start.isoformat(),
        baseline_end.isoformat(),
        db,
        user_id=user.id
        )
    
  
    baseline_impr = baseline["impressions"]
    current_impr = current["impressions"]

    if baseline_impr > 0:
            impr_delta_pct = ((current_impr - baseline_impr) / baseline_impr) * 100
    else:
            impr_delta_pct = 0

    impr_severity = None
    if impr_delta_pct <= -40:
            impr_severity = 3
    elif impr_delta_pct <= -20:
            impr_severity = 2

        # ==================================================
        # IMPRESSION ALARM
        # ==================================================
    if impr_severity:
            impr_window_days = 7
            impr_alert_type = "IMPRESSION_DROP"
            impr_metric = "impressions"

            impr_dedupe_raw = f"{site_id}|{impr_alert_type}|{impr_metric}|{impr_window_days}|v1"
            impr_dedupe_key = hashlib.sha256(impr_dedupe_raw.encode()).hexdigest()

            existing_impr = db.query(Alert).filter(
                Alert.dedupe_key == impr_dedupe_key
            ).first()

            if not existing_impr:
                impr_alert = Alert(
                    id=str(uuid.uuid4()),
                    site_id=site_id,
                    severity=impr_severity,
                    alert_type=impr_alert_type,
                    metric=impr_metric,
                    current_value=current_impr,
                    baseline_value=baseline_impr,
                    delta_pct=round(impr_delta_pct, 2),
                    reason=f"Son 7 günde gösterimler %{abs(round(impr_delta_pct,2))} azaldı",
                    recommendation="Index kapsamı ve teknik erişim kontrol edilmeli",
                    dedupe_key=impr_dedupe_key,
                    window_days=impr_window_days,
                )
                db.add(impr_alert)
                db.commit()
    # -----------------------------
    # CTR ANALYZE
    # -----------------------------
    baseline_ctr = (
        baseline["clicks"] / baseline["impressions"]
        if baseline["impressions"] > 0
        else 0
    )

    current_ctr = (
        current["clicks"] / current["impressions"]
        if current["impressions"] > 0
        else 0
    )

    if baseline_ctr > 0:
        ctr_delta_pct = ((current_ctr - baseline_ctr) / baseline_ctr) * 100
    else:
        ctr_delta_pct = 0

    ctr_severity = None
    if ctr_delta_pct <= -25:
        ctr_severity = 3
    elif ctr_delta_pct <= -15:
        ctr_severity = 2
    # -----------------------------
    # CTR ALARM
    # -----------------------------
    if ctr_severity:
        ctr_window_days = 7
        ctr_alert_type = "CTR_DROP"
        ctr_metric = "ctr"

        ctr_dedupe_raw = f"{site_id}|{ctr_alert_type}|{ctr_metric}|{ctr_window_days}|v1"
        ctr_dedupe_key = hashlib.sha256(ctr_dedupe_raw.encode()).hexdigest()

        existing_ctr = db.query(Alert).filter(
            Alert.dedupe_key == ctr_dedupe_key
        ).first()

        if not existing_ctr:
            ctr_alert = Alert(
                id=str(uuid.uuid4()),
                site_id=site_id,
                severity=ctr_severity,
                alert_type=ctr_alert_type,
                metric=ctr_metric,
                current_value=round(current_ctr, 4),
                baseline_value=round(baseline_ctr, 4),
                delta_pct=round(ctr_delta_pct, 2),
                reason=f"CTR son 7 günde %{abs(round(ctr_delta_pct,2))} düştü",
                recommendation="Title & meta description CTR uyumu kontrol edilmeli",
                dedupe_key=ctr_dedupe_key,
                window_days=ctr_window_days,
            )
            db.add(ctr_alert)
            db.commit()
    # ==================================================
    # POSITION ANALYZE
    # ==================================================
    baseline_pos = baseline["position"]
    current_pos = current["position"]

    pos_delta = current_pos - baseline_pos  # + ise kötüleşme

    pos_severity = None
    if pos_delta >= 5:
        pos_severity = 3
    elif pos_delta >= 3:
        pos_severity = 2

    # ==================================================
    # POSITION ALARM
    # ==================================================
    if pos_severity:
        pos_window_days = 7
        pos_alert_type = "POSITION_DROP"
        pos_metric = "position"

        pos_dedupe_raw = f"{site_id}|{pos_alert_type}|{pos_metric}|{pos_window_days}|v1"
        pos_dedupe_key = hashlib.sha256(pos_dedupe_raw.encode()).hexdigest()

        existing_pos = db.query(Alert).filter(
            Alert.dedupe_key == pos_dedupe_key
        ).first()

        if not existing_pos:
            pos_alert = Alert(
                id=str(uuid.uuid4()),
                site_id=site_id,
                severity=pos_severity,
                alert_type=pos_alert_type,
                metric=pos_metric,
                current_value=round(current_pos, 2),
                baseline_value=round(baseline_pos, 2),
                delta_pct=round(pos_delta, 2),
                reason=f"Ortalama pozisyon {round(pos_delta,2)} sıra geriledi",
                recommendation="Ranking kaybı olan URL’ler, query bazlı düşüşler ve rakip hareketleri incelenmeli",
                dedupe_key=pos_dedupe_key,
                window_days=pos_window_days,
            )
            db.add(pos_alert)
            db.commit()


    if baseline["clicks"] == 0:
        return {
            "status": "skipped",
            "reason": "baseline_zero",
            "baseline_clicks": baseline["clicks"],
            "current_clicks": current["clicks"]
        }
    

    health = calculate_health(site_id, db)

    
    snapshot = HealthSnapshot(
    id=str(uuid.uuid4()),
    site_id=site_id,
    score=health["score"],
    status=health["status"],
    alerts_count=health["alerts"],
)


    db.add(snapshot)
    db.commit()


    # --- DELTA ---
    delta_pct = ((current["clicks"] - baseline["clicks"]) / baseline["clicks"]) * 100

    # --- CONFIDENCE ---
    if baseline["clicks"] >= 1000:
        confidence = "high"
    elif baseline["clicks"] >= 300:
        confidence = "medium"
    else:
        confidence = "low"

    # --- SEVERITY ---
    severity = None
    if delta_pct <= -30:
        severity = 3
    elif delta_pct <= -15:
        severity = 2

    # --- DÜŞÜŞ YOK ---
    if not severity:
        return {
            "status": "ok",
            "metric": "clicks",
            "delta_pct": round(delta_pct, 2),
            "confidence": confidence,
            "baseline_clicks": baseline["clicks"],
            "current_clicks": current["clicks"]
        }

    window_days = 7
    alert_type = "CLICK_DROP"
    metric = "clicks"

    dedupe_raw = f"{site_id}|{alert_type}|{metric}|{window_days}|v2"
    dedupe_key = hashlib.sha256(dedupe_raw.encode()).hexdigest()

    # --- DEDUPE ---
    existing = db.query(Alert).filter(Alert.dedupe_key == dedupe_key).first()
    if existing:
        return {
            "status": "alert",
            "alert_created": False,
            "alert_id": existing.id,
            "metric": metric,
            "severity": severity,
            "delta_pct": round(delta_pct, 2),
            "confidence": confidence,
            "note": "Alarm zaten mevcut (dedupe)"
        }

    # --- ALARM OLUŞTUR ---
    alert = Alert(
        id=str(uuid.uuid4()),
        site_id=site_id,
        severity=severity,
        alert_type=alert_type,
        metric=metric,
        current_value=current["clicks"],
        baseline_value=baseline["clicks"],
        delta_pct=round(delta_pct, 2),
        reason=f"Son 7 günde tıklamalar %{abs(round(delta_pct,2))} azaldı",
        recommendation="Index durumu, teknik değişiklikler ve son deploylar kontrol edilmeli",
        dedupe_key=dedupe_key,
        window_days=window_days,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    create_health_snapshot(site_id, db)

    return {
        "status": "alert",
        "alert_created": True,
        "alert_id": alert.id,
        "metric": metric,
        "severity": severity,
        "delta_pct": round(delta_pct, 2),
        "confidence": confidence
    }

 # --- HEALTH SNAPSHOT ---

def create_health_snapshot(site_id: str, db: Session):
    alerts = (
        db.query(Alert)
        .filter(Alert.site_id == site_id)
        .all()
    )

    score = 100
    for a in alerts:
        if a.severity == 3:
            score -= 25
        elif a.severity == 2:
            score -= 10
        else:
            score -= 3

    score = max(score, 0)

    if score >= 85:
        status = "Healthy"
    elif score >= 65:
        status = "Risk"
    else:
        status = "Critical"

    snapshot = HealthSnapshot(
        id=str(uuid.uuid4()),
        site_id=site_id,
        score=score,
        status=status,
        alerts_count=len(alerts)
    )

    db.add(snapshot)
    db.commit()


@app.get("/sites/{site_id}/health")
def site_health_score(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    alerts = (
        db.query(Alert)
        .filter(Alert.site_id == site_id)
        .all()
    )

    score = 100
    breakdown = []

    now = datetime.now(timezone.utc)

    metric_weights = {
        "clicks": 1.5,
        "impressions": 1.2,
        "position": 1.3,
        "ctr": 1.0,
    }

    severity_weights = {
        3: 1.0,
        2: 0.6,
        1: 0.3,
    }

    for a in alerts:
        # --- metric weight ---
        metric_weight = metric_weights.get(a.metric, 1.0)

        # --- severity weight ---
        severity_weight = severity_weights.get(a.severity, 0.3)

        # --- recency weight ---
        created_at = ensure_utc(a.created_at)
        days_old = (now - created_at).days

        if days_old <= 7:
            recency_weight = 1.0
        elif days_old <= 14:
            recency_weight = 0.7
        elif days_old <= 30:
            recency_weight = 0.4
        else:
            recency_weight = 0.2

        base_impact = 10

        impact = round(
            base_impact
            * metric_weight
            * severity_weight
            * recency_weight,
            2
        )

        score -= impact

        breakdown.append({
            "alert_type": a.alert_type,
            "metric": a.metric,
            "severity": a.severity,
            "impact": -impact,
            "days_old": days_old,
            "delta_pct": a.delta_pct,
            "created_at": created_at

        })

    score = max(round(score, 2), 0)

    if score >= 85:
        status = "Healthy"
    elif score >= 65:
        status = "Risk"
    else:
        status = "Critical"

    return {
        "site_id": site_id,
        "score": score,
        "status": status,
        "alerts": len(alerts),
        "breakdown": breakdown
    }

@app.get("/sites/{site_id}/health/timeline")
def health_timeline(
    site_id: str,
    days: int = Query(1, ge=1, le=365),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    since = datetime.now(timezone.utc) - timedelta(days=days)

    snapshots = (
        db.query(HealthSnapshot)
        .filter(
            HealthSnapshot.site_id == site_id,
            HealthSnapshot.created_at >= since
        )
        .order_by(HealthSnapshot.created_at.asc())
        .all()
    )

    return {
        "site_id": site_id,
        "days": days,
        "points": [
            {
                "date": s.created_at.isoformat(),
                "score": s.score,
                "status": s.status,
                "alerts": s.alerts_count
            }
            for s in snapshots
        ]
    }

@app.get("/sites/{site_id}/health/timeline/calc")
def health_timeline(
    site_id: str,
    days: int = Query(1, ge=1, le=365),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    today = datetime.now(timezone.utc)
    points = []

    for i in range(days):
        day = today - timedelta(days=i)
        score, status, alerts = calculate_health_at_date(site_id, db, day)

        points.append({
            "date": day.date().isoformat(),
            "score": score,
            "status": status,
            "alerts": alerts
        })

    points.reverse()

    return {
        "site_id": site_id,
        "days": days,
        "points": points
    }

@app.post("/sites/{site_id}/health/run")
def run_health_check(
    site_id: str,
    days: int = Query(1, enum=[1, 7, 14, 30]),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    site = get_site_owned(site_id, user, db)

    if not site.gsc_property_url:
        raise HTTPException(
            status_code=400, 
            detail="Site'in GSC property URL'si tanımlı değil"
        )

    # 📅 Tarih aralığını hesapla
    end_date = (date.today() - timedelta(days=1)).isoformat()  # Dün
    start_date = (date.today() - timedelta(days=days)).isoformat()  # X gün önce

    try:
        # 🌐 GERÇEK GSC VERİSİNİ ÇEK
        gsc_data = fetch_gsc_summary(
            site_url=site.gsc_property_url,
            start_date=start_date,
            end_date=end_date,
            db=db,
            user_id=user.id
        )
        
        clicks = gsc_data.get("clicks", 0)
        impressions = gsc_data.get("impressions", 0)
        
        # CTR hesapla (0 bölme hatasını önle)
        if impressions > 0:
            ctr = round(clicks / impressions, 3)
        else:
            ctr = 0.0
            
    except Exception as e:
        # GSC verisi çekilemezse hata ver
        raise HTTPException(
            status_code=500,
            detail=f"GSC verisi alınamadı: {str(e)}"
        )

    # 🧠 Confidence (basit ama mantıklı)
    # İmpression sayısı yüksekse güven artar
    confidence = round(min(1.0, impressions / 1000), 2)

    # 🎯 Score hesaplama
    # CTR'nin ağırlığı %60, confidence %40
    score = round(
        (ctr * 100) * 0.6 +
        (confidence * 100) * 0.4,
        2
    )

    # 📊 Durum belirleme
    if score >= 80:
        status = "Healthy"
    elif score >= 60:
        status = "Risk"
    else:
        status = "Critical"

    # 💾 Snapshot kaydet
    snapshot = HealthSnapshot(
        site_id=site_id,
        created_at=datetime.now(timezone.utc),
        score=score,
        status=status,
        clicks=clicks,
        impressions=impressions,
        ctr=ctr,
        confidence=confidence,
        alerts_count=0  # Aşağıda güncellenecek
    )

    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)

    # 🚨 ALERT TESPİTİ (snapshot kaydedildikten sonra)
    detected_alerts = detect_anomalies(site_id, db)
    new_alerts_count = save_alerts_if_new(detected_alerts, db)
    
    # Alert sayısını snapshot'a güncelle
    snapshot.alerts_count = new_alerts_count
    db.commit()

    return {
        "message": "Health snapshot oluşturuldu (GERÇEK GSC VERİSİ)",
        "site_id": site_id,
        "days": days,
        "date_range": f"{start_date} → {end_date}",
        "score": score,
        "status": status,
        "clicks": clicks,
        "impressions": impressions,
        "ctr": ctr,
        "alerts_detected": new_alerts_count
    }
@app.get("/debug/gsc-test/{site_id}")
def debug_gsc(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    site = get_site_owned(site_id, user, db)
    token = (
        db.query(UserOAuthToken)
        .filter(
            UserOAuthToken.user_id == user.id,
            UserOAuthToken.provider == "google"
        )
        .first()
    )

    if not site or not token:
        return {"error": "Site veya token yok"}

    access_token = get_access_token_from_refresh(
        token.refresh_token
    )

    property_url = site.gsc_property_url

    if not property_url:
        raise HTTPException(
            status_code=400,
            detail="Bu site için GSC property URL kayıtlı değil"
        )

    # Test GSC fetch
    data = test_gsc_fetch(
        access_token=access_token,
        property_url=property_url
    )

    return {
        "site_domain": site.domain,
        "gsc_property": property_url,
        "gsc_data": data
    }

@app.get("/debug/gsc/{site_id}")
def debug_gsc_short(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Kısa URL versiyonu - /debug/gsc-test ile aynı"""
    return debug_gsc(site_id, user, db)


# ========================================
# 📊 ANALYTICS & ALERTS ENDPOINTS
# ========================================

@app.get("/sites/{site_id}/trend")
def get_trend_analysis(
    site_id: str,
    days: int = Query(1, enum=[1, 7, 14, 30]),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Site'in trend analizini döndürür.
    
    Query params:
    - days: Analiz periyodu (1, 7, 14 veya 30 gun)
    
    Returns:
    - trend: improving/declining/stable
    - change_pct: Yüzdelik değişim
    - İlk ve son score değerleri
    """
    site = get_site_owned(site_id, user, db)
    
    trend_data = analyze_trend(site_id, days, db)
    
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "analysis_period_days": days,
        **trend_data
    }


@app.get("/sites/{site_id}/alerts")
def get_site_alerts(
    site_id: str,
    days: int = Query(7),
    severity: Optional[int] = Query(None, ge=1, le=3),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Site için oluşturulmuş alert'leri döndürür.
    
    Query params:
    - days: Son kaç gün (default: 7)
    - severity: 1=Info, 2=Warning, 3=Critical (optional)
    
    Returns:
    - Alert listesi
    """
    site = get_site_owned(site_id, user, db)
    
    since = datetime.now(timezone.utc) - timedelta(days=days)
    
    query = db.query(Alert).filter(
        Alert.site_id == site_id,
        Alert.created_at >= since
    )
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    alerts = query.order_by(Alert.created_at.desc()).all()
    
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period_days": days,
        "total_alerts": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "type": a.alert_type,
                "severity": a.severity,
                "severity_label": {1: "Info", 2: "Warning", 3: "Critical"}[a.severity],
                "confidence": a.confidence,
                "metric": a.metric,
                "current_value": a.current_value,
                "baseline_value": a.baseline_value,
                "change_pct": a.delta_pct,
                "reason": a.reason,
                "recommendation": a.recommendation,
                "created_at": a.created_at.isoformat()
            }
            for a in alerts
        ]
    }


@app.get("/sites/{site_id}/alerts/smart")
def smart_alerts_endpoint(
    site_id: str,
    days: int = Query(14, ge=1, le=90),
    top: int = Query(10, ge=3, le=30),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    site = get_site_owned(site_id, user, db)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(Alert)
        .filter(Alert.site_id == site_id, Alert.created_at >= since)
        .order_by(Alert.created_at.desc())
        .all()
    )
    if not rows:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "days": days,
            "summary": {"total": 0, "critical": 0, "warning": 0, "info": 0},
            "top_cause_clusters": [],
            "insights": [],
        }

    bucket = defaultdict(lambda: {"count": 0, "impact": 0.0})
    insights = []
    for a in rows:
        impact_score = round((float(abs(a.delta_pct or 0)) * max(1, int(a.severity or 1))), 2)
        reco = _smart_recommendation_for_alert(a.metric or "", a.reason or "", float(a.delta_pct or 0))
        key = f"{(a.metric or '-').lower()}::{reco['root_cause']}"
        bucket[key]["count"] += 1
        bucket[key]["impact"] += impact_score
        insights.append({
            "id": a.id,
            "severity": int(a.severity or 1),
            "severity_label": {1: "Info", 2: "Warning", 3: "Critical"}.get(int(a.severity or 1), "Info"),
            "metric": a.metric or "-",
            "change_pct": round(float(a.delta_pct or 0), 2),
            "reason": a.reason or "-",
            "root_cause": reco["root_cause"],
            "action": reco["action"],
            "action_window": reco["window"],
            "impact_score": impact_score,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    insights.sort(key=lambda x: (-x["severity"], -x["impact_score"]))
    top_causes = sorted(
        [
            {"cluster": k, "count": v["count"], "impact_score": round(v["impact"], 2)}
            for k, v in bucket.items()
        ],
        key=lambda x: (-x["impact_score"], -x["count"])
    )[:5]

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "days": days,
        "summary": {
            "total": len(rows),
            "critical": len([x for x in rows if x.severity == 3]),
            "warning": len([x for x in rows if x.severity == 2]),
            "info": len([x for x in rows if x.severity == 1]),
        },
        "top_cause_clusters": top_causes,
        "insights": insights[:top],
    }


@app.get("/sites/{site_id}/growth/what-changed")
def growth_what_changed_endpoint(
    site_id: str,
    days: int = Query(7, ge=3, le=60),
    top_pages: int = Query(8, ge=3, le=25),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    current_end = datetime.now(timezone.utc).date() - timedelta(days=1)
    current_start = current_end - timedelta(days=days - 1)
    baseline_end = current_start - timedelta(days=1)
    baseline_start = baseline_end - timedelta(days=days - 1)

    current_summary = fetch_gsc_summary(
        site_url=site.gsc_property_url,
        start_date=current_start.isoformat(),
        end_date=current_end.isoformat(),
        db=db,
        user_id=user.id,
    )
    baseline_summary = fetch_gsc_summary(
        site_url=site.gsc_property_url,
        start_date=baseline_start.isoformat(),
        end_date=baseline_end.isoformat(),
        db=db,
        user_id=user.id,
    )

    current_page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=current_start.isoformat(),
        end_date=current_end.isoformat(),
        dimensions=["page"],
        row_limit=2500,
        db=db,
        user_id=user.id,
    )
    baseline_page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=baseline_start.isoformat(),
        end_date=baseline_end.isoformat(),
        dimensions=["page"],
        row_limit=2500,
        db=db,
        user_id=user.id,
    )

    current_map = _build_page_map(current_page_rows)
    baseline_map = _build_page_map(baseline_page_rows)
    pages = sorted(set(current_map.keys()) | set(baseline_map.keys()))

    page_changes = []
    for page in pages:
        curr = current_map.get(page, {})
        prev = baseline_map.get(page, {})
        c_clicks = float(curr.get("clicks", 0) or 0)
        c_impr = float(curr.get("impressions", 0) or 0)
        c_ctr = float(curr.get("ctr", 0) or 0)
        c_pos = float(curr.get("position", 0) or 0)
        p_clicks = float(prev.get("clicks", 0) or 0)
        p_impr = float(prev.get("impressions", 0) or 0)
        p_ctr = float(prev.get("ctr", 0) or 0)
        p_pos = float(prev.get("position", 0) or 0)
        if p_impr < 20 and c_impr < 20:
            continue

        click_diff = round(c_clicks - p_clicks, 2)
        click_delta_pct = _pct_delta(c_clicks, p_clicks) if p_clicks > 0 else (100.0 if c_clicks > 0 else 0.0)
        impr_delta_pct = _pct_delta(c_impr, p_impr) if p_impr > 0 else (100.0 if c_impr > 0 else 0.0)
        ctr_delta_pct = _pct_delta(c_ctr, p_ctr) if p_ctr > 0 else (100.0 if c_ctr > 0 else 0.0)
        pos_delta = round(c_pos - p_pos, 2) if p_pos > 0 else round(c_pos, 2)

        page_changes.append({
            "page": page,
            "click_diff": click_diff,
            "click_delta_pct": round(click_delta_pct, 2),
            "impression_delta_pct": round(impr_delta_pct, 2),
            "ctr_delta_pct": round(ctr_delta_pct, 2),
            "position_delta": pos_delta,
            "likely_reason": _classify_page_drop_reason(click_delta_pct, impr_delta_pct, ctr_delta_pct, pos_delta),
            "current": {
                "clicks": int(round(c_clicks)),
                "impressions": int(round(c_impr)),
                "ctr_pct": round(c_ctr * 100, 2),
                "position": round(c_pos, 2),
            },
            "baseline": {
                "clicks": int(round(p_clicks)),
                "impressions": int(round(p_impr)),
                "ctr_pct": round(p_ctr * 100, 2),
                "position": round(p_pos, 2),
            },
        })

    dropped_pages = sorted(
        [x for x in page_changes if x["click_diff"] < 0],
        key=lambda x: x["click_diff"]
    )
    recovering_pages = sorted(
        [x for x in page_changes if x["click_diff"] > 0],
        key=lambda x: x["click_diff"],
        reverse=True
    )

    curr_clicks = float(current_summary.get("clicks", 0) or 0)
    prev_clicks = float(baseline_summary.get("clicks", 0) or 0)
    curr_impr = float(current_summary.get("impressions", 0) or 0)
    prev_impr = float(baseline_summary.get("impressions", 0) or 0)
    curr_ctr = float(current_summary.get("ctr", 0) or 0)
    prev_ctr = float(baseline_summary.get("ctr", 0) or 0)
    curr_pos = float(current_summary.get("position", 0) or 0)
    prev_pos = float(baseline_summary.get("position", 0) or 0)

    delta_clicks = _pct_delta(curr_clicks, prev_clicks) if prev_clicks > 0 else 0.0
    delta_impr = _pct_delta(curr_impr, prev_impr) if prev_impr > 0 else 0.0
    delta_ctr = _pct_delta(curr_ctr, prev_ctr) if prev_ctr > 0 else 0.0
    delta_pos = round(curr_pos - prev_pos, 2)

    win_start_dt = datetime.combine(current_start, time(0, 0, 0), tzinfo=timezone.utc)
    win_end_dt = datetime.combine(current_end, time(23, 59, 59), tzinfo=timezone.utc)

    alerts = (
        db.query(Alert)
        .filter(Alert.site_id == site_id, Alert.created_at >= win_start_dt, Alert.created_at <= win_end_dt)
        .all()
    )
    changes = (
        db.query(SeoChangeLog)
        .filter(SeoChangeLog.site_id == site_id, SeoChangeLog.changed_at >= win_start_dt, SeoChangeLog.changed_at <= win_end_dt)
        .order_by(SeoChangeLog.changed_at.desc())
        .limit(15)
        .all()
    )

    reason_breakdown = []
    if delta_impr <= -10 and delta_pos >= 0.8:
        reason_breakdown.append({
            "title": "Gorunurluk kaybi",
            "detail": "Impression dususu ve pozisyon gerilemesi birlikte goruluyor.",
            "impact": "Yuksek"
        })
    if delta_ctr <= -10:
        reason_breakdown.append({
            "title": "CTR dususu",
            "detail": "Arama sonucunda tiklanma orani azalmis.",
            "impact": "Orta"
        })
    if delta_pos >= 1.2:
        reason_breakdown.append({
            "title": "Pozisyon kaybi",
            "detail": "Ortalama siralama gerilemis.",
            "impact": "Yuksek"
        })
    if changes:
        type_counter = Counter([(c.change_type or "other").lower() for c in changes])
        top_change_type = type_counter.most_common(1)[0][0]
        reason_breakdown.append({
            "title": "Son teknik/icerik degisiklikleri",
            "detail": f"Son {days} gunde {len(changes)} degisiklik kaydi var. En sik tur: {top_change_type}.",
            "impact": "Orta"
        })
    if alerts:
        critical_count = len([a for a in alerts if int(a.severity or 1) == 3])
        if critical_count > 0:
            reason_breakdown.append({
                "title": "Kritik alarm baskisi",
                "detail": f"Ayni donemde {critical_count} kritik uyari olustu.",
                "impact": "Yuksek"
            })

    if not reason_breakdown:
        reason_breakdown.append({
            "title": "Stabil gorunum",
            "detail": "Net bir negatif sinyal yok, degisimler normal dalga araliginda.",
            "impact": "Dusuk"
        })

    cause_counter = Counter([x["likely_reason"] for x in dropped_pages[:30]])
    top_causes = [
        {"reason": reason, "count": count}
        for reason, count in cause_counter.most_common(4)
    ]

    actions = []
    if delta_ctr <= -8:
        actions.append("Cok gorunen sayfalarda baslik ve aciklama metnini daha acik hale getirip iki farkli versiyon deneyin.")
    if delta_pos >= 0.8:
        actions.append("Geri dusen sayfalari guncelleyin ve sitedeki ilgili sayfalardan bu sayfalara baglanti verin.")
    if delta_impr <= -10:
        actions.append("Eksik kalan sorgular icin yeni bolumler ve yeni icerik fikirleri ekleyin.")
    if alerts:
        actions.append("Kritik uyarilari ayni gun kontrol edin ve once en buyuk kaybi olan sayfalari duzeltin.")
    if changes:
        actions.append("Son yaptiginiz degisiklikleri gozden gecirin, olumsuz etki verenleri iyilestirin.")
    if not actions:
        actions.append("Performans stabil: mevcut plani koruyup haftalik izlemeyi surdurun.")

    direction = "stable"
    if delta_clicks <= -7:
        direction = "down"
    elif delta_clicks >= 7:
        direction = "up"

    if direction == "down":
        headline = f"Son {days} gunde trafik dususu var. En guclu neden: {(top_causes[0]['reason'] if top_causes else 'karma etki')}."
    elif direction == "up":
        headline = f"Son {days} gunde trafik artisi var. Bu trendi korumak icin kazandirilan sayfalari guclendirin."
    else:
        headline = f"Son {days} gunde performans yatay seyrediyor. Hedef sayfalarda optimizasyon firsati suruyor."

    change_type_counter = Counter([(c.change_type or "other").lower() for c in changes])
    change_type_items = [
        {"type": k, "count": v}
        for k, v in change_type_counter.most_common(6)
    ]

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "days": days,
            "current": {"start": current_start.isoformat(), "end": current_end.isoformat()},
            "baseline": {"start": baseline_start.isoformat(), "end": baseline_end.isoformat()},
        },
        "headline": headline,
        "summary": {
            "direction": direction,
            "total_dropped_pages": len(dropped_pages),
            "total_recovering_pages": len(recovering_pages),
            "top_driver": (top_causes[0]["reason"] if top_causes else "-"),
        },
        "metrics": {
            "current": {
                "clicks": int(round(curr_clicks)),
                "impressions": int(round(curr_impr)),
                "ctr_pct": round(curr_ctr * 100, 2),
                "position": round(curr_pos, 2),
            },
            "baseline": {
                "clicks": int(round(prev_clicks)),
                "impressions": int(round(prev_impr)),
                "ctr_pct": round(prev_ctr * 100, 2),
                "position": round(prev_pos, 2),
            },
            "delta_pct": {
                "clicks": round(delta_clicks, 2),
                "impressions": round(delta_impr, 2),
                "ctr": round(delta_ctr, 2),
                "position": delta_pos,
            },
        },
        "reason_breakdown": reason_breakdown[:5],
        "top_causes": top_causes,
        "top_affected_pages": dropped_pages[:top_pages],
        "top_recovering_pages": recovering_pages[:max(3, top_pages // 2)],
        "alerts_window": {
            "total": len(alerts),
            "critical": len([a for a in alerts if int(a.severity or 1) == 3]),
            "warning": len([a for a in alerts if int(a.severity or 1) == 2]),
            "info": len([a for a in alerts if int(a.severity or 1) == 1]),
        },
        "change_log_summary": {
            "total": len(changes),
            "types": change_type_items,
            "items": [
                {
                    "change_type": c.change_type,
                    "title": c.title,
                    "changed_at": c.changed_at.isoformat() if c.changed_at else None,
                }
                for c in changes[:10]
            ],
        },
        "actions": actions[:5],
    }


@app.get("/sites/{site_id}/growth/anomaly-cause-score")
def growth_anomaly_cause_score_endpoint(
    site_id: str,
    days: int = Query(14, ge=7, le=90),
    top_pages: int = Query(10, ge=3, le=30),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    current_end = datetime.now(timezone.utc).date() - timedelta(days=1)
    current_start = current_end - timedelta(days=days - 1)
    baseline_end = current_start - timedelta(days=1)
    baseline_start = baseline_end - timedelta(days=days - 1)

    current_summary = fetch_gsc_summary(
        site_url=site.gsc_property_url,
        start_date=current_start.isoformat(),
        end_date=current_end.isoformat(),
        db=db,
        user_id=user.id,
    )
    baseline_summary = fetch_gsc_summary(
        site_url=site.gsc_property_url,
        start_date=baseline_start.isoformat(),
        end_date=baseline_end.isoformat(),
        db=db,
        user_id=user.id,
    )

    current_page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=current_start.isoformat(),
        end_date=current_end.isoformat(),
        dimensions=["page"],
        row_limit=2500,
        db=db,
        user_id=user.id,
    )
    baseline_page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=baseline_start.isoformat(),
        end_date=baseline_end.isoformat(),
        dimensions=["page"],
        row_limit=2500,
        db=db,
        user_id=user.id,
    )

    current_map = _build_page_map(current_page_rows)
    baseline_map = _build_page_map(baseline_page_rows)
    pages = sorted(set(current_map.keys()) | set(baseline_map.keys()))

    page_signals = []
    for page in pages:
        curr = current_map.get(page, {})
        prev = baseline_map.get(page, {})
        c_clicks = float(curr.get("clicks", 0) or 0)
        c_impr = float(curr.get("impressions", 0) or 0)
        c_ctr = float(curr.get("ctr", 0) or 0)
        c_pos = float(curr.get("position", 0) or 0)
        p_clicks = float(prev.get("clicks", 0) or 0)
        p_impr = float(prev.get("impressions", 0) or 0)
        p_ctr = float(prev.get("ctr", 0) or 0)
        p_pos = float(prev.get("position", 0) or 0)

        if p_impr < 20 and c_impr < 20:
            continue

        click_diff = round(c_clicks - p_clicks, 2)
        if click_diff >= 0:
            continue

        click_delta_pct = _pct_delta(c_clicks, p_clicks) if p_clicks > 0 else (-100.0 if c_clicks <= 0 else 0.0)
        impr_delta_pct = _pct_delta(c_impr, p_impr) if p_impr > 0 else (100.0 if c_impr > 0 else 0.0)
        ctr_delta_pct = _pct_delta(c_ctr, p_ctr) if p_ctr > 0 else (100.0 if c_ctr > 0 else 0.0)
        pos_delta = round(c_pos - p_pos, 2) if p_pos > 0 else round(c_pos, 2)

        page_signals.append({
            "page": page,
            "click_diff": click_diff,
            "click_delta_pct": round(click_delta_pct, 2),
            "impression_delta_pct": round(impr_delta_pct, 2),
            "ctr_delta_pct": round(ctr_delta_pct, 2),
            "position_delta": pos_delta,
            "primary_signal": _classify_page_drop_reason(click_delta_pct, impr_delta_pct, ctr_delta_pct, pos_delta),
            "current": {
                "clicks": int(round(c_clicks)),
                "impressions": int(round(c_impr)),
                "ctr_pct": round(c_ctr * 100, 2),
                "position": round(c_pos, 2),
            },
            "baseline": {
                "clicks": int(round(p_clicks)),
                "impressions": int(round(p_impr)),
                "ctr_pct": round(p_ctr * 100, 2),
                "position": round(p_pos, 2),
            },
        })

    dropped_pages = sorted(page_signals, key=lambda x: x["click_diff"])

    cause_meta = {
        "technical_changes": {
            "label": "Teknik Degisiklik Etkisi",
            "explanation": "Sitede yapilan son degisiklikler gorunurlugu olumsuz etkilemis olabilir.",
            "action": "Son yapilan degisiklikleri tek tek kontrol edin. Sorunun basladigi tarihteki degisiklikleri geri alip tekrar deneyin.",
        },
        "ctr_drop": {
            "label": "CTR Dususu",
            "explanation": "Kullanicilar sizi goruyor ama daha az tikliyor.",
            "action": "Baslik ve aciklama metnini daha net ve cazip hale getirin. 2 farkli metin deneyip hangisi daha iyi tiklaniyor bakin.",
        },
        "ranking_loss": {
            "label": "Pozisyon Kaybi",
            "explanation": "Sayfalarin arama sonuclarindaki yeri gerilemis.",
            "action": "Dusen sayfalari guncelleyin, daha anlasilir hale getirin ve siteden bu sayfalara daha fazla baglanti verin.",
        },
        "demand_shift": {
            "label": "Talep/Sezonsallik Etkisi",
            "explanation": "Bu donemde aranma ilgisi azalmis olabilir.",
            "action": "Benzer ama daha cok aranan yeni konu basliklari ekleyin ve mevcut icerikleri mevsime/doneme uygun guncelleyin.",
        },
        "query_coverage_loss": {
            "label": "Sorgu Kapsami Kaybi",
            "explanation": "Daha once gorundugunuz bazi aramalarda artik daha az gorunuyorsunuz.",
            "action": "Eksik kalan sorulari sayfaya ekleyin. Kullanicinin merak ettigi noktalar icin yeni bolumler ve SSS (sik sorulan sorular) olusturun.",
        },
    }
    cause_scores = {
        k: {"score": 0.0, "evidence": []}
        for k in cause_meta.keys()
    }

    def add_cause(cause_key: str, score: float, evidence: Optional[dict] = None):
        if cause_key not in cause_scores:
            return
        cause_scores[cause_key]["score"] += max(0.0, float(score or 0.0))
        if evidence and len(cause_scores[cause_key]["evidence"]) < 10:
            cause_scores[cause_key]["evidence"].append(evidence)

    curr_clicks = float(current_summary.get("clicks", 0) or 0)
    prev_clicks = float(baseline_summary.get("clicks", 0) or 0)
    curr_impr = float(current_summary.get("impressions", 0) or 0)
    prev_impr = float(baseline_summary.get("impressions", 0) or 0)
    curr_ctr = float(current_summary.get("ctr", 0) or 0)
    prev_ctr = float(baseline_summary.get("ctr", 0) or 0)
    curr_pos = float(current_summary.get("position", 0) or 0)
    prev_pos = float(baseline_summary.get("position", 0) or 0)

    delta_clicks = _pct_delta(curr_clicks, prev_clicks) if prev_clicks > 0 else 0.0
    delta_impr = _pct_delta(curr_impr, prev_impr) if prev_impr > 0 else 0.0
    delta_ctr = _pct_delta(curr_ctr, prev_ctr) if prev_ctr > 0 else 0.0
    delta_pos = round(curr_pos - prev_pos, 2)

    if delta_pos >= 0.8 and delta_impr <= -5:
        add_cause("ranking_loss", 18 + (delta_pos * 6), {
            "type": "summary",
            "detail": f"Ortalama pozisyon farki {delta_pos} ve impression degisimi %{round(delta_impr, 2)}",
        })
    if delta_ctr <= -8:
        add_cause("ctr_drop", 16 + (abs(delta_ctr) * 0.8), {
            "type": "summary",
            "detail": f"CTR degisimi %{round(delta_ctr, 2)}",
        })
    if delta_impr <= -12 and abs(delta_pos) < 1.1:
        add_cause("demand_shift", 14 + (abs(delta_impr) * 0.6), {
            "type": "summary",
            "detail": f"Impression degisimi %{round(delta_impr, 2)} (pozisyon etkisi sinirli)",
        })
    if delta_impr <= -10 and delta_ctr > -6 and delta_pos < 1.0:
        add_cause("query_coverage_loss", 10 + (abs(delta_impr) * 0.5), {
            "type": "summary",
            "detail": "Impression dususu var, CTR/pozisyon etkisi sinirli.",
        })

    total_negative_clicks = 0.0
    for p in dropped_pages[:120]:
        impact = max(1.0, abs(float(p["click_diff"] or 0)))
        total_negative_clicks += impact
        cdp = float(p["click_delta_pct"] or 0)
        idp = float(p["impression_delta_pct"] or 0)
        tdp = float(p["ctr_delta_pct"] or 0)
        pd = float(p["position_delta"] or 0)
        page_path = _url_to_path(p.get("page") or "/")

        if pd >= 1.0 and idp <= -5:
            add_cause("ranking_loss", impact * (0.7 + min(pd, 6.0) / 3.5), {
                "type": "page",
                "page": page_path,
                "detail": f"Pos +{round(pd, 2)}, click %{round(cdp, 2)}",
            })
        if tdp <= -8 and abs(pd) < 1.6:
            add_cause("ctr_drop", impact * (0.6 + min(abs(tdp), 45.0) / 26.0), {
                "type": "page",
                "page": page_path,
                "detail": f"CTR %{round(tdp, 2)}, click %{round(cdp, 2)}",
            })
        if idp <= -15 and abs(pd) < 1.1:
            add_cause("demand_shift", impact * (0.6 + min(abs(idp), 60.0) / 35.0), {
                "type": "page",
                "page": page_path,
                "detail": f"Impression %{round(idp, 2)}",
            })
        if idp <= -10 and pd < 1.0 and tdp > -8:
            add_cause("query_coverage_loss", impact * (0.45 + min(abs(idp), 50.0) / 40.0), {
                "type": "page",
                "page": page_path,
                "detail": f"Impression %{round(idp, 2)} / CTR %{round(tdp, 2)}",
            })
        if pd >= 2.0 and cdp <= -30:
            add_cause("technical_changes", impact * 0.35, {
                "type": "page",
                "page": page_path,
                "detail": "Sert dusus: teknik degisiklik etkisi kontrolu gerekli.",
            })

    win_start_dt = datetime.combine(current_start, time(0, 0, 0), tzinfo=timezone.utc)
    win_end_dt = datetime.combine(current_end, time(23, 59, 59), tzinfo=timezone.utc)
    alerts = (
        db.query(Alert)
        .filter(Alert.site_id == site_id, Alert.created_at >= win_start_dt, Alert.created_at <= win_end_dt)
        .all()
    )
    changes = (
        db.query(SeoChangeLog)
        .filter(SeoChangeLog.site_id == site_id, SeoChangeLog.changed_at >= win_start_dt, SeoChangeLog.changed_at <= win_end_dt)
        .order_by(SeoChangeLog.changed_at.desc())
        .limit(40)
        .all()
    )

    for a in alerts:
        sev = max(1, int(a.severity or 1))
        metric = (a.metric or "").strip().lower()
        reason_norm = _normalize_text(a.reason or "")
        base_score = 4.5 * sev
        ev = {
            "type": "alert",
            "detail": f"{a.alert_type or '-'} / {metric or '-'} / delta %{round(float(a.delta_pct or 0), 2)}",
        }
        if "ctr" in metric:
            add_cause("ctr_drop", base_score, ev)
        if "impression" in metric:
            add_cause("query_coverage_loss", base_score, ev)
        if "click" in metric and ("pozisyon" in reason_norm or "siralama" in reason_norm):
            add_cause("ranking_loss", base_score, ev)
        if (
            "score" in metric
            or "status" in metric
            or "page" in metric
            or "anomali" in reason_norm
            or "teknik" in reason_norm
        ):
            add_cause("technical_changes", base_score + 1.5, ev)

    technical_type_terms = {
        "deploy", "release", "redirect", "server", "infra", "migration",
        "canonical", "robots", "sitemap", "schema", "tag", "tracking", "code",
    }
    snippet_terms = {"title", "meta", "snippet", "ctr", "description"}
    content_terms = {"content", "blog", "landing", "page", "cluster", "copy", "h1", "h2", "faq"}
    for c in changes:
        ctype = _normalize_text(c.change_type or "")
        title_norm = _normalize_text(c.title or "")
        txt = f"{ctype} {title_norm}".strip()
        ev = {
            "type": "change_log",
            "detail": f"{(c.change_type or '-')} | {(c.title or '-')}",
        }
        if any(t in txt for t in technical_type_terms):
            add_cause("technical_changes", 8.0, ev)
        elif any(t in txt for t in snippet_terms):
            add_cause("ctr_drop", 5.5, ev)
        elif any(t in txt for t in content_terms):
            add_cause("query_coverage_loss", 4.5, ev)
        else:
            add_cause("technical_changes", 2.5, ev)

    for p in dropped_pages[:top_pages]:
        page_url = p.get("page") or ""
        if not page_url:
            continue
        try:
            losses = _page_query_losses(
                site_url=site.gsc_property_url,
                page_url=page_url,
                current_start=current_start.isoformat(),
                current_end=current_end.isoformat(),
                prev_start=baseline_start.isoformat(),
                prev_end=baseline_end.isoformat(),
                user_id=user.id,
                db=db,
            )
        except Exception:
            losses = []
        if not losses:
            continue
        imp_loss = sum(abs(float(x.get("impression_delta", 0) or 0)) for x in losses[:6])
        q_terms = ", ".join([x.get("query", "-") for x in losses[:3]])
        add_cause("query_coverage_loss", 6 + (imp_loss / 40.0), {
            "type": "query_loss",
            "page": _url_to_path(page_url),
            "detail": f"Kayip query: {q_terms}",
        })

    scored = []
    total_score = sum(float(v["score"] or 0) for v in cause_scores.values())
    if total_score <= 0:
        add_cause("technical_changes", 1.0, {"type": "fallback", "detail": "Skor sinyali olusmadi, teknik kontrol onerilir."})
        total_score = 1.0

    for cause_key, payload in cause_scores.items():
        raw_score = round(float(payload["score"] or 0), 2)
        if raw_score <= 0:
            continue
        share = round((raw_score / total_score) * 100, 2)
        ev_count = len(payload["evidence"])
        confidence = "Low"
        if share >= 45 or (share >= 35 and ev_count >= 3):
            confidence = "High"
        elif share >= 22 or ev_count >= 3:
            confidence = "Medium"

        meta = cause_meta[cause_key]
        scored.append({
            "cause": cause_key,
            "label": meta["label"],
            "score": raw_score,
            "share_pct": share,
            "confidence": confidence,
            "explanation": meta["explanation"],
            "evidence_count": ev_count,
            "evidence": payload["evidence"][:5],
            "recommended_action": meta["action"],
        })

    scored = sorted(scored, key=lambda x: x["score"], reverse=True)
    dominant = scored[0] if scored else {
        "label": "Karma etki",
        "share_pct": 0.0,
        "confidence": "Low",
    }

    actions = []
    for row in scored[:3]:
        if row["share_pct"] >= 12:
            actions.append(row["recommended_action"])
    if not actions:
        actions.append("Net bir ana neden cikmadi. Once en cok trafik kaybeden sayfalara odaklanip kucuk ama hizli iyilestirmeler yapin.")

    direction = "stable"
    if delta_clicks <= -7:
        direction = "down"
    elif delta_clicks >= 7:
        direction = "up"

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "days": days,
            "current": {"start": current_start.isoformat(), "end": current_end.isoformat()},
            "baseline": {"start": baseline_start.isoformat(), "end": baseline_end.isoformat()},
        },
        "summary": {
            "direction": direction,
            "dominant_cause": dominant.get("label", "-"),
            "dominant_cause_share_pct": dominant.get("share_pct", 0.0),
            "dominant_confidence": dominant.get("confidence", "Low"),
            "dropped_pages": len(dropped_pages),
            "inspected_pages": len(page_signals),
            "alerts_in_window": len(alerts),
            "changes_in_window": len(changes),
            "total_negative_clicks": round(total_negative_clicks, 2),
            "delta_pct": {
                "clicks": round(delta_clicks, 2),
                "impressions": round(delta_impr, 2),
                "ctr": round(delta_ctr, 2),
                "position": delta_pos,
            },
        },
        "cause_scores": scored,
        "top_page_signals": dropped_pages[:top_pages],
        "actions": actions[:5],
    }


@app.get("/sites/{site_id}/growth/recovery-plan")
def growth_recovery_plan_endpoint(
    site_id: str,
    days: int = Query(14, ge=7, le=90),
    top_pages: int = Query(8, ge=3, le=20),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    10/10 operasyon akisi:
    - What Changed + Anomaly Cause Score sinyallerini birlestirir
    - Uygulanabilir, onceliklendirilmis bir kurtarma plani uretir
    """
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    what = growth_what_changed_endpoint(
        site_id=site_id,
        days=days,
        top_pages=max(5, top_pages),
        user=user,
        db=db,
    )
    anomaly = growth_anomaly_cause_score_endpoint(
        site_id=site_id,
        days=days,
        top_pages=max(5, top_pages),
        user=user,
        db=db,
    )

    delta = ((what or {}).get("metrics") or {}).get("delta_pct") or {}
    top_causes = (anomaly or {}).get("cause_scores") or []
    top_pages_rows = (what or {}).get("top_affected_pages") or []

    tasks = []
    for idx, c in enumerate(top_causes[:3], start=1):
        share = float(c.get("share_pct") or 0)
        score = float(c.get("score") or 0)
        confidence = c.get("confidence") or "Low"
        phase = "24 saat"
        if idx == 2:
            phase = "7 gun"
        elif idx >= 3:
            phase = "30 gun"

        tasks.append({
            "priority": "P1" if idx == 1 else ("P2" if idx == 2 else "P3"),
            "phase": phase,
            "title": f"{c.get('label', 'Neden')} odakli aksiyon",
            "why": c.get("explanation", "-"),
            "action": c.get("recommended_action", "-"),
            "impact_score": round(score, 2),
            "confidence": confidence,
            "owner": "SEO Team",
            "kpi": "Clicks / Impression / CTR / Position",
            "success_metric": f"Neden payini % {max(5.0, round(share * 0.65, 1))} altina dusur",
        })

    for p in top_pages_rows[:max(2, top_pages // 2)]:
        page = p.get("page") or "-"
        tasks.append({
            "priority": "P2",
            "phase": "7 gun",
            "title": f"URL revizyonu: {_url_to_path(page)}",
            "why": p.get("likely_reason", "Dusus sinyali"),
            "action": "Bu sayfayi daha anlasilir hale getirin: ana basligi netlestirin, eksik sorulari ekleyin ve ilgili sayfalardan bu sayfaya baglanti verin.",
            "impact_score": round(abs(float(p.get("click_diff") or 0)), 2),
            "confidence": "Medium",
            "owner": "Content + SEO",
            "kpi": "URL bazli clicks + CTR",
            "success_metric": f"Click kaybini % {max(15, int(abs(float(p.get('click_delta_pct') or 0)) * 0.4))} azalt",
        })

    # basit dedupe: ayni title olanlari tekilleştir
    deduped = []
    seen_titles = set()
    for t in sorted(tasks, key=lambda x: (-float(x.get("impact_score") or 0), x.get("priority", "P3"))):
        key = (t.get("title") or "").strip().lower()
        if not key or key in seen_titles:
            continue
        seen_titles.add(key)
        deduped.append(t)

    health_score = 50
    clicks_delta = float(delta.get("clicks") or 0)
    if clicks_delta <= -20:
        health_score = 20
    elif clicks_delta <= -10:
        health_score = 35
    elif clicks_delta <= -3:
        health_score = 50
    elif clicks_delta < 5:
        health_score = 65
    else:
        health_score = 80

    confidence_order = {"High": 3, "Medium": 2, "Low": 1}
    plan_conf = "Low"
    if top_causes:
        plan_conf = sorted(
            [str(c.get("confidence") or "Low") for c in top_causes[:2]],
            key=lambda x: confidence_order.get(x, 1),
            reverse=True,
        )[0]

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period_days": days,
        "headline": (
            f"Son {days} gunde trafik degisimi %{round(clicks_delta, 2)}. "
            f"Odak neden: {(top_causes[0]['label'] if top_causes else 'Karma etki')}."
        ),
        "recovery_score": health_score,
        "plan_confidence": plan_conf,
        "summary": {
            "clicks_delta_pct": round(clicks_delta, 2),
            "impressions_delta_pct": round(float(delta.get("impressions") or 0), 2),
            "ctr_delta_pct": round(float(delta.get("ctr") or 0), 2),
            "position_delta": round(float(delta.get("position") or 0), 2),
            "dominant_cause": (top_causes[0]["label"] if top_causes else "Karma etki"),
            "task_count": len(deduped[:10]),
        },
        "timeline": [
            {"phase": "24 saat", "goal": "Kritik dususu durdur"},
            {"phase": "7 gun", "goal": "Kayip URL'lerde toparlanmayi baslat"},
            {"phase": "30 gun", "goal": "Kapsam ve kalite ile kalici buyume"},
        ],
        "tasks": deduped[:10],
        "source_links": {
            "what_changed": f"/sites/{site_id}/growth/what-changed?days={days}&top_pages={max(5, top_pages)}",
            "anomaly_cause_score": f"/sites/{site_id}/growth/anomaly-cause-score?days={days}&top_pages={max(5, top_pages)}",
        },
    }


@app.post("/sites/{site_id}/growth/serp-snippet-score")
def growth_serp_snippet_score_endpoint(
    site_id: str,
    payload: SerpSnippetScoreIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    result = _build_serp_snippet_score(payload)
    return {
        "site_id": site_id,
        **result,
    }


@app.get("/sites/{site_id}/pages/performance")
def get_page_performance_analysis(
    site_id: str,
    days: int = Query(1, enum=[1, 7, 14, 30]),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    En iyi ve en kötü performans gösteren sayfaları döndürür.
    (Yakında GSC page data entegrasyonu ile gelecek)
    """
    site = get_site_owned(site_id, user, db)
    
    # TODO: GSC'den page bazlı veri çek
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "message": "Sayfa performans analizi yakında eklenecek",
        "status": "coming_soon"
    }


@app.get("/sites/{site_id}/overview")
def get_site_overview(
    site_id: str,
    days: int = Query(1, ge=1, le=365),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Site için kapsamlı özet rapor.
    
    İçerir:
    - Son health durumu
    - Trend analizi
    - Aktif alert sayıları
    - Temel metrikler
    """
    site = get_site_owned(site_id, user, db)
    
    # Son snapshot
    latest_snapshot = (
        db.query(HealthSnapshot)
        .filter(HealthSnapshot.site_id == site_id)
        .order_by(HealthSnapshot.created_at.desc())
        .first()
    )
    
    # Trend analizi
    trend = analyze_trend(site_id, days, db)
    
    # Alert özeti
    since = datetime.now(timezone.utc) - timedelta(days=days)
    alerts_critical = db.query(Alert).filter(
        Alert.site_id == site_id,
        Alert.severity == 3,
        Alert.created_at >= since
    ).count()
    
    alerts_warning = db.query(Alert).filter(
        Alert.site_id == site_id,
        Alert.severity == 2,
        Alert.created_at >= since
    ).count()
    
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "gsc_property": site.gsc_property_url,
        "current_health": {
            "score": latest_snapshot.score if latest_snapshot else None,
            "status": latest_snapshot.status if latest_snapshot else None,
            "last_check": latest_snapshot.created_at.isoformat() if latest_snapshot else None
        },
        "trend": trend,
        "alerts": {
            "critical": alerts_critical,
            "warning": alerts_warning,
            "total": alerts_critical + alerts_warning
        },
        "metrics": {
            "clicks": latest_snapshot.clicks if latest_snapshot else 0,
            "impressions": latest_snapshot.impressions if latest_snapshot else 0,
            "ctr": latest_snapshot.ctr if latest_snapshot else 0
        }
    }

@app.post("/sites/{site_id}/keywords/fetch")
def fetch_keywords_endpoint(
    site_id: str,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(100, ge=1, le=25000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)

    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site için gsc_property_url tanımlı değil")

    # GSC için “tam gün” bitmiş data: bugün değil, dünkü günü baz al
    base_end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    rows = []
    used_end_day = base_end_day
    used_start_day = base_end_day - timedelta(days=days - 1)

    for back_days in range(0, 7):
        candidate_end = base_end_day - timedelta(days=back_days)
        candidate_start = candidate_end - timedelta(days=days - 1)

        candidate_rows = fetch_keywords_from_gsc(
            site_url=site.gsc_property_url,
            start_date=candidate_start.isoformat(),
            end_date=candidate_end.isoformat(),
            db=db,
            row_limit=limit,
            user_id=user.id,
        )

        if candidate_rows:
            rows = candidate_rows
            used_end_day = candidate_end
            used_start_day = candidate_start
            break

    # snapshot_date'i gun bazinda sabitle (UTC)
    snapshot_dt = datetime.combine(used_end_day, time(0, 0, 0), tzinfo=timezone.utc)

    saved = save_keyword_snapshots(
        site_id=site_id,
        keywords_data=rows,
        snapshot_date=snapshot_dt,
        db=db,
    )

    return {
        "site_id": site_id,
        "start_date": used_start_day.isoformat(),
        "end_date": used_end_day.isoformat(),
        "fallback_days_tried": 7,
        "keywords_received": len(rows),
        "keywords_saved": saved,
    }

@app.get("/sites/{site_id}/keywords")
def list_keywords_endpoint(
    site_id: str,
    sort_by: str = Query("impressions"),
    order: str = Query("desc"),
    limit: int = Query(500, ge=1, le=5000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    # Her keyword için en güncel date'i bul
    subq = (
        db.query(
            KeywordSnapshot.keyword.label("kw"),
            func.max(KeywordSnapshot.date).label("max_date"),
        )
        .filter(KeywordSnapshot.site_id == site_id)
        .group_by(KeywordSnapshot.keyword)
        .subquery()
    )

    q = (
        db.query(KeywordSnapshot)
        .join(
            subq,
            (KeywordSnapshot.keyword == subq.c.kw)
            & (KeywordSnapshot.date == subq.c.max_date),
        )
        .filter(KeywordSnapshot.site_id == site_id)
    )

    sort_map = {
        "position": KeywordSnapshot.position,
        "clicks": KeywordSnapshot.clicks,
        "impressions": KeywordSnapshot.impressions,
        "ctr": KeywordSnapshot.ctr,
        "keyword": KeywordSnapshot.keyword,
        "date": KeywordSnapshot.date,
    }
    col = sort_map.get(sort_by, KeywordSnapshot.impressions)

    if order.lower() == "asc":
        q = q.order_by(col.asc())
    else:
        q = q.order_by(col.desc())

    rows = q.limit(limit).all()

    return {
        "site_id": site_id,
        "count": len(rows),
        "keywords": [
            {
                "keyword": r.keyword,
                "position": float(r.position or 0.0),
                "clicks": int(r.clicks or 0),
                "impressions": int(r.impressions or 0),
                "ctr": round(float(r.ctr or 0.0) * 100, 2),  # yüzde
                "date": r.date.isoformat() if r.date else None,
            }
            for r in rows
        ],
    }
@app.get("/sites/{site_id}/keywords/analytics")
def keywords_analytics_endpoint(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    get_site_owned(site_id, user, db)
    return analyze_keyword_trends(site_id=site_id, db=db)


@app.get("/sites/{site_id}/keywords/intent-clusters")
def keyword_intent_clusters_endpoint(
    site_id: str,
    limit: int = Query(1000, ge=50, le=5000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    subq = (
        db.query(
            KeywordSnapshot.keyword.label("kw"),
            func.max(KeywordSnapshot.date).label("max_date"),
        )
        .filter(KeywordSnapshot.site_id == site_id)
        .group_by(KeywordSnapshot.keyword)
        .subquery()
    )
    rows = (
        db.query(KeywordSnapshot)
        .join(
            subq,
            (KeywordSnapshot.keyword == subq.c.kw)
            & (KeywordSnapshot.date == subq.c.max_date),
        )
        .filter(KeywordSnapshot.site_id == site_id)
        .order_by(KeywordSnapshot.impressions.desc())
        .limit(limit)
        .all()
    )
    if not rows:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "total_keywords": 0,
            "total_clicks": 0,
            "clusters": [],
        }

    label_map = {
        "informational": {"label": "Bilgi amacli", "color": "#2d9cdb"},
        "navigational": {"label": "Gezinme amacli", "color": "#9b5de5"},
        "commercial": {"label": "Ticari amacli", "color": "#f2b635"},
        "transactional": {"label": "Islem amacli", "color": "#53cfa1"},
    }
    bucket = {
        k: {
            "intent": k,
            "label": v["label"],
            "color": v["color"],
            "keyword_count": 0,
            "clicks": 0.0,
            "impressions": 0.0,
            "examples": [],
        }
        for k, v in label_map.items()
    }
    total_clicks = 0.0
    for r in rows:
        intent = _classify_keyword_intent(r.keyword or "")
        item = bucket[intent]
        item["keyword_count"] += 1
        item["clicks"] += float(r.clicks or 0)
        item["impressions"] += float(r.impressions or 0)
        total_clicks += float(r.clicks or 0)
        if len(item["examples"]) < 4 and r.keyword:
            item["examples"].append(r.keyword)

    total_keywords = len(rows)
    clusters = []
    for intent in ["informational", "navigational", "commercial", "transactional"]:
        b = bucket[intent]
        share = (b["keyword_count"] / total_keywords * 100) if total_keywords else 0
        traffic_share = (b["clicks"] / total_clicks * 100) if total_clicks > 0 else 0
        clusters.append({
            "intent": intent,
            "label": b["label"],
            "color": b["color"],
            "keyword_count": int(b["keyword_count"]),
            "keyword_share_pct": round(share, 1),
            "traffic_clicks": int(round(b["clicks"])),
            "traffic_share_pct": round(traffic_share, 1),
            "impressions": int(round(b["impressions"])),
            "examples": b["examples"],
        })

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "total_keywords": total_keywords,
        "total_clicks": int(round(total_clicks)),
        "clusters": clusters,
    }
# --- KEYWORDS: HISTORY ---
@app.get("/sites/{site_id}/keywords/{keyword}/history")
def keyword_history_endpoint(
    site_id: str,
    keyword: str,
    days: int = Query(30, ge=1, le=365),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    snaps = get_keyword_history(site_id=site_id, keyword=keyword, days=days, db=db)

    return {
        "site_id": site_id,
        "keyword": keyword,
        "days": days,
        "history": [
            {
                "date": s.date.isoformat() if s.date else None,
                "position": float(s.position or 0.0),
                "clicks": int(s.clicks or 0),
                "impressions": int(s.impressions or 0),
                "ctr": round(float(s.ctr or 0.0) * 100, 2),
            }
            for s in snaps
        ],
    }


@app.get("/sites/{site_id}/reports/notes")
def report_notes_list_endpoint(
    site_id: str,
    month: str = Query(..., description="YYYY-MM"),
    note_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    month_val = _safe_month_or_400(month)
    wanted_type = (note_type or "").strip().lower()
    q = (
        db.query(ReportNote)
        .filter(
            ReportNote.site_id == site_id,
            ReportNote.user_id == user.id,
            ReportNote.month == month_val,
        )
        .order_by(ReportNote.created_at.desc())
    )
    if wanted_type:
        q = q.filter(ReportNote.note_type == wanted_type)
    rows = q.limit(limit).all()
    return {
        "site_id": site_id,
        "month": month_val,
        "count": len(rows),
        "notes": [
            {
                "id": n.id,
                "note_type": n.note_type,
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
                "updated_at": n.updated_at.isoformat() if n.updated_at else None,
            }
            for n in rows
        ],
    }


@app.post("/sites/{site_id}/reports/notes")
def report_note_create_endpoint(
    site_id: str,
    payload: ReportNoteIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    month_val = _safe_month_or_400(payload.month)
    note_type = (payload.note_type or "team").strip().lower()
    if note_type not in {"team", "client"}:
        raise HTTPException(status_code=400, detail="note_type team veya client olmali")
    content = (payload.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Not icerigi bos olamaz")
    row = ReportNote(
        site_id=site_id,
        user_id=user.id,
        month=month_val,
        note_type=note_type,
        content=content,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "ok": True,
        "note": {
            "id": row.id,
            "site_id": row.site_id,
            "month": row.month,
            "note_type": row.note_type,
            "content": row.content,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
    }


@app.get("/sites/{site_id}/seo/monthly-report")
def monthly_seo_report_endpoint(
    site_id: str,
    month: Optional[str] = Query(None, description="YYYY-MM"),
    top_keywords_limit: int = Query(50, ge=10, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from calendar import monthrange
    from datetime import date as date_cls

    site = get_site_owned(site_id, user, db)

    # Default: onceki tamamlanmis ay
    today_utc = datetime.now(timezone.utc).date()
    if month:
        try:
            y, m = month.split("-")
            report_year = int(y)
            report_month = int(m)
            if report_month < 1 or report_month > 12:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=400, detail="month YYYY-MM formatinda olmali")
    else:
        first_this_month = date_cls(today_utc.year, today_utc.month, 1)
        prev_last_day = first_this_month - timedelta(days=1)
        report_year = prev_last_day.year
        report_month = prev_last_day.month

    _, last_day = monthrange(report_year, report_month)
    start_day = date_cls(report_year, report_month, 1)
    end_day = date_cls(report_year, report_month, last_day)

    prev_end = start_day - timedelta(days=1)
    prev_start = date_cls(prev_end.year, prev_end.month, 1)

    def pct_delta(curr, prev):
        if prev in (0, None):
            return 0.0
        return round(((curr - prev) / prev) * 100, 2)

    # GSC metrikleri (property yoksa bos dondur)
    current_metrics = {"clicks": 0, "impressions": 0, "ctr": 0.0, "position": 0.0}
    prev_metrics = {"clicks": 0, "impressions": 0, "ctr": 0.0, "position": 0.0}
    gsc_note = None
    if site.gsc_property_url:
        try:
            current_metrics = fetch_gsc_summary(
                site_url=site.gsc_property_url,
                start_date=start_day.isoformat(),
                end_date=end_day.isoformat(),
                db=db,
                user_id=user.id,
            )
            prev_metrics = fetch_gsc_summary(
                site_url=site.gsc_property_url,
                start_date=prev_start.isoformat(),
                end_date=prev_end.isoformat(),
                db=db,
                user_id=user.id,
            )
        except Exception as e:
            gsc_note = f"GSC monthly summary alinamadi: {str(e)}"
    else:
        gsc_note = "Bu site icin gsc_property_url tanimli degil"

    # Health snapshots
    month_start_dt = datetime.combine(start_day, time(0, 0, 0), tzinfo=timezone.utc)
    month_end_dt = datetime.combine(end_day, time(23, 59, 59), tzinfo=timezone.utc)

    health_points = (
        db.query(HealthSnapshot)
        .filter(
            HealthSnapshot.site_id == site_id,
            HealthSnapshot.created_at >= month_start_dt,
            HealthSnapshot.created_at <= month_end_dt
        )
        .order_by(HealthSnapshot.created_at.asc())
        .all()
    )

    if health_points:
        health_scores = [p.score for p in health_points]
        health_summary = {
            "points": len(health_points),
            "avg_score": round(sum(health_scores) / len(health_scores), 2),
            "min_score": min(health_scores),
            "max_score": max(health_scores),
            "first_score": health_scores[0],
            "last_score": health_scores[-1],
            "trend_delta": round(health_scores[-1] - health_scores[0], 2),
        }
    else:
        health_summary = {
            "points": 0,
            "avg_score": 0.0,
            "min_score": 0,
            "max_score": 0,
            "first_score": 0,
            "last_score": 0,
            "trend_delta": 0.0,
        }

    # Alerts
    month_alerts = (
        db.query(Alert)
        .filter(
            Alert.site_id == site_id,
            Alert.created_at >= month_start_dt,
            Alert.created_at <= month_end_dt
        )
        .order_by(Alert.created_at.desc())
        .all()
    )

    alerts_summary = {
        "total": len(month_alerts),
        "critical": len([a for a in month_alerts if a.severity == 3]),
        "warning": len([a for a in month_alerts if a.severity == 2]),
        "info": len([a for a in month_alerts if a.severity == 1]),
        "recent": [
            {
                "type": a.alert_type,
                "severity": a.severity,
                "metric": a.metric,
                "delta_pct": a.delta_pct,
                "reason": a.reason,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in month_alerts[:20]
        ],
    }

    # Keyword snapshots: ay icindeki en guncel gunden cek
    latest_kw_date = (
        db.query(func.max(KeywordSnapshot.date))
        .filter(
            KeywordSnapshot.site_id == site_id,
            KeywordSnapshot.date >= month_start_dt,
            KeywordSnapshot.date <= month_end_dt
        )
        .scalar()
    )

    keyword_rows = []
    if latest_kw_date:
        keyword_rows = (
            db.query(KeywordSnapshot)
            .filter(
                KeywordSnapshot.site_id == site_id,
                KeywordSnapshot.date == latest_kw_date
            )
            .order_by(KeywordSnapshot.impressions.desc())
            .limit(top_keywords_limit)
            .all()
        )

    top_keywords = [
        {
            "keyword": r.keyword,
            "position": round(float(r.position or 0.0), 2),
            "clicks": int(r.clicks or 0),
            "impressions": int(r.impressions or 0),
            "ctr": round(float(r.ctr or 0.0) * 100, 2),
        }
        for r in keyword_rows
    ]

    keyword_summary = {
        "snapshot_date": latest_kw_date.isoformat() if latest_kw_date else None,
        "total_keywords": len(top_keywords),
        "top3": len([k for k in top_keywords if k["position"] <= 3]),
        "top10": len([k for k in top_keywords if k["position"] <= 10]),
        "avg_position": round(
            (sum([k["position"] for k in top_keywords]) / len(top_keywords)),
            2
        ) if top_keywords else 0.0,
        "opportunities": [
            k for k in top_keywords
            if k["impressions"] >= 100 and k["ctr"] < 2.0
        ][:20],
        "top_keywords": top_keywords[:30],
    }

    # Basit visibility index (0-100)
    visibility_index = 0.0
    if keyword_summary["total_keywords"] > 0:
        top10_share = keyword_summary["top10"] / keyword_summary["total_keywords"]
        ctr_component = min((current_metrics.get("ctr", 0.0) * 100) / 10.0, 1.0)
        pos_component = max(0.0, min(1.0, (30.0 - keyword_summary["avg_position"]) / 30.0))
        visibility_index = round((top10_share * 0.5 + ctr_component * 0.25 + pos_component * 0.25) * 100, 2)

    # Oneriler
    recommendations = []
    if pct_delta(current_metrics.get("clicks", 0), prev_metrics.get("clicks", 0)) < -10:
        recommendations.append("Kliklerde dusus var: title/meta ve rich result optimizasyonu yapin.")
    if pct_delta(current_metrics.get("impressions", 0), prev_metrics.get("impressions", 0)) < -10:
        recommendations.append("Impression dusuyor: yeni icerik clusteri ve internal link guclendirmesi planlayin.")
    if alerts_summary["critical"] > 0:
        recommendations.append("Critical alertler var: teknik SEO ve index kapsami kontrollerini onceleyin.")
    if keyword_summary["avg_position"] > 20:
        recommendations.append("Ortalama pozisyon dusuk: ilk 20'deki URL'ler icin on-page iyilestirme yapin.")
    if len(keyword_summary["opportunities"]) > 0:
        recommendations.append("Yuksek impression - dusuk CTR keywordlerde snippet yeniden yazimi deneyin.")
    if not recommendations:
        recommendations.append("Performans stabil: mevcut stratejiyi koruyup yeni icerik yayilimini surdurun.")

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "month": f"{report_year:04d}-{report_month:02d}",
            "start_date": start_day.isoformat(),
            "end_date": end_day.isoformat(),
            "previous_start_date": prev_start.isoformat(),
            "previous_end_date": prev_end.isoformat(),
        },
        "gsc_note": gsc_note,
        "visibility_index": visibility_index,
        "metrics": {
            "current": current_metrics,
            "previous": prev_metrics,
            "delta_pct": {
                "clicks": pct_delta(current_metrics.get("clicks", 0), prev_metrics.get("clicks", 0)),
                "impressions": pct_delta(current_metrics.get("impressions", 0), prev_metrics.get("impressions", 0)),
                "ctr": pct_delta(current_metrics.get("ctr", 0.0), prev_metrics.get("ctr", 0.0)),
                "position": round(current_metrics.get("position", 0.0) - prev_metrics.get("position", 0.0), 2),
            },
        },
        "health": health_summary,
        "alerts": alerts_summary,
        "keywords": keyword_summary,
        "recommendations": recommendations,
    }


@app.post("/sites/{site_id}/seo/competitor-analysis")
def competitor_analysis_endpoint(
    site_id: str,
    payload: CompetitorAnalysisRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from calendar import monthrange
    from datetime import date as date_cls

    site = get_site_owned(site_id, user, db)

    if not payload.competitors:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "period": None,
            "objective": payload.objective,
            "leaderboard": [],
            "gaps": [],
            "missing_keyword_opportunities": [],
            "recommendations": ["Analiz icin en az bir rakip ekleyin."],
        }

    today_utc = datetime.now(timezone.utc).date()
    if payload.month:
        try:
            y, m = payload.month.split("-")
            report_year = int(y)
            report_month = int(m)
            if report_month < 1 or report_month > 12:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=400, detail="month YYYY-MM formatinda olmali")
    else:
        first_this_month = date_cls(today_utc.year, today_utc.month, 1)
        prev_last_day = first_this_month - timedelta(days=1)
        report_year = prev_last_day.year
        report_month = prev_last_day.month

    _, last_day = monthrange(report_year, report_month)
    start_day = date_cls(report_year, report_month, 1)
    end_day = date_cls(report_year, report_month, last_day)

    our_metrics = {"clicks": 0, "impressions": 0, "ctr": 0.0, "position": 0.0}
    if site.gsc_property_url:
        try:
            our_metrics = fetch_gsc_summary(
                site_url=site.gsc_property_url,
                start_date=start_day.isoformat(),
                end_date=end_day.isoformat(),
                db=db,
                user_id=user.id,
            )
        except Exception:
            pass

    month_start_dt = datetime.combine(start_day, time(0, 0, 0), tzinfo=timezone.utc)
    month_end_dt = datetime.combine(end_day, time(23, 59, 59), tzinfo=timezone.utc)

    latest_kw_date = (
        db.query(func.max(KeywordSnapshot.date))
        .filter(
            KeywordSnapshot.site_id == site_id,
            KeywordSnapshot.date >= month_start_dt,
            KeywordSnapshot.date <= month_end_dt,
        )
        .scalar()
    )
    our_keyword_set = set()
    if latest_kw_date:
        our_keywords = (
            db.query(KeywordSnapshot.keyword)
            .filter(
                KeywordSnapshot.site_id == site_id,
                KeywordSnapshot.date == latest_kw_date
            )
            .all()
        )
        our_keyword_set = {str(k[0]).strip().lower() for k in our_keywords if k and k[0]}

    # Bizim visibility skor (0-100)
    our_top10_share = 0.0
    if latest_kw_date:
        total_kws = (
            db.query(KeywordSnapshot)
            .filter(KeywordSnapshot.site_id == site_id, KeywordSnapshot.date == latest_kw_date)
            .count()
        )
        if total_kws > 0:
            top10_kws = (
                db.query(KeywordSnapshot)
                .filter(
                    KeywordSnapshot.site_id == site_id,
                    KeywordSnapshot.date == latest_kw_date,
                    KeywordSnapshot.position <= 10
                )
                .count()
            )
            our_top10_share = (top10_kws / total_kws) * 100

    our_visibility = (
        min(100.0, our_top10_share) * 0.45
        + min(100.0, (our_metrics.get("ctr", 0.0) * 100) * 8) * 0.20
        + max(0.0, min(100.0, (40 - our_metrics.get("position", 0.0)) * 2.5)) * 0.20
        + min(100.0, (our_metrics.get("impressions", 0.0) / 10000) * 100) * 0.15
    )
    our_visibility = round(our_visibility, 2)

    leaderboard = [
        {
            "name": site.domain,
            "is_our_site": True,
            "visibility_score": our_visibility,
            "clicks": round(float(our_metrics.get("clicks", 0)), 2),
            "impressions": round(float(our_metrics.get("impressions", 0)), 2),
            "ctr": round(float(our_metrics.get("ctr", 0.0)) * 100, 2),
            "avg_position": round(float(our_metrics.get("position", 0.0)), 2),
            "top10_share": round(float(our_top10_share), 2),
            "indexed_pages": 0,
            "backlinks": 0,
        }
    ]

    gaps = []
    missing_kw_rows = []

    for c in payload.competitors:
        # Manuel metrik girilmediyse rakip degerlerini bizim metriklerden
        # deterministik bir benchmark modeliyle tahmin et.
        auto_mode = (
            c.clicks == 0 and c.impressions == 0 and c.ctr == 0
            and c.avg_position == 0 and c.top10_share == 0
            and c.indexed_pages == 0 and c.backlinks == 0
        )

        if auto_mode:
            seed = sum(ord(ch) for ch in (c.name or "competitor"))
            factor_click = 0.8 + ((seed % 35) / 100.0)      # 0.80 - 1.14
            factor_impr = 0.85 + ((seed % 40) / 100.0)      # 0.85 - 1.24
            ctr_bonus = ((seed % 25) - 10) / 100.0          # -0.10 - +0.14
            pos_shift = ((seed % 11) - 5) * 0.6             # -3.0 - +3.0
            top10_shift = ((seed % 21) - 10) * 0.9          # -9.0 - +9.0
            pages_base = 80 + (seed % 320)
            backlinks_base = 200 + (seed % 2800)

            c_clicks = round(float(our_metrics.get("clicks", 0)) * factor_click, 2)
            c_impressions = round(float(our_metrics.get("impressions", 0)) * factor_impr, 2)
            c_ctr = round(max(0.1, (float(our_metrics.get("ctr", 0.0)) * 100) + ctr_bonus), 2)
            c_avg_position = round(max(1.0, float(our_metrics.get("position", 0.0)) + pos_shift), 2)
            c_top10_share = round(max(0.0, min(100.0, float(our_top10_share) + top10_shift)), 2)
            c_indexed_pages = int(pages_base)
            c_backlinks = int(backlinks_base)
        else:
            c_clicks = c.clicks
            c_impressions = c.impressions
            c_ctr = c.ctr
            c_avg_position = c.avg_position
            c_top10_share = c.top10_share
            c_indexed_pages = c.indexed_pages
            c_backlinks = c.backlinks

        comp_visibility = (
            min(100.0, c_top10_share) * 0.45
            + min(100.0, c_ctr * 8) * 0.20
            + max(0.0, min(100.0, (40 - c_avg_position) * 2.5)) * 0.20
            + min(100.0, (c_impressions / 10000) * 100) * 0.15
        )
        comp_visibility = round(comp_visibility, 2)

        leaderboard.append({
            "name": c.name,
            "is_our_site": False,
            "visibility_score": comp_visibility,
            "clicks": round(c_clicks, 2),
            "impressions": round(c_impressions, 2),
            "ctr": round(c_ctr, 2),
            "avg_position": round(c_avg_position, 2),
            "top10_share": round(c_top10_share, 2),
            "indexed_pages": c_indexed_pages,
            "backlinks": c_backlinks,
        })

        click_gap = round(c_clicks - float(our_metrics.get("clicks", 0)), 2)
        imp_gap = round(c_impressions - float(our_metrics.get("impressions", 0)), 2)
        ctr_gap = round(c_ctr - (float(our_metrics.get("ctr", 0.0)) * 100), 2)
        pos_gap = round(c_avg_position - float(our_metrics.get("position", 0.0)), 2)

        gaps.append({
            "competitor": c.name,
            "visibility_gap": round(comp_visibility - our_visibility, 2),
            "click_gap": click_gap,
            "impression_gap": imp_gap,
            "ctr_gap": ctr_gap,
            "position_gap": pos_gap,
            "backlink_gap": int(c_backlinks or 0),
            "indexed_pages_gap": int(c_indexed_pages or 0),
        })

        comp_kw = [str(k).strip().lower() for k in (c.priority_keywords or []) if str(k).strip()]
        missing = [k for k in comp_kw if k not in our_keyword_set]
        if missing:
            missing_kw_rows.append({
                "competitor": c.name,
                "missing_count": len(missing),
                "missing_keywords": missing[:25],
            })

    leaderboard = sorted(leaderboard, key=lambda x: x["visibility_score"], reverse=True)
    gaps = sorted(gaps, key=lambda x: x["visibility_gap"], reverse=True)
    missing_kw_rows = sorted(missing_kw_rows, key=lambda x: x["missing_count"], reverse=True)

    recommendations = []
    if gaps and gaps[0]["visibility_gap"] > 5:
        recommendations.append(
            f"En guclu rakip ({gaps[0]['competitor']}) gorunurlukte onde. Top10 share ve snippet optimizasyonu onceliklendirilmeli."
        )
    if any(g["ctr_gap"] > 1.5 for g in gaps):
        recommendations.append("Rakip CTR avantajina sahip. Title ve meta aciklama AB testleri uygulanmali.")
    if any(g["position_gap"] < -3 for g in gaps):
        recommendations.append("Pozisyonda geri kalinan keyword gruplari icin landing page refresh plani yapin.")
    if missing_kw_rows:
        recommendations.append("Rakip odakli keyword gap listesi uzerinden yeni icerik clusteri acin.")
    if not recommendations:
        recommendations.append("Rakiplerle fark dengeli. Mevcut stratejiyi buyume hedefiyle surdurun.")

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "month": f"{report_year:04d}-{report_month:02d}",
            "start_date": start_day.isoformat(),
            "end_date": end_day.isoformat(),
        },
        "objective": payload.objective,
        "leaderboard": leaderboard,
        "gaps": gaps,
        "missing_keyword_opportunities": missing_kw_rows,
        "recommendations": recommendations,
    }


@app.get("/sites/{site_id}/pages/anomalies")
def page_level_anomaly_endpoint(
    site_id: str,
    days: int = Query(14, ge=7, le=90),
    row_limit: int = Query(500, ge=50, le=25000),
    persist_alerts: bool = Query(True),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    current_end = datetime.now(timezone.utc).date() - timedelta(days=1)
    current_start = current_end - timedelta(days=days - 1)
    prev_end = current_start - timedelta(days=1)
    prev_start = prev_end - timedelta(days=days - 1)

    current_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=current_start.isoformat(),
        end_date=current_end.isoformat(),
        dimensions=["page"],
        row_limit=row_limit,
        db=db,
        user_id=user.id,
    )
    prev_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=prev_start.isoformat(),
        end_date=prev_end.isoformat(),
        dimensions=["page"],
        row_limit=row_limit,
        db=db,
        user_id=user.id,
    )

    current_map = _build_page_map(current_rows)
    prev_map = _build_page_map(prev_rows)
    pages = sorted(set(current_map.keys()) | set(prev_map.keys()))
    if not pages:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "period": {
                "current": {"start": current_start.isoformat(), "end": current_end.isoformat()},
                "baseline": {"start": prev_start.isoformat(), "end": prev_end.isoformat()},
            },
            "anomalies": [],
        }

    click_deltas = []
    for page in pages:
        c = current_map.get(page, {})
        p = prev_map.get(page, {})
        prev_impr = float(p.get("impressions", 0) or 0)
        if prev_impr >= 20:
            click_deltas.append(_pct_delta(float(c.get("clicks", 0) or 0), float(p.get("clicks", 0) or 0)))
    mean_delta, std_delta = _mean_std(click_deltas)

    anomalies = []
    new_alerts = 0
    for page in pages:
        c = current_map.get(page, {})
        p = prev_map.get(page, {})

        c_clicks = float(c.get("clicks", 0) or 0)
        c_impr = float(c.get("impressions", 0) or 0)
        c_ctr = float(c.get("ctr", 0) or 0)
        c_pos = float(c.get("position", 0) or 0)

        p_clicks = float(p.get("clicks", 0) or 0)
        p_impr = float(p.get("impressions", 0) or 0)
        p_ctr = float(p.get("ctr", 0) or 0)
        p_pos = float(p.get("position", 0) or 0)

        if p_impr < 20 and c_impr < 20:
            continue

        click_delta = _pct_delta(c_clicks, p_clicks)
        imp_delta = _pct_delta(c_impr, p_impr)
        ctr_delta = _pct_delta(c_ctr, p_ctr)
        pos_delta = round(c_pos - p_pos, 2)

        z_score = round((click_delta - mean_delta) / std_delta, 2) if std_delta > 0 else 0.0
        severity = 1
        if click_delta <= -40 or z_score <= -2.5:
            severity = 3
        elif click_delta <= -20 or z_score <= -1.8:
            severity = 2

        if severity == 1:
            continue

        losses = _page_query_losses(
            site_url=site.gsc_property_url,
            page_url=page,
            current_start=current_start.isoformat(),
            current_end=current_end.isoformat(),
            prev_start=prev_start.isoformat(),
            prev_end=prev_end.isoformat(),
            user_id=user.id,
            db=db,
        )
        reason = _estimate_page_reason(click_delta, imp_delta, ctr_delta, pos_delta, losses)

        anomaly = {
            "page": page,
            "severity": severity,
            "click_delta_pct": click_delta,
            "impression_delta_pct": imp_delta,
            "ctr_delta_pct": ctr_delta,
            "position_delta": pos_delta,
            "z_score": z_score,
            "current": {
                "clicks": round(c_clicks, 2),
                "impressions": round(c_impr, 2),
                "ctr": round(c_ctr * 100, 2),
                "position": round(c_pos, 2),
            },
            "baseline": {
                "clicks": round(p_clicks, 2),
                "impressions": round(p_impr, 2),
                "ctr": round(p_ctr * 100, 2),
                "position": round(p_pos, 2),
            },
            "lost_queries": losses,
            "estimated_reason": reason,
        }
        anomalies.append(anomaly)

        if persist_alerts:
            dedupe_raw = f"{site_id}|PAGE_ANOMALY|{page}|{current_end.isoformat()}"
            dedupe_key = hashlib.sha256(dedupe_raw.encode()).hexdigest()
            exists = db.query(Alert).filter(Alert.dedupe_key == dedupe_key).first()
            if not exists:
                db.add(Alert(
                    id=str(uuid.uuid4()),
                    site_id=site_id,
                    severity=severity,
                    alert_type="PAGE_ANOMALY",
                    metric="page_clicks",
                    current_value=c_clicks,
                    baseline_value=p_clicks,
                    delta_pct=click_delta,
                    reason=f"{page} sayfasinda anomali: {reason}",
                    recommendation="Sayfanin ana basligi, icerigi ve son degisiklikleri kontrol edilmeli.",
                    dedupe_key=dedupe_key,
                    window_days=days,
                ))
                new_alerts += 1

    if persist_alerts and new_alerts > 0:
        db.commit()

    anomalies = sorted(anomalies, key=lambda x: (-x["severity"], x["click_delta_pct"]))

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "current": {"start": current_start.isoformat(), "end": current_end.isoformat()},
            "baseline": {"start": prev_start.isoformat(), "end": prev_end.isoformat()},
        },
        "stats": {"mean_click_delta_pct": round(mean_delta, 2), "std_click_delta_pct": round(std_delta, 2)},
        "new_alerts_created": new_alerts,
        "anomalies": anomalies,
    }


@app.post("/sites/{site_id}/backlinks/snapshot")
def backlink_snapshot_endpoint(
    site_id: str,
    payload: BacklinkSnapshotRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    snapshot_dt = _parse_iso_dt_or_none(payload.snapshot_date) or datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    db.query(BacklinkSnapshot).filter(
        BacklinkSnapshot.site_id == site_id,
        BacklinkSnapshot.snapshot_date == snapshot_dt,
    ).delete(synchronize_session=False)

    saved = 0
    for row in payload.backlinks:
        source = (row.source_url or "").strip()
        target = (row.target_url or "").strip()
        if not source or not target:
            continue
        first_seen = _parse_iso_dt_or_none(row.first_seen)
        last_seen = _parse_iso_dt_or_none(row.last_seen)

        db.add(BacklinkSnapshot(
            site_id=site_id,
            source_url=source,
            target_url=target,
            anchor_text=(row.anchor_text or "").strip(),
            domain_authority=max(0.0, min(100.0, float(row.domain_authority or 0))),
            spam_score=max(0.0, min(100.0, float(row.spam_score or 0))),
            is_active=bool(row.is_active),
            first_seen=first_seen,
            last_seen=last_seen,
            snapshot_date=snapshot_dt,
        ))
        saved += 1

    db.commit()
    return {
        "site_id": site_id,
        "snapshot_date": snapshot_dt.isoformat(),
        "saved": saved,
    }


@app.get("/sites/{site_id}/backlinks/overview")
def backlink_overview_endpoint(
    site_id: str,
    toxic_limit: int = Query(50, ge=5, le=300),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)

    snapshot_dates = [
        r[0] for r in (
            db.query(BacklinkSnapshot.snapshot_date)
            .filter(BacklinkSnapshot.site_id == site_id)
            .distinct()
            .order_by(BacklinkSnapshot.snapshot_date.desc())
            .limit(2)
            .all()
        )
    ]
    if not snapshot_dates:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "latest_snapshot_date": None,
            "comparison_snapshot_date": None,
            "summary": {"total_backlinks": 0, "active_backlinks": 0, "toxic_backlinks": 0, "toxic_ratio_pct": 0.0},
            "new_backlinks": [],
            "lost_backlinks": [],
            "anchor_distribution": [],
            "toxic_backlinks": [],
        }

    latest_date = snapshot_dates[0]
    prev_date = snapshot_dates[1] if len(snapshot_dates) > 1 else None
    latest_rows = db.query(BacklinkSnapshot).filter(
        BacklinkSnapshot.site_id == site_id,
        BacklinkSnapshot.snapshot_date == latest_date,
    ).all()
    prev_rows = []
    if prev_date:
        prev_rows = db.query(BacklinkSnapshot).filter(
            BacklinkSnapshot.site_id == site_id,
            BacklinkSnapshot.snapshot_date == prev_date,
        ).all()

    latest_keys = {(r.source_url, r.target_url) for r in latest_rows}
    prev_keys = {(r.source_url, r.target_url) for r in prev_rows}
    new_keys = latest_keys - prev_keys
    lost_keys = prev_keys - latest_keys

    latest_map = {(r.source_url, r.target_url): r for r in latest_rows}
    prev_map = {(r.source_url, r.target_url): r for r in prev_rows}

    anchor_counter = Counter()
    toxic_rows = []
    for r in latest_rows:
        if r.is_active:
            anchor = (r.anchor_text or "(empty)").strip() or "(empty)"
            anchor_counter[anchor] += 1
        risk = _backlink_risk(r.anchor_text or "", float(r.domain_authority or 0), float(r.spam_score or 0))
        if risk >= 0.7:
            toxic_rows.append({
                "source_url": r.source_url,
                "target_url": r.target_url,
                "anchor_text": r.anchor_text or "",
                "domain_authority": round(float(r.domain_authority or 0), 2),
                "spam_score": round(float(r.spam_score or 0), 2),
                "risk_score": risk,
            })
    toxic_rows.sort(key=lambda x: x["risk_score"], reverse=True)

    active_count = len([r for r in latest_rows if r.is_active])
    toxic_count = len(toxic_rows)

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "latest_snapshot_date": latest_date.isoformat() if latest_date else None,
        "comparison_snapshot_date": prev_date.isoformat() if prev_date else None,
        "summary": {
            "total_backlinks": len(latest_rows),
            "active_backlinks": active_count,
            "toxic_backlinks": toxic_count,
            "toxic_ratio_pct": round((toxic_count / len(latest_rows) * 100), 2) if latest_rows else 0.0,
            "new_count": len(new_keys),
            "lost_count": len(lost_keys),
        },
        "new_backlinks": [
            {
                "source_url": k[0],
                "target_url": k[1],
                "anchor_text": latest_map[k].anchor_text or "",
            }
            for k in list(new_keys)[:200]
        ],
        "lost_backlinks": [
            {
                "source_url": k[0],
                "target_url": k[1],
                "anchor_text": prev_map[k].anchor_text or "",
            }
            for k in list(lost_keys)[:200]
        ],
        "anchor_distribution": [
            {"anchor_text": a, "count": c}
            for a, c in anchor_counter.most_common(30)
        ],
        "toxic_backlinks": toxic_rows[:toxic_limit],
    }


@app.get("/sites/{site_id}/content/opportunities")
def content_opportunities_endpoint(
    site_id: str,
    days: int = Query(28, ge=7, le=120),
    top_pages: int = Query(25, ge=5, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["page"],
        row_limit=1000,
        db=db,
        user_id=user.id,
    )
    page_map = _build_page_map(page_rows)
    if not page_map:
        return {"site_id": site_id, "site_domain": site.domain, "opportunities": []}

    total_clicks = sum(v["clicks"] for v in page_map.values())
    total_impr = sum(v["impressions"] for v in page_map.values())
    site_ctr = (total_clicks / total_impr) if total_impr > 0 else 0.0

    sorted_pages = sorted(page_map.items(), key=lambda x: x[1]["impressions"], reverse=True)[:top_pages]
    out = []
    for page, m in sorted_pages:
        recs = []
        pos = m["position"]
        ctr = m["ctr"]
        impr = m["impressions"]
        if 4 <= pos <= 15 and impr >= 150:
            recs.append("Quick win: bu sayfa ilk 3'e tasinabilir, internal link ve on-page guclendirilmeli.")
        if pos <= 10 and ctr < site_ctr * 0.7:
            recs.append("CTR gap: title/meta aciklama test edilmeli, SERP snippet iyilestirilmeli.")
        if impr >= 500 and m["clicks"] < 15:
            recs.append("Yuksek impresyon ama dusuk tiklama: arama niyeti ve snippet uyumu dusuk olabilir.")

        if recs:
            out.append({
                "page": page,
                "clicks": round(m["clicks"], 2),
                "impressions": round(impr, 2),
                "ctr": round(ctr * 100, 2),
                "position": round(pos, 2),
                "recommendations": recs,
            })

    out.sort(key=lambda x: (x["position"], -x["impressions"]))
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "site_ctr_pct": round(site_ctr * 100, 2),
        "opportunities": out,
    }


@app.post("/sites/{site_id}/content/optimize")
def content_optimize_endpoint(
    site_id: str,
    payload: ContentAuditRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    days = max(7, min(120, int(payload.days or 28)))
    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    page_filter = [{"filters": [{"dimension": "page", "operator": "equals", "expression": payload.page_url}]}]
    target_queries = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["query"],
        row_limit=200,
        dimension_filter_groups=page_filter,
        db=db,
        user_id=user.id,
    )
    target_query_terms = set()
    for row in target_queries:
        keys = row.get("keys") or []
        if not keys:
            continue
        target_query_terms.update(_extract_terms(str(keys[0])))

    page_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["page"],
        row_limit=100,
        db=db,
        user_id=user.id,
    )
    page_map = _build_page_map(page_rows)
    ranked_bench = sorted(
        [(p, m) for p, m in page_map.items() if p != payload.page_url and m["position"] <= 8 and m["impressions"] >= 100],
        key=lambda x: (x[1]["position"], -x[1]["impressions"])
    )[:5]

    benchmark_terms = Counter()
    for page_url, _ in ranked_bench:
        filt = [{"filters": [{"dimension": "page", "operator": "equals", "expression": page_url}]}]
        q_rows = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["query"],
            row_limit=100,
            dimension_filter_groups=filt,
            db=db,
            user_id=user.id,
        )
        for r in q_rows:
            keys = r.get("keys") or []
            if not keys:
                continue
            for t in _extract_terms(str(keys[0])):
                benchmark_terms[t] += 1

    content_terms = set()
    content_terms.update(_extract_terms(payload.page_url))
    content_terms.update(_extract_terms(payload.title or ""))
    content_terms.update(_extract_terms(payload.h1 or ""))
    for h in payload.headings or []:
        content_terms.update(_extract_terms(h))
    for e in payload.entities or []:
        content_terms.update(_extract_terms(e))

    target_kw = (payload.target_keyword or "").strip().lower()
    title_norm = _normalize_text(payload.title or "")
    h1_norm = _normalize_text(payload.h1 or "")
    url_norm = _normalize_text(payload.page_url or "")
    has_kw_title = bool(target_kw) and target_kw in title_norm
    has_kw_h1 = bool(target_kw) and target_kw in h1_norm
    has_kw_url = bool(target_kw) and target_kw in url_norm

    benchmark_top_terms = [t for t, _ in benchmark_terms.most_common(40)]
    entity_gap = [t for t in benchmark_top_terms if t not in content_terms and t not in target_query_terms][:20]

    recommendations = []
    score = 100

    if target_kw and not has_kw_title:
        recommendations.append("Hedef keyword title icinde gecmiyor, title yeniden yazilmali.")
        score -= 15
    if target_kw and not has_kw_h1:
        recommendations.append("Hedef keyword H1 icinde gecmiyor, H1 ile arama niyeti hizalanmali.")
        score -= 12
    if target_kw and not has_kw_url:
        recommendations.append("URL icinde hedef keyword yok, yeni URL planlanabiliyorsa optimize edin.")
        score -= 5
    if len(payload.headings or []) < 3:
        recommendations.append("Heading yapisi zayif, en az 3 anlamli H2/H3 ile icerik kapsami artirilmali.")
        score -= 10
    if entity_gap:
        recommendations.append(f"Entity/konu gap bulundu: {', '.join(entity_gap[:12])}")
        score -= min(25, len(entity_gap))
    if len(target_query_terms) < 8:
        recommendations.append("Sayfa query kapsami dar, long-tail alt basliklar ve FAQ bloklari eklenmeli.")
        score -= 8
    if score >= 85:
        recommendations.append("Temel optimizasyon iyi seviyede. CTR testleri ve internal link ile destekleyin.")

    score = max(0, min(100, score))

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "page_url": payload.page_url,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "content_score": score,
        "signals": {
            "target_keyword": payload.target_keyword,
            "keyword_in_title": has_kw_title,
            "keyword_in_h1": has_kw_h1,
            "keyword_in_url": has_kw_url,
            "heading_count": len(payload.headings or []),
            "entity_count": len(payload.entities or []),
            "query_coverage_terms": len(target_query_terms),
        },
        "top_ranking_benchmarks": [
            {"page": p, "position": round(m["position"], 2), "impressions": round(m["impressions"], 2)}
            for p, m in ranked_bench
        ],
        "entity_gap_terms": entity_gap,
        "recommendations": recommendations,
    }


@app.get("/sites/{site_id}/content/revision-suggestions")
def content_revision_suggestions_endpoint(
    site_id: str,
    days: int = Query(28, ge=7, le=120),
    top_pages: int = Query(20, ge=5, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)
    prev_end = start_day - timedelta(days=1)
    prev_start = prev_end - timedelta(days=days - 1)

    current_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["page"],
        row_limit=1000,
        db=db,
        user_id=user.id,
    )
    prev_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=prev_start.isoformat(),
        end_date=prev_end.isoformat(),
        dimensions=["page"],
        row_limit=1000,
        db=db,
        user_id=user.id,
    )
    page_map = _build_page_map(current_rows)
    prev_map = _build_page_map(prev_rows)
    if not page_map:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
            "items": [],
        }

    total_clicks = sum(v["clicks"] for v in page_map.values())
    total_impr = sum(v["impressions"] for v in page_map.values())
    site_ctr = (total_clicks / total_impr) if total_impr > 0 else 0.0

    candidates = sorted(page_map.items(), key=lambda x: x[1]["impressions"], reverse=True)[:top_pages]
    suggestions = []
    for page_url, m in candidates:
        clicks = float(m["clicks"] or 0)
        impr = float(m["impressions"] or 0)
        ctr = float(m["ctr"] or 0)
        pos = float(m["position"] or 0)
        if impr < 80:
            continue

        prev_clicks = float((prev_map.get(page_url) or {}).get("clicks", 0) or 0)
        click_delta_pct = _pct_delta(clicks, prev_clicks) if prev_clicks > 0 else 0.0

        page_filter = [{"filters": [{"dimension": "page", "operator": "equals", "expression": page_url}]}]
        query_rows = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["query"],
            row_limit=80,
            dimension_filter_groups=page_filter,
            db=db,
            user_id=user.id,
        )
        query_terms = Counter()
        top_queries = []
        for row in query_rows:
            keys = row.get("keys") or []
            if not keys:
                continue
            q = str(keys[0]).strip()
            if not q:
                continue
            top_queries.append({
                "query": q,
                "impressions": int(float(row.get("impressions", 0) or 0)),
                "clicks": int(float(row.get("clicks", 0) or 0)),
                "ctr_pct": round(float(row.get("ctr", 0) or 0) * 100, 2),
                "position": round(float(row.get("position", 0) or 0), 2),
            })
            for t in _extract_terms(q):
                query_terms[t] += 1

        missing_terms = [t for t, _ in query_terms.most_common(12) if t not in _extract_terms(page_url)][:6]
        reasons = []
        actions = []
        priority_score = 0.0

        if 4 <= pos <= 20 and impr >= 150:
            reasons.append("Pozisyon 4-20 araliginda ve yuksek gorunurlukte.")
            actions.append("Sayfayi query niyetine gore yeniden yapilandirip ilk bolume net deger onerisi ekleyin.")
            priority_score += 28
        if ctr < site_ctr * 0.75 and impr >= 120:
            reasons.append("Site ortalamasina gore CTR dusuk.")
            actions.append("Title/meta varyantlarini test edip snippet'i daha net fayda odakli yazin.")
            priority_score += 34
        if click_delta_pct <= -20:
            reasons.append("Onceki doneme gore click kaybi var.")
            actions.append("Son 30 gunluk teknik/content degisikliklerini kontrol edip kayip queryler icin revizyon yapin.")
            priority_score += 24
        if missing_terms:
            reasons.append("Query kapsami dar, konu/entite bosluklari var.")
            actions.append("Eksik terimler icin H2/H3 bolumleri ve FAQ alt basliklari ekleyin: " + ", ".join(missing_terms[:4]))
            priority_score += 18

        if not reasons:
            continue
        priority_score = min(100.0, round(priority_score + min(14.0, impr / 120), 2))
        priority = "High" if priority_score >= 70 else "Medium" if priority_score >= 45 else "Low"
        suggestions.append({
            "page": page_url,
            "priority": priority,
            "priority_score": priority_score,
            "metrics": {
                "clicks": int(round(clicks)),
                "impressions": int(round(impr)),
                "ctr_pct": round(ctr * 100, 2),
                "position": round(pos, 2),
                "click_delta_pct": round(click_delta_pct, 2),
            },
            "reasons": reasons[:3],
            "actions": actions[:3],
            "missing_terms": missing_terms,
            "top_queries": top_queries[:8],
        })

    suggestions.sort(key=lambda x: x["priority_score"], reverse=True)
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {
            "current": {"start": start_day.isoformat(), "end": end_day.isoformat()},
            "baseline": {"start": prev_start.isoformat(), "end": prev_end.isoformat()},
        },
        "site_ctr_pct": round(site_ctr * 100, 2),
        "items": suggestions[:top_pages],
    }


@app.get("/sites/{site_id}/keywords/cannibalization")
def keyword_cannibalization_endpoint(
    site_id: str,
    days: int = Query(30, ge=1, le=120),
    min_impressions: int = Query(50, ge=1, le=10000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)
    try:
        rows = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["query", "page"],
            row_limit=25000,
            db=db,
            user_id=user.id,
        )
    except HTTPException as e:
        if e.status_code in (401, 403):
            raise HTTPException(
                status_code=403,
                detail="Secili site icin GSC erisimi yok. Siteyi bu Google hesabiyla Search Console'da yetkilendirin."
            )
        raise
    query_map = {}
    for row in rows:
        keys = row.get("keys") or []
        if len(keys) < 2:
            continue
        q = str(keys[0]).strip().lower()
        p = str(keys[1]).strip()
        if not q or not p:
            continue
        item = query_map.setdefault(q, {"impressions": 0.0, "clicks": 0.0, "pages": {}})
        imp = float(row.get("impressions", 0) or 0)
        clk = float(row.get("clicks", 0) or 0)
        item["impressions"] += imp
        item["clicks"] += clk
        p_item = item["pages"].setdefault(p, {"impressions": 0.0, "clicks": 0.0, "position_sum": 0.0, "rows": 0})
        p_item["impressions"] += imp
        p_item["clicks"] += clk
        p_item["position_sum"] += float(row.get("position", 0) or 0)
        p_item["rows"] += 1

    cannibalized = []
    for query, data in query_map.items():
        if data["impressions"] < min_impressions:
            continue
        pages = []
        for page_url, p_data in data["pages"].items():
            avg_pos = (p_data["position_sum"] / p_data["rows"]) if p_data["rows"] else 0.0
            pages.append({
                "page": page_url,
                "impressions": round(p_data["impressions"], 2),
                "clicks": round(p_data["clicks"], 2),
                "avg_position": round(avg_pos, 2),
            })
        if len(pages) < 2:
            continue
        pages = sorted(pages, key=lambda x: x["impressions"], reverse=True)
        top_share = pages[0]["impressions"] / data["impressions"] if data["impressions"] > 0 else 0
        if top_share < 0.85:
            cannibalized.append({
                "query": query,
                "total_impressions": round(data["impressions"], 2),
                "total_clicks": round(data["clicks"], 2),
                "page_count": len(pages),
                "dominance_pct": round(top_share * 100, 2),
                "pages": pages[:8],
                "recommendation": "Ana niyeti tasiyan tek URL belirleyip digerlerini internal link/canonical/icerik ayrismasi ile netlestirin.",
            })
    cannibalized.sort(key=lambda x: (-x["total_impressions"], x["dominance_pct"]))
    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "count": len(cannibalized),
        "queries": cannibalized[:200],
    }


@app.post("/sites/{site_id}/seo/change-log")
def add_seo_change_log(
    site_id: str,
    payload: SeoChangeLogIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    changed_at = _parse_iso_dt_or_none(payload.changed_at) or datetime.now(timezone.utc)
    row = SeoChangeLog(
        site_id=site_id,
        change_type=(payload.change_type or "other").strip().lower(),
        title=(payload.title or "").strip() or "Unnamed change",
        description=(payload.description or "").strip(),
        page_url=(payload.page_url or "").strip(),
        impact_scope=(payload.impact_scope or "site").strip().lower(),
        changed_at=changed_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "site_id": row.site_id, "title": row.title, "changed_at": row.changed_at.isoformat()}


@app.get("/sites/{site_id}/seo/change-log")
def list_seo_change_logs(
    site_id: str,
    days: int = Query(30, ge=1, le=365),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(SeoChangeLog)
        .filter(SeoChangeLog.site_id == site_id, SeoChangeLog.changed_at >= since)
        .order_by(SeoChangeLog.changed_at.desc())
        .all()
    )
    return {
        "site_id": site_id,
        "days": days,
        "items": [
            {
                "id": r.id,
                "change_type": r.change_type,
                "title": r.title,
                "description": r.description or "",
                "page_url": r.page_url or "",
                "impact_scope": r.impact_scope or "site",
                "changed_at": r.changed_at.isoformat() if r.changed_at else None,
            }
            for r in rows
        ],
    }


@app.post("/sites/{site_id}/ctr-tests")
def create_ctr_test(
    site_id: str,
    payload: CtrExperimentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    row = CtrExperiment(
        site_id=site_id,
        page_url=(payload.page_url or "").strip(),
        variant_name=(payload.variant_name or "").strip() or "Variant A",
        title_variant=(payload.title_variant or "").strip(),
        meta_variant=(payload.meta_variant or "").strip(),
        hypothesis=(payload.hypothesis or "").strip(),
        status=(payload.status or "running").strip().lower(),
        started_at=_parse_iso_dt_or_none(payload.started_at) or datetime.now(timezone.utc),
        ended_at=_parse_iso_dt_or_none(payload.ended_at),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "site_id": row.site_id, "page_url": row.page_url, "status": row.status}


@app.get("/sites/{site_id}/ctr-tests")
def list_ctr_tests(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    rows = db.query(CtrExperiment).filter(CtrExperiment.site_id == site_id).order_by(CtrExperiment.created_at.desc()).all()
    out = []
    for r in rows:
        metrics = (
            db.query(CtrExperimentMetric)
            .filter(CtrExperimentMetric.experiment_id == r.id)
            .order_by(CtrExperimentMetric.snapshot_date.asc())
            .all()
        )
        baseline = metrics[0] if metrics else None
        latest = metrics[-1] if metrics else None
        uplift = 0.0
        if baseline and latest and baseline.ctr > 0:
            uplift = ((latest.ctr - baseline.ctr) / baseline.ctr) * 100
        out.append({
            "id": r.id,
            "page_url": r.page_url,
            "variant_name": r.variant_name,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "samples": len(metrics),
            "baseline_ctr_pct": round((baseline.ctr * 100), 2) if baseline else None,
            "latest_ctr_pct": round((latest.ctr * 100), 2) if latest else None,
            "ctr_uplift_pct": round(uplift, 2),
        })
    return {"site_id": site_id, "tests": out}


@app.post("/sites/{site_id}/ctr-tests/{test_id}/snapshot")
def add_ctr_test_snapshot(
    site_id: str,
    test_id: str,
    payload: CtrSnapshotIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    test = db.query(CtrExperiment).filter(CtrExperiment.id == test_id, CtrExperiment.site_id == site_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="CTR test bulunamadi")
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")

    rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=payload.start_date,
        end_date=payload.end_date,
        dimensions=["page"],
        row_limit=25000,
        dimension_filter_groups=[{"filters": [{"dimension": "page", "operator": "equals", "expression": test.page_url}]}],
        db=db,
        user_id=user.id,
    )
    clicks = sum(float(r.get("clicks", 0) or 0) for r in rows)
    impressions = sum(float(r.get("impressions", 0) or 0) for r in rows)
    ctr = (clicks / impressions) if impressions > 0 else 0.0
    pos_list = [float(r.get("position", 0) or 0) for r in rows if (r.get("position", 0) or 0) > 0]
    avg_pos = (sum(pos_list) / len(pos_list)) if pos_list else 0.0

    snap = CtrExperimentMetric(
        experiment_id=test.id,
        snapshot_date=datetime.now(timezone.utc),
        clicks=clicks,
        impressions=impressions,
        ctr=ctr,
        position=avg_pos,
    )
    db.add(snap)
    db.commit()
    return {
        "site_id": site_id,
        "test_id": test_id,
        "clicks": round(clicks, 2),
        "impressions": round(impressions, 2),
        "ctr_pct": round(ctr * 100, 2),
        "position": round(avg_pos, 2),
    }


@app.post("/sites/{site_id}/technical/crawl")
def technical_crawl_endpoint(
    site_id: str,
    payload: CrawlRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    urls = payload.urls[:] if payload.urls else []
    if not urls:
        default_url = site.gsc_property_url or ("https://" + site.domain.strip("/"))
        urls = [default_url]
    timeout_sec = max(3, min(30, int(payload.timeout_sec or 12)))

    results = []
    for raw_url in urls[:50]:
        url = str(raw_url).strip()
        if not url:
            continue
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")
        row = {"url": url, "ok": False}
        if not _is_public_http_url(url):
            row.update({"status_code": None, "issues": ["Gecersiz veya guvensiz URL (local/private adres engellendi)"]})
            results.append(row)
            continue
        if not _is_allowed_site_url(url, site.domain):
            row.update({"status_code": None, "issues": ["Sadece secili site domainine ait URL'ler taranabilir"]})
            results.append(row)
            continue
        try:
            resp = requests.get(url, timeout=timeout_sec, allow_redirects=False, headers={"User-Agent": "GSC-Radar/1.0"})
            html = resp.text or ""
            title = _extract_title(html)
            description = _extract_meta_content(html, "description")
            canonical = _extract_canonical(html)
            h1_count = len(re.findall(r"<h1\\b", html, flags=re.IGNORECASE))
            row.update({
                "ok": 200 <= resp.status_code < 400,
                "status_code": resp.status_code,
                "final_url": resp.url,
                "title_length": len(title),
                "description_length": len(description),
                "canonical": canonical,
                "has_noindex": _is_noindex(html),
                "h1_count": h1_count,
                "issues": [],
            })
            if 300 <= resp.status_code < 400:
                row["issues"].append("Redirect tespit edildi (guvenlik icin takip edilmiyor)")
            if resp.status_code >= 400:
                row["issues"].append("HTTP hata kodu")
            if len(title) < 20 or len(title) > 65:
                row["issues"].append("Title uzunlugu ideal aralikta degil (20-65)")
            if len(description) < 80 or len(description) > 170:
                row["issues"].append("Meta description uzunlugu ideal aralikta degil (80-170)")
            if h1_count != 1:
                row["issues"].append("H1 sayisi ideal degil (1 olmali)")
            if row["has_noindex"]:
                row["issues"].append("Noindex etiketi tespit edildi")
            if canonical and canonical.rstrip("/") != resp.url.rstrip("/"):
                row["issues"].append("Canonical farkli URL'e isaret ediyor")
        except Exception as e:
            row.update({"status_code": None, "issues": [f"Crawl hatasi: {str(e)}"]})
        results.append(row)
    return {"site_id": site_id, "crawled": len(results), "results": results}


@app.get("/sites/{site_id}/internal-link/suggestions")
def internal_link_suggestions_endpoint(
    site_id: str,
    days: int = Query(28, ge=1, le=120),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")
    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    try:
        query_page_rows = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["query", "page"],
            row_limit=25000,
            db=db,
            user_id=user.id,
        )
    except HTTPException as e:
        if e.status_code in (401, 403):
            raise HTTPException(
                status_code=403,
                detail="Secili site icin GSC erisimi yok. Siteyi bu Google hesabiyla Search Console'da yetkilendirin."
            )
        raise
    if not query_page_rows:
        return {"site_id": site_id, "count": 0, "suggestions": [], "note": "Yeterli query-page verisi yok"}

    # Aggregate query-page metrikleri
    qp = {}
    page_totals = {}
    for r in query_page_rows:
        keys = r.get("keys") or []
        if len(keys) < 2:
            continue
        q = str(keys[0]).strip().lower()
        p = str(keys[1]).strip()
        if not q or not p:
            continue
        impr = float(r.get("impressions", 0) or 0)
        clk = float(r.get("clicks", 0) or 0)
        pos = float(r.get("position", 0) or 0)
        if impr <= 0:
            continue

        key = (q, p)
        item = qp.setdefault(key, {"impressions": 0.0, "clicks": 0.0, "weighted_pos_sum": 0.0})
        item["impressions"] += impr
        item["clicks"] += clk
        item["weighted_pos_sum"] += pos * impr

        pt = page_totals.setdefault(p, {"impressions": 0.0, "clicks": 0.0, "weighted_pos_sum": 0.0})
        pt["impressions"] += impr
        pt["clicks"] += clk
        pt["weighted_pos_sum"] += pos * impr

    if not page_totals:
        return {"site_id": site_id, "count": 0, "suggestions": [], "note": "Sayfa bazli veri bulunamadi"}

    # Query -> page listesi
    query_to_pages = {}
    page_to_queries = {}
    for (q, p), m in qp.items():
        avg_pos = (m["weighted_pos_sum"] / m["impressions"]) if m["impressions"] > 0 else 0.0
        q_item = {
            "query": q,
            "page": p,
            "impressions": m["impressions"],
            "clicks": m["clicks"],
            "position": avg_pos,
        }
        query_to_pages.setdefault(q, []).append(q_item)
        page_to_queries.setdefault(p, []).append(q_item)

    brand_token = (site.domain or "").split(".")[0].strip().lower()

    # Hedef URL: pozisyonu 4-20 olan ve anlamli impresyon alan sayfalar
    target_pages = []
    for p, m in page_totals.items():
        avg_pos = (m["weighted_pos_sum"] / m["impressions"]) if m["impressions"] > 0 else 0.0
        if m["impressions"] >= 80 and 4 <= avg_pos <= 20:
            target_pages.append({
                "page": p,
                "impressions": m["impressions"],
                "clicks": m["clicks"],
                "position": avg_pos,
            })
    target_pages.sort(key=lambda x: (x["position"], -x["impressions"]))

    suggestions = []
    used_edges = set()

    for tgt in target_pages[:35]:
        tgt_page = tgt["page"]
        target_queries = sorted(page_to_queries.get(tgt_page, []), key=lambda x: x["impressions"], reverse=True)

        picked_for_target = 0
        for tq in target_queries:
            q = tq["query"]
            if brand_token and brand_token in q:
                continue
            word_count = len([w for w in q.split(" ") if w.strip()])
            if word_count < 2 or word_count > 7:
                continue
            if tq["impressions"] < 20 or tq["position"] > 25:
                continue

            same_query_pages = query_to_pages.get(q, [])
            better_sources = [
                sp for sp in same_query_pages
                if sp["page"] != tgt_page
                and sp["position"] <= max(8.0, tq["position"] - 0.3)
                and sp["impressions"] >= 30
            ]
            if not better_sources:
                continue

            better_sources.sort(key=lambda x: (x["position"], -x["impressions"]))
            src = better_sources[0]

            edge = (src["page"], tgt_page, q)
            if edge in used_edges:
                continue
            used_edges.add(edge)

            confidence = 0.4
            if (tq["position"] - src["position"]) >= 4:
                confidence += 0.25
            if tq["impressions"] >= 100:
                confidence += 0.2
            if src["impressions"] >= 120:
                confidence += 0.15
            confidence = min(0.95, round(confidence, 2))

            anchor = q[:70].strip()
            suggestions.append({
                "from_page": src["page"],
                "to_page": tgt_page,
                "suggested_anchor": anchor,
                "anchor_type": "exact_or_close_query",
                "reason": (
                    f"'{q}' sorgusunda kaynak URL daha iyi sirada "
                    f"({round(src['position'],2)}) ve hedef URL firsat pozisyonunda "
                    f"({round(tq['position'],2)})."
                ),
                "evidence": {
                    "query": q,
                    "source_position": round(src["position"], 2),
                    "target_position": round(tq["position"], 2),
                    "source_impressions": int(src["impressions"]),
                    "target_impressions": int(tq["impressions"]),
                },
                "confidence": confidence,
            })

            picked_for_target += 1
            if picked_for_target >= 3:
                break

        if len(suggestions) >= 200:
            break

    return {
        "site_id": site_id,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "count": len(suggestions),
        "suggestions": suggestions[:200],
    }


@app.get("/sites/{site_id}/segments/report")
def segment_report_endpoint(
    site_id: str,
    days: int = Query(30, ge=1, le=120),
    brand_terms: str = Query(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")
    brand_list = [b.strip().lower() for b in brand_terms.split(",") if b.strip()]
    if not brand_list and site.domain:
        core = site.domain.split(".")[0].lower()
        brand_list = [core]

    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    try:
        by_query_device = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["query", "device"],
            row_limit=25000,
            db=db,
            user_id=user.id,
        )
        by_country = fetch_gsc_rows(
            site_url=site.gsc_property_url,
            start_date=start_day.isoformat(),
            end_date=end_day.isoformat(),
            dimensions=["country"],
            row_limit=25000,
            db=db,
            user_id=user.id,
        )
    except HTTPException as e:
        if e.status_code in (401, 403):
            raise HTTPException(
                status_code=403,
                detail="Secili site icin GSC erisimi yok. Siteyi bu Google hesabiyla Search Console'da yetkilendirin."
            )
        raise

    branded = {"clicks": 0.0, "impressions": 0.0}
    non_branded = {"clicks": 0.0, "impressions": 0.0}
    devices = {}
    for r in by_query_device:
        keys = r.get("keys") or []
        if len(keys) < 2:
            continue
        query = str(keys[0]).strip().lower()
        device = str(keys[1]).strip().lower()
        clicks = float(r.get("clicks", 0) or 0)
        impr = float(r.get("impressions", 0) or 0)
        is_brand = any(b in query for b in brand_list)
        if is_brand:
            branded["clicks"] += clicks
            branded["impressions"] += impr
        else:
            non_branded["clicks"] += clicks
            non_branded["impressions"] += impr
        d = devices.setdefault(device, {"clicks": 0.0, "impressions": 0.0})
        d["clicks"] += clicks
        d["impressions"] += impr

    countries = []
    for r in by_country:
        keys = r.get("keys") or []
        if not keys:
            continue
        c = str(keys[0]).strip().upper()
        countries.append({
            "country": c,
            "clicks": round(float(r.get("clicks", 0) or 0), 2),
            "impressions": round(float(r.get("impressions", 0) or 0), 2),
            "ctr_pct": round(float((r.get("ctr", 0) or 0) * 100), 2),
        })
    countries.sort(key=lambda x: x["impressions"], reverse=True)

    def pack_seg(data):
        ctr = (data["clicks"] / data["impressions"]) if data["impressions"] > 0 else 0.0
        return {
            "clicks": round(data["clicks"], 2),
            "impressions": round(data["impressions"], 2),
            "ctr_pct": round(ctr * 100, 2),
        }

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "brand_terms_used": brand_list,
        "segments": {
            "branded": pack_seg(branded),
            "non_branded": pack_seg(non_branded),
        },
        "device_breakdown": [
            {"device": k, **pack_seg(v)}
            for k, v in sorted(devices.items(), key=lambda x: x[1]["impressions"], reverse=True)
        ],
        "country_breakdown": countries[:50],
    }


@app.get("/sites/{site_id}/growth/channel-compare")
def growth_channel_compare_endpoint(
    site_id: str,
    ga4_property_id: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=120),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    resolved_property_id, resolution_mode = _resolve_ga4_property_id(
        site=site,
        user=user,
        db=db,
        provided_property_id=ga4_property_id,
    )
    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    rows = fetch_ga4_rows(
        property_id=resolved_property_id,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["sessionDefaultChannelGroup"],
        metrics=["sessions", "engagedSessions", "conversions", "totalRevenue"],
        db=db,
        user_id=user.id,
        row_limit=200,
    )
    source_rows = fetch_ga4_rows(
        property_id=resolved_property_id,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["sessionSourceMedium"],
        metrics=["sessions", "engagedSessions", "conversions", "totalRevenue"],
        db=db,
        user_id=user.id,
        row_limit=1000,
    )

    wanted = ("Organic Search", "Paid Search", "Direct", "Referral")
    buckets = {
        k: {"channel": k, "sessions": 0.0, "engaged_sessions": 0.0, "conversions": 0.0, "revenue": 0.0}
        for k in wanted
    }
    buckets["Other"] = {"channel": "Other", "sessions": 0.0, "engaged_sessions": 0.0, "conversions": 0.0, "revenue": 0.0}

    for r in rows:
        dims = r.get("dimensions") or []
        mets = r.get("metrics") or []
        ch = (dims[0] if dims else "").strip() or "Other"
        tgt = buckets[ch] if ch in buckets else buckets["Other"]
        tgt["sessions"] += float(mets[0] or 0) if len(mets) > 0 else 0.0
        tgt["engaged_sessions"] += float(mets[1] or 0) if len(mets) > 1 else 0.0
        tgt["conversions"] += float(mets[2] or 0) if len(mets) > 2 else 0.0
        tgt["revenue"] += float(mets[3] or 0) if len(mets) > 3 else 0.0

    ordered = [buckets[k] for k in wanted] + [buckets["Other"]]
    total_sessions = sum(x["sessions"] for x in ordered)
    total_conversions = sum(x["conversions"] for x in ordered)
    total_revenue = sum(x["revenue"] for x in ordered)

    for x in ordered:
        sess = x["sessions"]
        x["session_share_pct"] = round((sess / total_sessions * 100), 2) if total_sessions > 0 else 0.0
        x["engagement_rate_pct"] = round((x["engaged_sessions"] / sess * 100), 2) if sess > 0 else 0.0
        x["conversion_rate_pct"] = round((x["conversions"] / sess * 100), 2) if sess > 0 else 0.0
        x["sessions"] = int(round(x["sessions"]))
        x["engaged_sessions"] = int(round(x["engaged_sessions"]))
        x["conversions"] = round(x["conversions"], 2)
        x["revenue"] = round(x["revenue"], 2)

    top_sources = []
    for r in source_rows:
        dims = r.get("dimensions") or []
        mets = r.get("metrics") or []
        source = (dims[0] if dims else "").strip() or "(not set)"
        sessions = float(mets[0] or 0) if len(mets) > 0 else 0.0
        engaged = float(mets[1] or 0) if len(mets) > 1 else 0.0
        conversions = float(mets[2] or 0) if len(mets) > 2 else 0.0
        revenue = float(mets[3] or 0) if len(mets) > 3 else 0.0
        top_sources.append({
            "source_medium": source,
            "sessions": int(round(sessions)),
            "session_share_pct": round((sessions / total_sessions * 100), 2) if total_sessions > 0 else 0.0,
            "engagement_rate_pct": round((engaged / sessions * 100), 2) if sessions > 0 else 0.0,
            "conversion_rate_pct": round((conversions / sessions * 100), 2) if sessions > 0 else 0.0,
            "conversions": round(conversions, 2),
            "revenue": round(revenue, 2),
        })
    top_sources.sort(key=lambda x: x["sessions"], reverse=True)

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "ga4_property_id": resolved_property_id,
        "ga4_resolution_mode": resolution_mode,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "totals": {
            "sessions": int(round(total_sessions)),
            "conversions": round(total_conversions, 2),
            "revenue": round(total_revenue, 2),
        },
        "channels": ordered,
        "top_sources": top_sources[:25],
    }


@app.get("/sites/{site_id}/growth/opportunity-score")
def growth_opportunity_score_endpoint(
    site_id: str,
    ga4_property_id: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=120),
    min_impressions: int = Query(50, ge=1, le=100000),
    limit: int = Query(50, ge=5, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    if not site.gsc_property_url:
        raise HTTPException(status_code=400, detail="Site icin gsc_property_url tanimli degil")
    resolved_property_id, resolution_mode = _resolve_ga4_property_id(
        site=site,
        user=user,
        db=db,
        provided_property_id=ga4_property_id,
    )

    end_day = datetime.now(timezone.utc).date() - timedelta(days=1)
    start_day = end_day - timedelta(days=days - 1)

    gsc_rows = fetch_gsc_rows(
        site_url=site.gsc_property_url,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["page"],
        row_limit=25000,
        db=db,
        user_id=user.id,
    )

    ga_rows = fetch_ga4_rows(
        property_id=resolved_property_id,
        start_date=start_day.isoformat(),
        end_date=end_day.isoformat(),
        dimensions=["landingPagePlusQueryString"],
        metrics=["sessions", "engagedSessions", "conversions", "totalRevenue"],
        db=db,
        user_id=user.id,
        row_limit=25000,
    )

    ga_map = {}
    for r in ga_rows:
        dims = r.get("dimensions") or []
        mets = r.get("metrics") or []
        path = _url_to_path(dims[0] if dims else "")
        row = ga_map.setdefault(path, {"sessions": 0.0, "engaged_sessions": 0.0, "conversions": 0.0, "revenue": 0.0})
        row["sessions"] += float(mets[0] or 0) if len(mets) > 0 else 0.0
        row["engaged_sessions"] += float(mets[1] or 0) if len(mets) > 1 else 0.0
        row["conversions"] += float(mets[2] or 0) if len(mets) > 2 else 0.0
        row["revenue"] += float(mets[3] or 0) if len(mets) > 3 else 0.0

    pages = []
    for r in gsc_rows:
        keys = r.get("keys") or []
        if not keys:
            continue
        page_url = str(keys[0]).strip()
        if not page_url:
            continue
        impressions = float(r.get("impressions", 0) or 0)
        if impressions < min_impressions:
            continue
        clicks = float(r.get("clicks", 0) or 0)
        ctr = float(r.get("ctr", 0) or 0)
        position = float(r.get("position", 0) or 0)
        path = _url_to_path(page_url)
        ga = ga_map.get(path, {"sessions": 0.0, "engaged_sessions": 0.0, "conversions": 0.0, "revenue": 0.0})
        sessions = float(ga["sessions"] or 0)
        conversions = float(ga["conversions"] or 0)
        engaged = float(ga["engaged_sessions"] or 0)
        conv_rate = (conversions / sessions) if sessions > 0 else 0.0
        engagement_rate = (engaged / sessions) if sessions > 0 else 0.0
        pages.append({
            "page": page_url,
            "path": path,
            "impressions": impressions,
            "clicks": clicks,
            "ctr_pct": round(ctr * 100, 2),
            "position": round(position, 2),
            "sessions": int(round(sessions)),
            "conversions": round(conversions, 2),
            "engagement_rate_pct": round(engagement_rate * 100, 2),
            "conversion_rate_pct": round(conv_rate * 100, 2),
            "revenue": round(float(ga["revenue"] or 0), 2),
            "_ctr": ctr,
            "_conv_rate": conv_rate,
        })

    if not pages:
        return {
            "site_id": site_id,
            "site_domain": site.domain,
            "ga4_property_id": resolved_property_id,
            "ga4_resolution_mode": resolution_mode,
            "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
            "count": 0,
            "items": [],
            "benchmarks": {"avg_ctr_pct": 0.0, "avg_conversion_rate_pct": 0.0},
        }

    max_impressions = max(p["impressions"] for p in pages) or 1.0
    avg_ctr = sum((p["_ctr"] * p["impressions"]) for p in pages) / sum(p["impressions"] for p in pages)
    conv_samples = [p["_conv_rate"] for p in pages if p["sessions"] >= 20]
    conv_baseline = _median(conv_samples) if conv_samples else 0.02
    conv_baseline = max(conv_baseline, 0.002)

    for p in pages:
        visibility_norm = p["impressions"] / max_impressions
        ctr_gap = max(0.0, avg_ctr - p["_ctr"])
        ctr_gap_norm = min(1.0, ctr_gap / max(avg_ctr, 0.001))
        conv_weak_norm = 1.0 - min(1.0, (p["_conv_rate"] / conv_baseline))
        score = (0.45 * visibility_norm) + (0.35 * ctr_gap_norm) + (0.20 * conv_weak_norm)
        p["opportunity_score"] = round(score * 100, 2)
        if p["opportunity_score"] >= 70:
            p["priority"] = "high"
        elif p["opportunity_score"] >= 45:
            p["priority"] = "medium"
        else:
            p["priority"] = "low"

        notes = []
        if ctr_gap_norm > 0.4:
            notes.append("CTR gelistirme potansiyeli yuksek")
        if conv_weak_norm > 0.5 and p["sessions"] > 0:
            notes.append("Donusum orani benchmarkin altinda")
        if visibility_norm > 0.5:
            notes.append("Yuksek gorunurluk nedeniyle etkisi buyuk")
        p["recommendation"] = "; ".join(notes) if notes else "Sayfa performansi genel olarak dengeli."
        del p["_ctr"]
        del p["_conv_rate"]

    pages.sort(key=lambda x: x["opportunity_score"], reverse=True)

    return {
        "site_id": site_id,
        "site_domain": site.domain,
        "ga4_property_id": resolved_property_id,
        "ga4_resolution_mode": resolution_mode,
        "period": {"start": start_day.isoformat(), "end": end_day.isoformat()},
        "count": len(pages),
        "benchmarks": {
            "avg_ctr_pct": round(avg_ctr * 100, 2),
            "avg_conversion_rate_pct": round(conv_baseline * 100, 2),
        },
        "items": pages[:limit],
    }


@app.post("/sites/{site_id}/backlinks/watchlist")
def set_backlink_watchlist(
    site_id: str,
    payload: BacklinkWatchConfigIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    cleaned_webhook = (payload.webhook_url or "").strip()
    if cleaned_webhook and not _is_safe_webhook_url(cleaned_webhook):
        raise HTTPException(
            status_code=400,
            detail="Webhook URL gecersiz. Public bir HTTPS endpoint kullanin (localhost/private IP engelli)."
        )
    row = db.query(BacklinkWatchConfig).filter(BacklinkWatchConfig.site_id == site_id).first()
    if not row:
        row = BacklinkWatchConfig(site_id=site_id)
        db.add(row)
    row.webhook_url = cleaned_webhook
    row.notify_new = bool(payload.notify_new)
    row.notify_lost = bool(payload.notify_lost)
    row.notify_toxic = bool(payload.notify_toxic)
    row.enabled = bool(payload.enabled)
    db.commit()
    return {
        "site_id": site_id,
        "enabled": row.enabled,
        "notify_new": row.notify_new,
        "notify_lost": row.notify_lost,
        "notify_toxic": row.notify_toxic,
    }


@app.post("/sites/{site_id}/backlinks/watchlist/check")
def run_backlink_watchlist_check(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    cfg = db.query(BacklinkWatchConfig).filter(BacklinkWatchConfig.site_id == site_id).first()
    if not cfg or not cfg.enabled:
        return {"site_id": site_id, "status": "disabled"}

    overview = backlink_overview_endpoint(site_id=site_id, toxic_limit=50, user=user, db=db)
    payload = {
        "site_id": site_id,
        "site_domain": site.domain,
        "summary": overview.get("summary", {}),
        "new_backlinks": overview.get("new_backlinks", [])[:25] if cfg.notify_new else [],
        "lost_backlinks": overview.get("lost_backlinks", [])[:25] if cfg.notify_lost else [],
        "toxic_backlinks": overview.get("toxic_backlinks", [])[:25] if cfg.notify_toxic else [],
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    _send_webhook(cfg.webhook_url or "", payload)
    return {"site_id": site_id, "status": "sent", "payload_preview": payload}


@app.post("/sites/{site_id}/pdf/templates")
def create_pdf_template(
    site_id: str,
    payload: PdfTemplateIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    row = PdfReportTemplate(
        site_id=site_id,
        name=(payload.name or "").strip() or "Custom Template",
        theme=(payload.theme or "agency").strip().lower(),
        include_sections=",".join([s.strip().lower() for s in payload.include_sections if s.strip()]),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "site_id": row.site_id, "name": row.name, "theme": row.theme}


@app.get("/sites/{site_id}/pdf/templates")
def list_pdf_templates(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    rows = db.query(PdfReportTemplate).filter(PdfReportTemplate.site_id == site_id).order_by(PdfReportTemplate.created_at.desc()).all()
    return {
        "site_id": site_id,
        "templates": [
            {
                "id": r.id,
                "name": r.name,
                "theme": r.theme,
                "include_sections": [s for s in (r.include_sections or "").split(",") if s],
            }
            for r in rows
        ],
    }


@app.get("/sites/{site_id}/pdf/report")
def generate_pdf_report(
    site_id: str,
    template_id: Optional[str] = Query(None),
    month: Optional[str] = Query(None),
    format: str = Query("html"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    template = None
    if template_id:
        template = db.query(PdfReportTemplate).filter(PdfReportTemplate.id == template_id, PdfReportTemplate.site_id == site_id).first()
        if not template:
            raise HTTPException(status_code=404, detail="Template bulunamadi")

    report_data = monthly_seo_report_endpoint(
        site_id=site_id,
        month=month,
        top_keywords_limit=50,
        user=user,
        db=db,
    )
    sections = [s for s in ((template.include_sections if template else "overview,alerts,keywords,recommendations").split(",")) if s]
    theme = (template.theme if template else "agency")
    theme_key = str(theme or "agency").strip().lower()
    theme_map = {
        "agency": {
            "cover_bg": "linear-gradient(135deg, #0f4c81 0%, #1f2937 100%)",
            "card_bg": "#f8fafc",
            "section_head_bg": "#f1f5f9",
            "body_bg": "#ffffff",
            "text": "#0f172a",
            "muted": "#475569",
            "border": "#dbe3ee",
        },
        "minimal": {
            "cover_bg": "linear-gradient(135deg, #334155 0%, #475569 100%)",
            "card_bg": "#ffffff",
            "section_head_bg": "#f8fafc",
            "body_bg": "#ffffff",
            "text": "#111827",
            "muted": "#6b7280",
            "border": "#e5e7eb",
        },
        "enterprise": {
            "cover_bg": "linear-gradient(135deg, #0b1220 0%, #0f172a 45%, #1d4ed8 100%)",
            "card_bg": "#eef2ff",
            "section_head_bg": "#e0e7ff",
            "body_bg": "#ffffff",
            "text": "#0b1220",
            "muted": "#334155",
            "border": "#c7d2fe",
        },
    }
    t = theme_map.get(theme_key, theme_map["agency"])
    title = f"{site.domain} - SEO Report ({report_data['period']['month']})"
    current = report_data.get("metrics", {}).get("current", {})
    delta = report_data.get("metrics", {}).get("delta_pct", {})
    health = report_data.get("health", {})
    alerts = report_data.get("alerts", {})
    keywords = report_data.get("keywords", {})
    recommendations = report_data.get("recommendations", [])
    top_keywords = keywords.get("top_keywords", [])[:15]
    recent_alerts = alerts.get("recent", [])[:12]

    def pct(v):
        return f"{round(float(v or 0), 2)}%"

    def badge_for_delta(v):
        x = float(v or 0)
        cls = "up" if x > 0 else "down" if x < 0 else "flat"
        sign = "+" if x > 0 else ""
        return f"<span class='delta {cls}'>{sign}{round(x,2)}%</span>"

    keyword_rows_html = "".join([
        "<tr>"
        f"<td>{escape(str(k.get('keyword','-')))}</td>"
        f"<td>{round(float(k.get('position',0) or 0),2)}</td>"
        f"<td>{int(k.get('clicks',0) or 0)}</td>"
        f"<td>{int(k.get('impressions',0) or 0)}</td>"
        f"<td>{pct(k.get('ctr',0))}</td>"
        "</tr>"
        for k in top_keywords
    ]) or "<tr><td colspan='5'>Veri bulunamadi</td></tr>"

    alert_rows_html = "".join([
        "<tr>"
        f"<td>{escape(str(a.get('type','-')))}</td>"
        f"<td>{int(a.get('severity',0) or 0)}</td>"
        f"<td>{escape(str(a.get('metric','-')))}</td>"
        f"<td>{round(float(a.get('delta_pct',0) or 0),2)}%</td>"
        f"<td>{escape(str(a.get('reason','-')))}</td>"
        "</tr>"
        for a in recent_alerts
    ]) or "<tr><td colspan='5'>Alert bulunamadi</td></tr>"

    rec_html = "".join([f"<li>{escape(str(r))}</li>" for r in recommendations]) or "<li>Oneri bulunamadi</li>"
    health_score = float(health.get("last_score", 0) or 0)
    health_bar = max(0, min(100, int(round(health_score))))

    html = f"""
    <html>
    <head>
      <meta charset='utf-8'>
      <title>{escape(title)}</title>
      <style>
        @page {{ size: A4; margin: 18mm 14mm; }}
        body {{ font-family: 'Inter', sans-serif; color: {t['text']}; margin:0; background:{t['body_bg']}; }}
        .cover {{
          border-radius: 16px; padding: 24px; margin-bottom: 16px;
          background: {t['cover_bg']}; color:#fff;
        }}
        .cover h1 {{ margin: 0 0 8px; font-size: 28px; }}
        .cover .meta {{ font-size: 13px; opacity: 0.92; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }}
        .kpi {{
          border: 1px solid {t['border']}; border-radius: 12px; padding: 12px; background: {t['card_bg']};
        }}
        .kpi .k {{ font-size: 11px; color: {t['muted']}; text-transform: uppercase; letter-spacing: .5px; }}
        .kpi .v {{ font-size: 22px; font-weight: 700; margin-top: 6px; }}
        .delta {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
        .delta.up {{ background:#dcfce7; color:#166534; }}
        .delta.down {{ background:#fee2e2; color:#991b1b; }}
        .delta.flat {{ background:#e2e8f0; color:#334155; }}
        .section {{ border:1px solid {t['border']}; border-radius: 12px; margin: 10px 0; overflow:hidden; }}
        .section .head {{ background:{t['section_head_bg']}; padding:10px 12px; font-weight:700; }}
        .section .body {{ padding: 12px; }}
        .bar-wrap {{ background:#e2e8f0; border-radius:999px; height:10px; overflow:hidden; }}
        .bar {{ height:10px; background: linear-gradient(90deg, #ef4444 0%, #f59e0b 45%, #22c55e 100%); width:{health_bar}%; }}
        table {{ width:100%; border-collapse: collapse; font-size: 12px; }}
        th, td {{ border-bottom:1px solid {t['border']}; padding:8px; text-align:left; vertical-align:top; }}
        th {{ background:{t['card_bg']}; font-size:11px; text-transform:uppercase; color:{t['muted']}; }}
        ul {{ margin: 0; padding-left: 18px; }}
        .foot {{ margin-top: 12px; font-size: 11px; color:{t['muted']}; }}
      </style>
    </head>
    <body>
      <div class='cover'>
        <h1>{escape(site.domain)} SEO Performance Report</h1>
        <div class='meta'>Period: {escape(report_data['period']['start_date'])} - {escape(report_data['period']['end_date'])} | Theme: {escape(theme)} | Sections: {escape(", ".join(sections))}</div>
      </div>

      <div class='kpi-grid'>
        <div class='kpi'>
          <div class='k'>Visibility Index</div>
          <div class='v'>{round(float(report_data.get('visibility_index', 0) or 0),2)}</div>
        </div>
        <div class='kpi'>
          <div class='k'>Clicks</div>
          <div class='v'>{int(current.get('clicks',0) or 0)}</div>
          {badge_for_delta(delta.get('clicks',0))}
        </div>
        <div class='kpi'>
          <div class='k'>Impressions</div>
          <div class='v'>{int(current.get('impressions',0) or 0)}</div>
          {badge_for_delta(delta.get('impressions',0))}
        </div>
        <div class='kpi'>
          <div class='k'>CTR</div>
          <div class='v'>{pct((float(current.get('ctr',0) or 0)*100))}</div>
          {badge_for_delta(delta.get('ctr',0))}
        </div>
      </div>

      <div class='section'>
        <div class='head'>Health Snapshot</div>
        <div class='body'>
          <div style='display:flex; justify-content:space-between; margin-bottom:8px; font-size:12px;'>
            <span>Score: <strong>{health_score}</strong></span>
            <span>Min/Max: {health.get('min_score',0)} / {health.get('max_score',0)}</span>
            <span>Trend Delta: {health.get('trend_delta',0)}</span>
          </div>
          <div class='bar-wrap'><div class='bar'></div></div>
        </div>
      </div>

      <div class='section'>
        <div class='head'>Top Keywords</div>
        <div class='body'>
          <table>
            <thead><tr><th>Keyword</th><th>Position</th><th>Clicks</th><th>Impressions</th><th>CTR</th></tr></thead>
            <tbody>{keyword_rows_html}</tbody>
          </table>
        </div>
      </div>

      <div class='section'>
        <div class='head'>Alert Summary</div>
        <div class='body'>
          <div style='display:flex; gap:16px; margin-bottom:10px; font-size:12px;'>
            <span><strong>Total:</strong> {alerts.get('total',0)}</span>
            <span><strong>Critical:</strong> {alerts.get('critical',0)}</span>
            <span><strong>Warning:</strong> {alerts.get('warning',0)}</span>
          </div>
          <table>
            <thead><tr><th>Type</th><th>Severity</th><th>Metric</th><th>Delta</th><th>Reason</th></tr></thead>
            <tbody>{alert_rows_html}</tbody>
          </table>
        </div>
      </div>

      <div class='section'>
        <div class='head'>Executive Recommendations</div>
        <div class='body'><ul>{rec_html}</ul></div>
      </div>

      <div class='foot'>Generated by GSC Radar | {escape(datetime.now(timezone.utc).isoformat())}</div>
    </body>
    </html>
    """
    if format.lower() == "pdf":
        try:
            from weasyprint import HTML  # type: ignore
            pdf_bytes = HTML(string=html).write_pdf()
            return Response(content=pdf_bytes, media_type="application/pdf", headers={
                "Content-Disposition": f"attachment; filename=seo-report-{site_id}.pdf"
            })
        except Exception:
            raise HTTPException(status_code=501, detail="PDF engine bulunamadi. format=html kullanin.")
    return HTMLResponse(content=html)


@app.post("/sites/{site_id}/kpi/goals")
def create_kpi_goal(
    site_id: str,
    payload: KpiGoalIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    start_dt = _parse_iso_dt_or_none(payload.start_date)
    end_dt = _parse_iso_dt_or_none(payload.end_date)
    if not start_dt or not end_dt or end_dt <= start_dt:
        raise HTTPException(status_code=400, detail="start_date ve end_date gecersiz")
    row = KpiGoal(
        site_id=site_id,
        metric=(payload.metric or "").strip().lower(),
        target_value=float(payload.target_value),
        start_date=start_dt,
        end_date=end_dt,
        note=(payload.note or "").strip(),
        is_active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "metric": row.metric, "target_value": row.target_value}


@app.get("/sites/{site_id}/kpi/dashboard")
def kpi_dashboard(
    site_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = get_site_owned(site_id, user, db)
    goals = db.query(KpiGoal).filter(KpiGoal.site_id == site_id, KpiGoal.is_active == True).all()  # noqa: E712
    now = datetime.now(timezone.utc)
    out = []
    for g in goals:
        start = ensure_utc(g.start_date).date()
        end = ensure_utc(g.end_date).date()
        metric_data = {"clicks": 0, "impressions": 0, "ctr": 0.0, "position": 0.0}
        if site.gsc_property_url:
            try:
                metric_data = fetch_gsc_summary(
                    site_url=site.gsc_property_url,
                    start_date=start.isoformat(),
                    end_date=min(end, now.date() - timedelta(days=1)).isoformat(),
                    db=db,
                    user_id=user.id,
                )
            except Exception:
                pass
        current = float(metric_data.get(g.metric, 0.0))
        if g.metric == "ctr":
            current = current * 100
        total_days = max(1, (end - start).days + 1)
        elapsed_days = min(total_days, max(1, (min(now.date(), end) - start).days + 1))
        expected = (g.target_value / total_days) * elapsed_days
        progress = (current / g.target_value * 100) if g.target_value > 0 else 0.0
        pace = (current / expected * 100) if expected > 0 else 0.0
        out.append({
            "goal_id": g.id,
            "metric": g.metric,
            "target_value": round(g.target_value, 2),
            "current_value": round(current, 2),
            "progress_pct": round(progress, 2),
            "pace_vs_plan_pct": round(pace, 2),
            "is_risk": pace < 80,
            "note": g.note or "",
            "period": {"start": start.isoformat(), "end": end.isoformat()},
        })
    return {"site_id": site_id, "site_domain": site.domain, "goals": out}


@app.post("/sites/{site_id}/jobs/daily-health/config")
def set_daily_health_job_config(
    site_id: str,
    payload: DailyHealthConfigIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_site_owned(site_id, user, db)
    row = db.query(DailyHealthJobConfig).filter(DailyHealthJobConfig.site_id == site_id).first()
    if not row:
        row = DailyHealthJobConfig(site_id=site_id)
        db.add(row)
    row.enabled = bool(payload.enabled)
    row.run_hour_utc = int(payload.run_hour_utc)
    db.commit()
    return {"site_id": site_id, "enabled": row.enabled, "run_hour_utc": row.run_hour_utc}


@app.post("/jobs/health/daily/run")
def run_daily_health_jobs_manual(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sites = db.query(Site).filter(Site.user_id == user.id).all()
    results = []
    for s in sites:
        try:
            results.append(_run_single_health_snapshot(s, user, db, days=1))
        except Exception as e:
            db.rollback()
            results.append({"site_id": s.id, "status": "error", "error": str(e)})
    return {"user_id": user.id, "count": len(results), "results": results}
