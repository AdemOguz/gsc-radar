"""
GSC Radar - Keyword Tracking Module
Keyword pozisyon takibi, analiz ve raporlama
"""

from sqlalchemy.orm import Session
from models import KeywordSnapshot
from datetime import datetime, timezone
import urllib3
from sqlalchemy.exc import IntegrityError


# SSL warning'lerini kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_keywords_from_gsc(
    site_url: str,
    start_date: str,
    end_date: str,
    db,
    row_limit: int = 100,
    user_id: str = None
):
    from auth import get_refresh_token, refresh_access_token, gsc_headers, GSC_BASE
    from urllib.parse import quote
    import requests

    refresh_token = get_refresh_token(db, user_id=user_id)
    access_token = refresh_access_token(refresh_token)

    encoded_site = quote(site_url, safe="")
    url = f"{GSC_BASE}/sites/{encoded_site}/searchAnalytics/query"

    payload = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": ["query"],
        "rowLimit": row_limit,
        "type": "web",
        "dataState": "all"
    }

    r = requests.post(
        url,
        headers=gsc_headers(access_token),
        json=payload,
        timeout=30,
        verify=False
    )

    if r.status_code != 200:
        from fastapi import HTTPException
        raise HTTPException(status_code=r.status_code, detail=r.text)

    data = r.json()
    return data.get("rows", [])



def save_keyword_snapshots(
    site_id: str,
    keywords_data: list,
    snapshot_date,
    db
):
    saved_count = 0

    for row in keywords_data:
        kw = row.get("keys", [None])[0]
        if not kw:
            continue

        keyword = str(kw).strip()
        if not keyword:
            continue

        snapshot = KeywordSnapshot(
            site_id=site_id,
            keyword=keyword,
            clicks=row.get("clicks", 0),
            impressions=row.get("impressions", 0),
            ctr=row.get("ctr", 0.0),
            position=row.get("position", 0.0),
            date=snapshot_date,
            created_at=datetime.now(timezone.utc)
        )

        try:
            with db.begin_nested():
                db.add(snapshot)
                db.flush()
            saved_count += 1
            print("KEYWORD SAVED:", keyword)
        except IntegrityError:
            print("DUPLICATE SKIPPED:", keyword)
            

    db.commit()
    return saved_count


def get_keyword_history(site_id: str, keyword: str, days: int, db: Session):
    """
    Belirli bir keyword'ün tarihsel verilerini döndürür.
    
    Returns:
        List of snapshots (chronological)
    """
    from datetime import timedelta
    
    since = datetime.now(timezone.utc) - timedelta(days=days)
    
    snapshots = (
        db.query(KeywordSnapshot)
        .filter(
            KeywordSnapshot.site_id == site_id,
            KeywordSnapshot.keyword == keyword,
            KeywordSnapshot.date >= since
        )
        .order_by(KeywordSnapshot.date.asc())
        .all()
    )
    
    return snapshots


def analyze_keyword_trends(site_id: str, db: Session):
    """
    Keyword trendlerini analiz eder.
    
    Returns:
        {
            "top_movers": [...],  # En çok yükselen keyword'ler
            "top_losers": [...],  # En çok düşen keyword'ler
            "opportunities": [...] # Yüksek impression, düşük click
        }
    """
    from datetime import timedelta
    from sqlalchemy import func, desc
    
    # Son 2 gün
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)
    
    # Subquery: Son snapshot
    latest_subq = (
        db.query(
            KeywordSnapshot.keyword,
            KeywordSnapshot.position.label("latest_position"),
            KeywordSnapshot.clicks.label("latest_clicks"),
            KeywordSnapshot.impressions.label("latest_impressions")
        )
        .filter(
            KeywordSnapshot.site_id == site_id,
            func.date(KeywordSnapshot.date) == yesterday
        )
        .subquery()
    )
    
    # Subquery: 7 gün önce
    old_subq = (
        db.query(
            KeywordSnapshot.keyword,
            KeywordSnapshot.position.label("old_position")
        )
        .filter(
            KeywordSnapshot.site_id == site_id,
            func.date(KeywordSnapshot.date) == week_ago
        )
        .subquery()
    )
    
    # Join ve position delta hesapla
    movers = (
        db.query(
            latest_subq.c.keyword,
            latest_subq.c.latest_position,
            old_subq.c.old_position,
            (old_subq.c.old_position - latest_subq.c.latest_position).label("position_change")
        )
        .join(
            old_subq,
            latest_subq.c.keyword == old_subq.c.keyword
        )
        .filter(old_subq.c.old_position.isnot(None))
        .all()
    )
    
    # Top movers (position düştü = sıralama yükseldi)
    top_movers = sorted(
        [m for m in movers if m.position_change > 0],
        key=lambda x: x.position_change,
        reverse=True
    )[:10]
    
    # Top losers (position yükseldi = sıralama düştü)
    top_losers = sorted(
        [m for m in movers if m.position_change < 0],
        key=lambda x: x.position_change
    )[:10]
    
    # Opportunities (yüksek impression, düşük CTR)
    opportunities = (
        db.query(KeywordSnapshot)
        .filter(
            KeywordSnapshot.site_id == site_id,
            func.date(KeywordSnapshot.date) == yesterday,
            KeywordSnapshot.impressions > 100,
            KeywordSnapshot.ctr < 0.02  # %2'den düşük CTR
        )
        .order_by(desc(KeywordSnapshot.impressions))
        .limit(10)
        .all()
    )
    
    return {
        "top_movers": [
            {
                "keyword": m.keyword,
                "current_position": round(m.latest_position, 1),
                "old_position": round(m.old_position, 1),
                "change": round(m.position_change, 1)
            }
            for m in top_movers
        ],
        "top_losers": [
            {
                "keyword": m.keyword,
                "current_position": round(m.latest_position, 1),
                "old_position": round(m.old_position, 1),
                "change": round(m.position_change, 1)
            }
            for m in top_losers
        ],
        "opportunities": [
            {
                "keyword": o.keyword,
                "impressions": o.impressions,
                "clicks": o.clicks,
                "ctr": round(o.ctr * 100, 2),
                "position": round(o.position, 1)
            }
            for o in opportunities
        ]
    }

