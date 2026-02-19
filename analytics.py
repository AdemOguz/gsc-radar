"""
GSC Radar - Analytics & Alert Engine
Trend analizi, alert üretimi ve sayfa performans analizi
"""

from sqlalchemy.orm import Session
from models import Alert, HealthSnapshot, Site
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
import uuid


def analyze_trend(site_id: str, days: int, db: Session) -> Dict:
    """
    Son N gündeki health score trendini analiz eder.
    
    Returns:
        {
            "trend": "improving" | "declining" | "stable",
            "change_pct": float,  # Yüzdelik değişim
            "first_score": float,
            "last_score": float,
            "data_points": int
        }
    """
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
    
    if len(snapshots) < 2:
        return {
            "trend": "insufficient_data",
            "change_pct": 0,
            "first_score": 0,
            "last_score": 0,
            "data_points": len(snapshots)
        }
    
    first_score = snapshots[0].score
    last_score = snapshots[-1].score
    
    # Yüzdelik değişim hesapla
    if first_score > 0:
        change_pct = ((last_score - first_score) / first_score) * 100
    else:
        change_pct = 0
    
    # Trend belirleme
    if change_pct > 5:
        trend = "improving"
    elif change_pct < -5:
        trend = "declining"
    else:
        trend = "stable"
    
    return {
        "trend": trend,
        "change_pct": round(change_pct, 2),
        "first_score": first_score,
        "last_score": last_score,
        "data_points": len(snapshots)
    }


def detect_anomalies(site_id: str, db: Session) -> List[Alert]:
    """
    Son snapshot'ları analiz eder ve anomali (anormal durum) tespit eder.
    
    Kontroller:
    - Ani score düşüşü (>20 puan)
    - Click/impression düşüşü (>30%)
    - CTR düşüşü (>20%)
    - Critical status'e geçiş
    """
    # Son 2 snapshot'ı al
    snapshots = (
        db.query(HealthSnapshot)
        .filter(HealthSnapshot.site_id == site_id)
        .order_by(HealthSnapshot.created_at.desc())
        .limit(10)
        .all()
    )
    
    if len(snapshots) < 2:
        return []
    
    latest = snapshots[0]
    previous = snapshots[1]
    
    alerts = []
    
    # 1. Score düşüşü kontrolü
    score_drop = previous.score - latest.score
    if score_drop > 20:
        alerts.append(create_alert(
            site_id=site_id,
            alert_type="SCORE_DROP",
            severity=3,  # Critical
            metric="score",
            current_value=latest.score,
            baseline_value=previous.score,
            delta_pct=-((score_drop / previous.score) * 100),
            reason=f"Health score {previous.score:.1f}'dan {latest.score:.1f}'a düştü ({score_drop:.1f} puan)",
            recommendation="GSC verileri ve site performansını acil kontrol edin."
        ))
    
    # 2. Click düşüşü kontrolü
    if previous.clicks > 0:
        click_drop_pct = ((previous.clicks - latest.clicks) / previous.clicks) * 100
        if click_drop_pct > 30:
            alerts.append(create_alert(
                site_id=site_id,
                alert_type="CLICK_DROP",
                severity=2,  # Warning
                metric="clicks",
                current_value=latest.clicks,
                baseline_value=previous.clicks,
                delta_pct=-click_drop_pct,
                reason=f"Click sayısı %{click_drop_pct:.1f} düştü ({previous.clicks} → {latest.clicks})",
                recommendation="En çok trafik alan sayfaları kontrol edin. Ranking kayıpları olabilir."
            ))
    
    # 3. Impression düşüşü kontrolü
    if previous.impressions > 0:
        imp_drop_pct = ((previous.impressions - latest.impressions) / previous.impressions) * 100
        if imp_drop_pct > 30:
            alerts.append(create_alert(
                site_id=site_id,
                alert_type="IMPRESSION_DROP",
                severity=2,  # Warning
                metric="impressions",
                current_value=latest.impressions,
                baseline_value=previous.impressions,
                delta_pct=-imp_drop_pct,
                reason=f"Impression sayısı %{imp_drop_pct:.1f} düştü ({previous.impressions} → {latest.impressions})",
                recommendation="Indexleme sorunları veya visibility kaybı olabilir."
            ))
    
    # 4. CTR düşüşü kontrolü
    if previous.ctr > 0:
        ctr_drop_pct = ((previous.ctr - latest.ctr) / previous.ctr) * 100
        if ctr_drop_pct > 20:
            alerts.append(create_alert(
                site_id=site_id,
                alert_type="CTR_DROP",
                severity=1,  # Info
                metric="ctr",
                current_value=latest.ctr,
                baseline_value=previous.ctr,
                delta_pct=-ctr_drop_pct,
                reason=f"CTR %{ctr_drop_pct:.1f} düştü ({previous.ctr:.3f} → {latest.ctr:.3f})",
                recommendation="Meta başlıkları ve açıklamaları optimize edin."
            ))
    
    # 5. Critical duruma geçiş kontrolü
    if latest.status == "Critical" and previous.status != "Critical":
        alerts.append(create_alert(
            site_id=site_id,
            alert_type="STATUS_CRITICAL",
            severity=3,  # Critical
            metric="status",
            current_value=0,
            baseline_value=0,
            delta_pct=0,
            reason=f"Site durumu {previous.status} → Critical'e düştü",
            recommendation="Acil müdahale gerekiyor. Tüm metrikleri kontrol edin."
        ))
    
    return alerts


def create_alert(
    site_id: str,
    alert_type: str,
    severity: int,
    metric: str,
    current_value: float,
    baseline_value: float,
    delta_pct: float,
    reason: str,
    recommendation: str
) -> Alert:
    """
    Alert nesnesi oluşturur (henüz veritabanına kaydetmez).
    """
    # Dedupe key oluştur (aynı alert tekrar oluşmasın)
    dedupe_key = f"{site_id}_{alert_type}_{metric}_{datetime.now(timezone.utc).date()}"
    
    confidence = "HIGH" if abs(delta_pct) > 50 else "MEDIUM" if abs(delta_pct) > 30 else "LOW"
    
    return Alert(
        id=str(uuid.uuid4()),
        site_id=site_id,
        severity=severity,
        confidence=confidence,
        alert_type=alert_type,
        metric=metric,
        current_value=current_value,
        baseline_value=baseline_value,
        delta_pct=delta_pct,
        reason=reason,
        recommendation=recommendation,
        dedupe_key=dedupe_key,
        window_days=7,
        created_at=datetime.now(timezone.utc)
    )


def save_alerts_if_new(alerts: List[Alert], db: Session) -> int:
    """
    Alert listesini veritabanına kaydeder (duplicate kontrolü ile).
    
    Returns:
        Kaydedilen yeni alert sayısı
    """
    new_count = 0
    
    for alert in alerts:
        # Aynı dedupe_key ile alert var mı kontrol et
        existing = db.query(Alert).filter(
            Alert.dedupe_key == alert.dedupe_key
        ).first()
        
        if not existing:
            db.add(alert)
            new_count += 1
    
    if new_count > 0:
        db.commit()
    
    return new_count


def get_page_performance(site_id: str, days: int, db: Session) -> Dict:
    """
    En iyi ve en kötü performans gösteren sayfaları döndürür.
    (Şimdilik placeholder - GSC page data entegrasyonu gerekiyor)
    """
    # TODO: GSC'den sayfa bazlı veri çekilecek
    return {
        "message": "Sayfa performans analizi yakında eklenecek",
        "requires": "GSC page dimension data"
    }
