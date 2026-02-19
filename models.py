from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone
import uuid


Base = declarative_base()


# --------------------------------------------------
# SITES (İzlenen GSC Property'ler)
# --------------------------------------------------
class Site(Base):
    __tablename__ = "sites"

    id = Column(
        String, 
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    domain = Column(String, index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=True)
    ga4_property_id = Column(String, index=True, nullable=True)

    # GSC'deki gerçek property URL (https://example.com/)
    gsc_property_url = Column(String, index=True, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# ALERTS (Radar çıktıları)
# --------------------------------------------------
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)

    severity = Column(Integer)          # 1=info, 2=warning, 3=critical
    confidence = Column(String)         # LOW / MEDIUM / HIGH
    alert_type = Column(String)         # CLICK_DROP, IMPRESSION_DROP, vb.
    metric = Column(String)             # clicks, impressions, ctr, position

    current_value = Column(Float)
    baseline_value = Column(Float)
    delta_pct = Column(Float)

    reason = Column(Text)
    recommendation = Column(Text)

    # DEDUPE
    dedupe_key = Column(String, unique=True, index=True)
    window_days = Column(Integer)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# GOOGLE OAUTH TOKEN
# --------------------------------------------------
class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    provider = Column(String, primary_key=True, default="google")
    email = Column(String, index=True, nullable=True)

    refresh_token = Column(Text, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# USERS (uyelik sistemi)
# --------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False, default="User")
    password_hash = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    method = Column(String, nullable=False)
    path = Column(String, index=True, nullable=False)
    query_string = Column(Text, nullable=True, default="")
    status_code = Column(Integer, nullable=False, default=200)
    ip_address = Column(String, nullable=True, default="")
    user_agent = Column(Text, nullable=True, default="")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class UserOAuthToken(Base):
    __tablename__ = "user_oauth_tokens"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    provider = Column(String, index=True, nullable=False, default="google")
    email = Column(String, index=True, nullable=True)
    refresh_token = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# DASHBOARD PREFERENCES
# --------------------------------------------------
class DashboardPreference(Base):
    __tablename__ = "dashboard_preferences"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    card_order = Column(Text, nullable=True)    # JSON array string
    hidden_cards = Column(Text, nullable=True)  # JSON array string
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint("user_id", "site_id", name="uq_dashboard_pref_user_site"),
    )


# --------------------------------------------------
# REPORT NOTES
# --------------------------------------------------
class ReportNote(Base):
    __tablename__ = "report_notes"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    month = Column(String, index=True, nullable=False)  # YYYY-MM
    note_type = Column(String, index=True, nullable=False, default="team")
    content = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("idx_report_notes_site_month_created", "site_id", "month", "created_at"),
    )


# --------------------------------------------------
# BACKLINK SNAPSHOTS
# --------------------------------------------------
class BacklinkSnapshot(Base):
    __tablename__ = "backlink_snapshots"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)

    source_url = Column(Text, nullable=False)
    target_url = Column(Text, nullable=False)
    anchor_text = Column(String, nullable=True)

    # 0-100
    domain_authority = Column(Float, nullable=False, default=0.0)
    spam_score = Column(Float, nullable=False, default=0.0)
    is_active = Column(Boolean, nullable=False, default=True)

    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    snapshot_date = Column(DateTime(timezone=True), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("idx_backlink_site_snapshot", "site_id", "snapshot_date"),
    )


# --------------------------------------------------
# BACKLINK WATCHLIST CONFIG
# --------------------------------------------------
class BacklinkWatchConfig(Base):
    __tablename__ = "backlink_watch_configs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False, unique=True)
    webhook_url = Column(Text, nullable=True)
    notify_new = Column(Boolean, nullable=False, default=True)
    notify_lost = Column(Boolean, nullable=False, default=True)
    notify_toxic = Column(Boolean, nullable=False, default=True)
    enabled = Column(Boolean, nullable=False, default=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# SEO CHANGE LOG
# --------------------------------------------------
class SeoChangeLog(Base):
    __tablename__ = "seo_change_logs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    change_type = Column(String, nullable=False)  # deploy/content/redirect/technical/etc.
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    page_url = Column(Text, nullable=True)
    impact_scope = Column(String, nullable=True)  # site/page/section
    changed_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# CTR EXPERIMENTS
# --------------------------------------------------
class CtrExperiment(Base):
    __tablename__ = "ctr_experiments"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    page_url = Column(Text, nullable=False)
    variant_name = Column(String, nullable=False)
    title_variant = Column(Text, nullable=True)
    meta_variant = Column(Text, nullable=True)
    hypothesis = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="running")  # running/paused/completed
    started_at = Column(DateTime(timezone=True), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class CtrExperimentMetric(Base):
    __tablename__ = "ctr_experiment_metrics"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    experiment_id = Column(String, ForeignKey("ctr_experiments.id"), index=True, nullable=False)
    snapshot_date = Column(DateTime(timezone=True), nullable=False)
    clicks = Column(Float, nullable=False, default=0.0)
    impressions = Column(Float, nullable=False, default=0.0)
    ctr = Column(Float, nullable=False, default=0.0)
    position = Column(Float, nullable=False, default=0.0)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("idx_ctr_exp_date", "experiment_id", "snapshot_date"),
    )


# --------------------------------------------------
# KPI GOALS
# --------------------------------------------------
class KpiGoal(Base):
    __tablename__ = "kpi_goals"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    metric = Column(String, nullable=False)  # clicks/impressions/ctr/position/visibility
    target_value = Column(Float, nullable=False)
    start_date = Column(DateTime(timezone=True), nullable=False)
    end_date = Column(DateTime(timezone=True), nullable=False)
    note = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# DAILY HEALTH JOB CONFIG
# --------------------------------------------------
class DailyHealthJobConfig(Base):
    __tablename__ = "daily_health_job_configs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=False)
    run_hour_utc = Column(Integer, nullable=False, default=3)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# PDF REPORT TEMPLATES
# --------------------------------------------------
class PdfReportTemplate(Base):
    __tablename__ = "pdf_report_templates"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    site_id = Column(String, ForeignKey("sites.id"), index=True, nullable=False)
    name = Column(String, nullable=False)
    theme = Column(String, nullable=False, default="agency")
    include_sections = Column(Text, nullable=True)  # comma separated list
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

# --------------------------------------------------
# HEALTH SNAPSHOTS
# --------------------------------------------------
class HealthSnapshot(Base):
    __tablename__ = "health_snapshots"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4())
    )

    site_id = Column(
        String,
        ForeignKey("sites.id"),
        index=True,
        nullable=False
    )

    # Health core
    score = Column(Integer, nullable=False)
    status = Column(String, nullable=False)  # Healthy / Risk / Critical
    alerts_count = Column(Integer, nullable=False, default=0)

    # Metrics
    clicks = Column(Integer, nullable=False, default=0)
    impressions = Column(Integer, nullable=False, default=0)
    ctr = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=False, default=0.0)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------
# KEYWORD SNAPSHOTS
# --------------------------------------------------
class KeywordSnapshot(Base):
    """Keyword'lerin günlük snapshot'ları"""
    __tablename__ = "keyword_snapshots"

    id = Column(
        String, 
        primary_key=True, 
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    
    site_id = Column(
        String, 
        ForeignKey("sites.id"), 
        index=True, 
        nullable=False
    )
    
    keyword = Column(String, index=True, nullable=False)
    
    # GSC Metrikleri
    clicks = Column(Integer, default=0)
    impressions = Column(Integer, default=0)
    ctr = Column(Float, default=0.0)
    position = Column(Float, default=0.0)
    
    # Tarih
    date = Column(DateTime(timezone=True), index=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    
    # Composite index for performance
    __table_args__ = (
        Index('idx_site_keyword_date', 'site_id', 'keyword', 'date'),
    )
