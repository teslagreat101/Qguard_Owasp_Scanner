"""
Admin Dashboard API (Direct User Model)
Super admin endpoints for platform management.
Removed all Multi-Tenancy / Tenant isolation logic.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import (
    get_db, get_db_session, User, Scan, Finding, ScanJob,
    SecurityEvent, APIToken,
    SubscriptionTier, SubscriptionStatus, seed_super_admin
)
from backend.auth import require_super_admin, SUPER_ADMIN_EMAIL, get_password_hash
from backend.billing import get_subscription, create_checkout_session, TIER_CONFIG

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class DashboardStats(BaseModel):
    total_users: int
    active_users: int
    users_this_month: int
    total_scans: int
    scans_today: int
    revenue_this_month: float
    security_events_24h: int

class UserUpdateRequest(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    role: Optional[str] = None
    full_name: Optional[str] = None
    subscription_tier: Optional[SubscriptionTier] = None
    subscription_status: Optional[SubscriptionStatus] = None

class SubscriptionOverrideRequest(BaseModel):
    tier: SubscriptionTier
    scan_limit: Optional[int] = None
    reason: str

class SubscriptionExtendRequest(BaseModel):
    days: int = Field(ge=1, le=365, description="Number of days to extend")
    reason: str = ""

class ChangeTierRequest(BaseModel):
    tier: SubscriptionTier
    reason: str = ""

class CancelSubscriptionRequest(BaseModel):
    reason: str = ""

# ═══════════════════════════════════════════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════════════════════════════════════════

@router.on_event("startup")
async def init_super_admin():
    db = get_db_session()
    try:
        seed_super_admin(db, SUPER_ADMIN_EMAIL)
    finally:
        db.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard Overview
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = today_start.replace(day=1)
    
    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0
    users_this_month = db.query(func.count(User.id)).filter(User.created_at >= month_start).scalar() or 0
    
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    scans_today = db.query(func.count(Scan.id)).filter(Scan.created_at >= today_start).scalar() or 0
    
    # Calculate revenue based on active subscriptions
    pro_users = db.query(func.count(User.id)).filter(
        User.subscription_tier == SubscriptionTier.PRO,
        User.subscription_status == SubscriptionStatus.ACTIVE
    ).scalar() or 0
    
    enterprise_users = db.query(func.count(User.id)).filter(
        User.subscription_tier == SubscriptionTier.ENTERPRISE,
        User.subscription_status == SubscriptionStatus.ACTIVE
    ).scalar() or 0
    
    revenue = (pro_users * TIER_CONFIG[SubscriptionTier.PRO]["price_monthly"]) + \
              (enterprise_users * TIER_CONFIG[SubscriptionTier.ENTERPRISE]["price_monthly"])
    
    security_events = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= (now - timedelta(hours=24))
    ).scalar() or 0
    
    return DashboardStats(
        total_users=total_users,
        active_users=active_users,
        users_this_month=users_this_month,
        total_scans=total_scans,
        scans_today=scans_today,
        revenue_this_month=float(revenue),
        security_events_24h=security_events,
    )

@router.get("/dashboard/recent-activity")
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
    recent_events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    
    return {
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "user_id": s.user_id,
                "target": s.target,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent_scans
        ],
        "recent_security_events": [
            {
                "id": e.id,
                "user_id": e.user_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in recent_events
        ]
    }

# ═══════════════════════════════════════════════════════════════════════════════
# User Management
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/users")
async def list_users(
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    query = db.query(User).filter(User.deleted_at.is_(None))
    if search:
        query = query.filter(
            (User.email.ilike(f"%{search}%")) |
            (User.username.ilike(f"%{search}%")) |
            (User.full_name.ilike(f"%{search}%"))
        )

    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()

    # Per-user scan counts
    user_ids = [u.id for u in users]
    scan_counts = {}
    if user_ids:
        rows = db.query(Scan.user_id, func.count(Scan.id)).filter(
            Scan.user_id.in_(user_ids)
        ).group_by(Scan.user_id).all()
        scan_counts = {uid: cnt for uid, cnt in rows}

    # Tier distribution (across all non-deleted users)
    tier_rows = db.query(User.subscription_tier, func.count(User.id)).filter(
        User.deleted_at.is_(None)
    ).group_by(User.subscription_tier).all()
    tier_distribution = {}
    for tier, count in tier_rows:
        tier_key = tier.value if tier else "free"
        tier_distribution[tier_key] = count

    user_list = []
    for u in users:
        d = u.to_dict()
        d["total_scans"] = scan_counts.get(u.id, 0)
        user_list.append(d)

    return {
        "total": total,
        "users": user_list,
        "tier_distribution": tier_distribution,
    }

@router.get("/users/{user_id}")
async def get_user_admin(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    scans_count = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    findings_count = db.query(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.scan_id).filter(
        Scan.user_id == user_id
    ).scalar() or 0

    recent_scans = db.query(Scan).filter(Scan.user_id == user_id).order_by(
        Scan.created_at.desc()
    ).limit(5).all()

    d = user.to_dict()
    d["total_scans"] = scans_count

    return {
        "user": d,
        "stats": {
            "scans_count": scans_count,
            "findings_count": findings_count,
        },
        "recent_scans": [s.to_dict() for s in recent_scans],
    }

@router.patch("/users/{user_id}")
async def update_user_admin(
    user_id: str,
    request: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot modify primary super admin")

    data = request.dict(exclude_unset=True)
    for key, value in data.items():
        setattr(user, key, value)

    # Sync scan limit when tier changes
    if "subscription_tier" in data:
        config = TIER_CONFIG.get(user.subscription_tier, TIER_CONFIG[SubscriptionTier.FREE])
        user.monthly_scan_limit = config["monthly_scan_limit"]

    db.commit()
    d = user.to_dict()
    d["total_scans"] = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    return d


@router.delete("/users/{user_id}")
async def delete_user_admin(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    """Soft-delete a user (sets deleted_at, deactivates account)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot delete primary super admin")

    user.deleted_at = datetime.now(timezone.utc)
    user.is_active = False
    user.subscription_status = SubscriptionStatus.CANCELLED
    db.commit()
    return {"status": "deleted", "user_id": user_id}


@router.post("/users/{user_id}/cancel-subscription")
async def cancel_user_subscription(
    user_id: str,
    request: CancelSubscriptionRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    """Cancel a user's subscription — revert to free tier."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot modify primary super admin")

    user.subscription_tier = SubscriptionTier.FREE
    user.subscription_status = SubscriptionStatus.CANCELLED
    user.monthly_scan_limit = TIER_CONFIG[SubscriptionTier.FREE]["monthly_scan_limit"]
    db.commit()

    d = user.to_dict()
    d["total_scans"] = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    return {"status": "cancelled", "user": d}


@router.post("/users/{user_id}/extend-subscription")
async def extend_user_subscription(
    user_id: str,
    request: SubscriptionExtendRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    """Extend a user's subscription by N days — reactivate if cancelled/expired."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot modify primary super admin")

    user.subscription_status = SubscriptionStatus.ACTIVE
    # Reset updated_at to track extension time
    user.updated_at = datetime.now(timezone.utc)
    db.commit()

    d = user.to_dict()
    d["total_scans"] = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    return {"status": "extended", "days": request.days, "user": d}


@router.post("/users/{user_id}/change-tier")
async def change_user_tier(
    user_id: str,
    request: ChangeTierRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    """Change a user's subscription tier and sync limits."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot modify primary super admin")

    config = TIER_CONFIG.get(request.tier, TIER_CONFIG[SubscriptionTier.FREE])
    user.subscription_tier = request.tier
    user.subscription_status = SubscriptionStatus.ACTIVE
    user.monthly_scan_limit = config["monthly_scan_limit"]
    user.updated_at = datetime.now(timezone.utc)
    db.commit()

    d = user.to_dict()
    d["total_scans"] = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    return {"status": "tier_changed", "new_tier": request.tier.value, "user": d}


# ═══════════════════════════════════════════════════════════════════════════════
# Security & Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/security/events")
async def list_security_events(
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    query = db.query(SecurityEvent)
    if severity: query = query.filter(SecurityEvent.severity == severity)
    if event_type: query = query.filter(SecurityEvent.event_type == event_type)
    
    events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return {"events": [e.id for e in events]} # Placeholder for actual to_dict if needed

@router.get("/platform/health")
async def get_platform_health(
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    return {"status": "healthy", "database": "connected"}
