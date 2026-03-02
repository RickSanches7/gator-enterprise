"""
GATOR PRO — Dashboard API
Statistics, charts data, recent activity
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from datetime import datetime, timedelta

from app.core.database import get_db
from app.models.models import Scan, Finding, Engagement

router = APIRouter(prefix="/dashboard")


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Main dashboard KPIs."""

    # Total scans
    total_scans = await db.scalar(select(func.count(Scan.id)))
    active_scans = await db.scalar(
        select(func.count(Scan.id)).where(Scan.status == "running")
    )

    # Findings by severity
    findings_q = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
    )
    sev_counts = dict(findings_q.all())

    total_findings = sum(sev_counts.values())

    # Recent critical findings (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    new_critical = await db.scalar(
        select(func.count(Finding.id)).where(
            and_(
                Finding.severity == "critical",
                Finding.discovered_at >= week_ago
            )
        )
    )

    # CVSS average
    avg_cvss = await db.scalar(select(func.avg(Finding.cvss_score)))

    # Active engagements
    active_engagements = await db.scalar(
        select(func.count(Engagement.id)).where(Engagement.status == "active")
    )

    return {
        "scans": {
            "total": total_scans or 0,
            "active": active_scans or 0,
            "finished": (total_scans or 0) - (active_scans or 0),
        },
        "findings": {
            "total": total_findings,
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "info": sev_counts.get("info", 0),
            "new_critical_7d": new_critical or 0,
            "avg_cvss": round(float(avg_cvss or 0), 1),
        },
        "engagements": {
            "active": active_engagements or 0,
        }
    }


@router.get("/timeline")
async def get_timeline(days: int = 30, db: AsyncSession = Depends(get_db)):
    """Findings discovered over time for chart."""
    since = datetime.utcnow() - timedelta(days=days)

    result = await db.execute(
        select(
            func.date_trunc("day", Finding.discovered_at).label("day"),
            Finding.severity,
            func.count(Finding.id).label("count")
        )
        .where(Finding.discovered_at >= since)
        .group_by("day", Finding.severity)
        .order_by("day")
    )
    rows = result.all()

    # Group by date
    timeline = {}
    for row in rows:
        day_str = row.day.strftime("%Y-%m-%d") if row.day else "unknown"
        if day_str not in timeline:
            timeline[day_str] = {"date": day_str, "critical": 0, "high": 0, "medium": 0, "low": 0}
        timeline[day_str][row.severity] = row.count

    return {"timeline": list(timeline.values()), "days": days}


@router.get("/top-targets")
async def get_top_targets(limit: int = 10, db: AsyncSession = Depends(get_db)):
    """Most scanned / most vulnerable targets."""
    result = await db.execute(
        select(
            Scan.target,
            func.count(Scan.id).label("scan_count"),
            func.sum(Scan.critical_count).label("total_critical"),
            func.sum(Scan.findings_count).label("total_findings"),
        )
        .group_by(Scan.target)
        .order_by(desc("total_critical"))
        .limit(limit)
    )
    return {
        "targets": [
            {
                "target": r.target,
                "scans": r.scan_count,
                "critical": int(r.total_critical or 0),
                "findings": int(r.total_findings or 0),
            }
            for r in result.all()
        ]
    }


@router.get("/owasp-distribution")
async def get_owasp_distribution(db: AsyncSession = Depends(get_db)):
    """Findings grouped by OWASP Top 10 category."""
    result = await db.execute(
        select(
            Finding.owasp_category,
            func.count(Finding.id).label("count"),
            func.avg(Finding.cvss_score).label("avg_cvss")
        )
        .where(Finding.owasp_category != "")
        .where(Finding.owasp_category.isnot(None))
        .group_by(Finding.owasp_category)
        .order_by(desc("count"))
    )
    return {
        "owasp": [
            {
                "category": r.owasp_category,
                "count": r.count,
                "avg_cvss": round(float(r.avg_cvss or 0), 1)
            }
            for r in result.all()
        ]
    }


@router.get("/recent-findings")
async def get_recent_findings(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Latest findings across all scans."""
    result = await db.execute(
        select(Finding)
        .order_by(desc(Finding.discovered_at))
        .limit(limit)
    )
    findings = result.scalars().all()
    return {
        "findings": [
            {
                "id": str(f.id),
                "severity": f.severity,
                "cvss": f.cvss_score,
                "title": f.title,
                "host": f.host,
                "owasp": f.owasp_category,
                "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
            }
            for f in findings
        ]
    }
