"""
GATOR PRO — Scans API Router
POST /scans       — start scan
GET  /scans       — list all scans
GET  /scans/{id}  — get scan details
GET  /scans/{id}/events — poll real-time events
POST /scans/{id}/stop  — cancel scan
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional
from datetime import datetime
import uuid
import json
import asyncio

from app.core.database import get_db
from app.core.config import settings
from app.core.logging import logger
from app.models.models import Scan, ScanEvent, Finding

router = APIRouter(prefix="/scans")


# ─── Schemas (inline for simplicity) ────────────────────────
from pydantic import BaseModel, Field
from typing import Any


class ScanCreateRequest(BaseModel):
    target: str = Field(..., description="Domain or IP to scan")
    scan_type: str = Field("full", description="full/recon/portscan/webscan/api/auth/ssl/pci")
    engagement_id: Optional[str] = None
    options: dict = Field(default_factory=dict)


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    stream_url: str
    poll_url: str
    findings_url: str


# ─── Start Scan ───────────────────────────────────────────────
@router.post("", response_model=ScanResponse)
async def create_scan(request: ScanCreateRequest, db: AsyncSession = Depends(get_db)):
    """Start a new scan. Returns scan_id for polling/streaming."""

    target = request.target.strip().rstrip("/")
    if not target:
        raise HTTPException(400, "target is required")

    # Create scan record
    scan = Scan(
        id=uuid.uuid4(),
        target=target,
        scan_type=request.scan_type,
        status="pending",
        options=request.options,
        engagement_id=uuid.UUID(request.engagement_id) if request.engagement_id else None,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    scan_id = str(scan.id)

    # Dispatch to Celery
    from app.tasks.scan_tasks import (
        run_full_scan, run_recon, run_portscan
    )

    task_map = {
        "full": run_full_scan,
        "recon": run_recon,
        "portscan": run_portscan,
    }

    task_fn = task_map.get(request.scan_type, run_full_scan)
    task = task_fn.delay(scan_id, target, request.options)

    # Save celery task id
    scan.celery_task_id = task.id
    await db.commit()

    logger.info("Scan started: {} → {} ({})", scan_id[:8], target, request.scan_type)

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        stream_url=f"/api/v1/scans/{scan_id}/stream",
        poll_url=f"/api/v1/scans/{scan_id}/events",
        findings_url=f"/api/v1/findings?scan_id={scan_id}",
    )


# ─── List Scans ───────────────────────────────────────────────
@router.get("")
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Scan).order_by(desc(Scan.created_at)).limit(limit).offset(offset)
    if status:
        query = query.where(Scan.status == status)
    result = await db.execute(query)
    scans = result.scalars().all()
    return {
        "scans": [
            {
                "id": str(s.id),
                "target": s.target,
                "type": s.scan_type,
                "status": s.status,
                "findings": s.findings_count,
                "critical": s.critical_count,
                "high": s.high_count,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "duration": s.duration_seconds,
            }
            for s in scans
        ],
        "total": len(scans)
    }


# ─── Get Scan ─────────────────────────────────────────────────
@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, uuid.UUID(scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": str(scan.id),
        "target": scan.target,
        "type": scan.scan_type,
        "status": scan.status,
        "options": scan.options,
        "findings_count": scan.findings_count,
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "open_ports": scan.open_ports_count,
        "subdomains": scan.subdomains_count,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_seconds": scan.duration_seconds,
        "error": scan.error_message,
    }


# ─── Poll Events ──────────────────────────────────────────────
@router.get("/{scan_id}/events")
async def poll_events(
    scan_id: str,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Polling endpoint — returns new events since offset."""
    scan = await db.get(Scan, uuid.UUID(scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")

    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == uuid.UUID(scan_id))
        .where(ScanEvent.id > offset)
        .order_by(ScanEvent.id)
        .limit(200)
    )
    events = result.scalars().all()

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "events": [
            {
                "id": e.id,
                "type": e.event_type,
                "level": e.level,
                "msg": e.message,
                "data": e.data,
                "ts": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in events
        ],
        "total_events": len(events),
    }


# ─── SSE Stream ───────────────────────────────────────────────
@router.get("/{scan_id}/stream")
async def stream_events(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Server-Sent Events stream for real-time output."""
    scan = await db.get(Scan, uuid.UUID(scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")

    async def event_generator():
        last_id = 0
        timeout = 0

        while timeout < 3600:  # max 1 hour stream
            # New DB session each iteration
            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(ScanEvent)
                    .where(ScanEvent.scan_id == uuid.UUID(scan_id))
                    .where(ScanEvent.id > last_id)
                    .order_by(ScanEvent.id)
                    .limit(100)
                )
                events = result.scalars().all()

                for e in events:
                    data = json.dumps({
                        "id": e.id,
                        "type": e.event_type,
                        "level": e.level,
                        "msg": e.message,
                        "data": e.data,
                        "ts": e.timestamp.isoformat() if e.timestamp else None,
                    })
                    yield f"data: {data}\n\n"
                    last_id = e.id

                # Check if scan finished
                scan_obj = await session.get(Scan, uuid.UUID(scan_id))
                if scan_obj and scan_obj.status in ["finished", "failed", "cancelled"]:
                    yield f"data: {json.dumps({'type': 'stream_end', 'status': scan_obj.status})}\n\n"
                    return

            await asyncio.sleep(0.5)
            timeout += 0.5

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        }
    )


# ─── Stop Scan ────────────────────────────────────────────────
@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, uuid.UUID(scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.celery_task_id:
        from app.core.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")

    scan.status = "cancelled"
    scan.finished_at = datetime.utcnow()
    await db.commit()

    # Push stop event
    event = ScanEvent(
        scan_id=uuid.UUID(scan_id),
        event_type="log",
        level="warn",
        message="Scan cancelled by user",
    )
    db.add(event)
    await db.commit()

    return {"status": "cancelled", "scan_id": scan_id}
