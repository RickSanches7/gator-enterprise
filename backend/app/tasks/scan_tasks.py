"""
GATOR PRO Enterprise — Celery Scan Pipeline
Full 10-module orchestrator with Telegram alerts and PDF reports.
"""

import json
import time
import traceback
from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.scan   import Scan, ScanStatus
from app.models.event  import ScanEvent
from app.models.finding import Finding

from app.modules.recon.engine      import ReconEngine
from app.modules.portscan.engine   import PortScanEngine
from app.modules.portscan.analyzer import analyze_ports
from app.modules.webscan.engine    import WebScanEngine
from app.modules.apisec.engine     import APISecEngine
from app.modules.auth_test.engine  import AuthTestEngine
from app.modules.ssl_test.engine   import SSLTestEngine
from app.modules.bizlogic.engine   import BizLogicEngine
from app.modules.ad_test.engine    import ADTestEngine
from app.modules.pci_swift.engine  import PCISWIFTEngine
from app.modules.network.engine    import NetworkEngine
from app.tasks.report_generator    import ReportGenerator
from app.tasks.telegram_bot        import get_bot


def push_event(db, scan_id, event_type, level, message, data=None):
    try:
        ev = ScanEvent(scan_id=scan_id, event_type=event_type,
            level=level, message=message[:500], data=data or {})
        db.add(ev); db.commit()
    except Exception: db.rollback()


def _save_findings(db, scan_id, findings, target):
    bot = get_bot(); saved = 0
    for f in findings:
        try:
            if db.query(Finding).filter(Finding.scan_id==scan_id,
                    Finding.title==f.get("title","")[:255],
                    Finding.host==f.get("host","")[:255]).first():
                continue
            db.add(Finding(
                scan_id=scan_id, severity=f.get("severity","info"),
                cvss=f.get("cvss",0.0), cvss_vector=f.get("cvss_vector",""),
                title=f.get("title","")[:255], description=f.get("description",""),
                recommendation=f.get("recommendation",""), evidence=f.get("evidence",""),
                poc=f.get("poc",""), owasp_category=f.get("owasp_category",""),
                pci_dss_req=f.get("pci_dss_req",[]), swift_control=f.get("swift_control",[]),
                cwe_ids=f.get("cwe_ids",[]), host=f.get("host","")[:255],
                url=f.get("url","")[:1000], port=f.get("port"),
                parameter=f.get("parameter","")[:255], payload=f.get("payload","")[:2000],
                tool=f.get("tool","")[:100], category=f.get("category","web"),
            )); db.commit(); saved += 1
            if bot and f.get("cvss",0) >= 7.0:
                bot.alert_critical_finding(f, target, scan_id); time.sleep(0.1)
        except Exception: db.rollback()
    return saved


def _upd(db, scan_id, **kw):
    try:
        s = db.query(Scan).filter(Scan.id==scan_id).first()
        if s:
            for k,v in kw.items(): setattr(s,k,v)
            db.commit()
    except Exception: db.rollback()


@shared_task(bind=True, name="run_full_scan", max_retries=0,
             time_limit=7200, soft_time_limit=6900)
def run_full_scan(self, scan_id: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id==scan_id).first()
        if not scan: return {"error":"not found"}
        target = scan.target; opts = scan.options or {}; scan_type = scan.scan_type or "full"

        _upd(db,scan_id,status=ScanStatus.RUNNING,
             started_at=datetime.now(timezone.utc),progress=0)
        bot = get_bot()
        if bot: bot.alert_scan_started(target, scan_id, scan_type)
        push_event(db,scan_id,"scan_start","info",f"GATOR PRO scan started: {target}",{})

        all_findings=[]; all_results={"target":target,"scan_id":scan_id}

        def prog(pct, msg=""):
            _upd(db,scan_id,progress=pct)
            if msg: push_event(db,scan_id,"progress","info",msg,{"progress":pct})

        def run_module(name, Engine, pct_start, pct_end, scan_types, **engine_kw):
            if scan_type not in scan_types: return {}
            prog(pct_start, f"Module: {name}")
            try:
                eng = Engine(target, scan_id, db, push_event, **engine_kw)
                result = eng.run()
                fs = result.get("findings",[])
                all_findings.extend(fs)
                _save_findings(db, scan_id, fs, target)
                push_event(db,scan_id,"log","ok",f"{name}: {len(fs)} findings",{})
                prog(pct_end)
                return result
            except Exception as e:
                push_event(db,scan_id,"error","err",f"{name} error: {e}",{})
                return {}

        # ── 1. Recon
        recon_r = run_module("Recon & OSINT", ReconEngine, 5, 10,
            ("full","recon","web"), **opts.get("recon",{}))
        if recon_r: all_results["recon"]=recon_r
        if recon_r: _upd(db,scan_id,subdomains_count=len(recon_r.get("subdomains",[])))

        # ── 2. Port Scan
        if scan_type in ("full","network"):
            prog(12,"Module: Port Scan + CVE")
            try:
                ps=PortScanEngine(target,scan_id,db,push_event,**opts.get("portscan",{}))
                ps_data=ps.run(); all_results["port_scan"]=ps_data
                ps_findings=analyze_ports(ps_data,target)
                all_findings.extend(ps_findings)
                _save_findings(db,scan_id,ps_findings,target)
                prog(22)
            except Exception as e:
                push_event(db,scan_id,"error","err",f"PortScan error: {e}",{})

        # ── 3. Web Scan
        web_r  = run_module("Web Scanner",   WebScanEngine,  24, 38, ("full","web"), **opts.get("webscan",{}))
        # ── 4. API Sec
        api_r  = run_module("API Security",  APISecEngine,   40, 50, ("full","api","web"), **opts.get("apisec",{}))
        # ── 5. Auth
        auth_r = run_module("Auth Testing",  AuthTestEngine, 52, 60, ("full","auth","web"), **opts.get("auth",{}))

        # ── 6. SSL
        if scan_type in ("full","ssl","web"):
            prog(62,"Module: SSL/TLS Analysis")
            try:
                ssl_eng=SSLTestEngine(target,scan_id,db,push_event,**opts.get("ssl",{}))
                ssl_data=ssl_eng.run()
                all_results["ssl"]=ssl_data.get("ssl_results",{})
                all_findings.extend(ssl_data.get("findings",[]))
                _save_findings(db,scan_id,ssl_data.get("findings",[]),target)
                prog(68)
            except Exception as e:
                push_event(db,scan_id,"error","err",f"SSL error: {e}",{})

        # ── 7-10
        run_module("Business Logic", BizLogicEngine, 70, 75, ("full","bizlogic"), **opts.get("bizlogic",{}))
        run_module("Active Directory", ADTestEngine, 77, 82, ("full","ad"),
            domain=opts.get("ad",{}).get("domain"),
            username=opts.get("ad",{}).get("username"),
            password=opts.get("ad",{}).get("password"))

        # ── 9. PCI/SWIFT
        if scan_type in ("full","compliance"):
            prog(84,"Module: PCI DSS + SWIFT CSCF")
            try:
                pci=PCISWIFTEngine(target,scan_id,db,push_event,scan_results=all_results)
                pci_data=pci.run()
                all_results["pci_results"]=pci_data.get("pci_results",{})
                all_results["swift_results"]=pci_data.get("swift_results",{})
                all_findings.extend(pci_data.get("findings",[]))
                _save_findings(db,scan_id,pci_data.get("findings",[]),target)
                _upd(db,scan_id,pci_score=pci_data.get("pci_score",0))
                prog(92)
            except Exception as e:
                push_event(db,scan_id,"error","err",f"PCI error: {e}",{})

        run_module("Network Security", NetworkEngine, 93, 97, ("full","network"), **opts.get("network",{}))

        # ── Reports
        prog(98,"Generating reports...")
        import os; report_dir="/app/reports"; os.makedirs(report_dir, exist_ok=True)
        report_paths={}
        try:
            rdata={**all_results,"findings":all_findings,"target":target}
            for lang in ["ru","en"]:
                rg=ReportGenerator(rdata, language=lang,
                    client_name=opts.get("client_name","Client"),
                    output_dir=report_dir)
                report_paths[lang]=rg.generate_all()
                push_event(db,scan_id,"report","ok",f"Report [{lang.upper()}] ready",report_paths[lang])
            all_results["reports"]=report_paths
            if bot and report_paths.get("ru",{}).get("pdf"):
                bot.send_report_ready(target, "", report_paths["ru"]["pdf"])
        except Exception as e:
            push_event(db,scan_id,"error","warn",f"Report error: {e}",{})

        # ── Finalize
        sev={s:len([f for f in all_findings if f.get("severity")==s])
             for s in ("critical","high","medium","low","info")}
        scan=db.query(Scan).filter(Scan.id==scan_id).first()
        ended=datetime.now(timezone.utc)
        dur=int((ended-scan.started_at).total_seconds()) if scan and scan.started_at else 0
        _upd(db,scan_id, status=ScanStatus.COMPLETED, finished_at=ended, progress=100,
             findings_count=len(all_findings), critical_count=sev["critical"],
             high_count=sev["high"], medium_count=sev["medium"],
             low_count=sev["low"], raw_results=all_results)
        push_event(db,scan_id,"scan_complete","ok",
            f"Scan complete: {len(all_findings)} findings (C:{sev['critical']} H:{sev['high']})",
            {"duration":dur, **sev})
        if bot: bot.alert_scan_complete({"target":target,"id":scan_id,
            "findings":all_findings,"duration_seconds":dur})
        return {"scan_id":scan_id,"status":"completed",
                "findings":len(all_findings),"duration_s":dur}

    except Exception as e:
        push_event(db,scan_id,"error","err",f"Fatal: {e}",{"tb":traceback.format_exc()[-500:]})
        _upd(db,scan_id,status=ScanStatus.FAILED,error_msg=str(e)[:500])
        if get_bot(): get_bot().send(f"GATOR PRO scan FAILED: {scan_id}\n{str(e)[:200]}")
        raise
    finally: db.close()


@shared_task(name="generate_report_task")
def generate_report_task(scan_id, language="ru"):
    db=SessionLocal()
    try:
        scan=db.query(Scan).filter(Scan.id==scan_id).first()
        if not scan: return {"error":"not found"}
        findings=[row.__dict__ for row in db.query(Finding).filter(Finding.scan_id==scan_id).all()]
        rg=ReportGenerator({**scan.raw_results,"findings":findings,"target":scan.target},
            language=language, client_name=(scan.options or {}).get("client_name","Client"),
            output_dir="/app/reports")
        paths=rg.generate_all()
        push_event(db,scan_id,"report","ok",f"Report [{language.upper()}] generated",paths)
        return paths
    finally: db.close()


@shared_task(name="daily_digest")
def daily_digest():
    bot=get_bot()
    if not bot: return
    db=SessionLocal()
    try:
        from datetime import timedelta
        cutoff=datetime.now(timezone.utc)-timedelta(hours=24)
        scans=db.query(Scan).filter(Scan.created_at>=cutoff).all()
        if not scans: bot.send("GATOR PRO Daily: No scans in 24h"); return
        lines=["<b>GATOR PRO Daily Digest</b>",f"Scans: {len(scans)}",""]
        for s in scans:
            icon={"completed":"✅","running":"🔄","failed":"❌"}.get(
                s.status.value if hasattr(s.status,"value") else str(s.status),"❓")
            lines.append(f"{icon} {s.target} C:{s.critical_count or 0} H:{s.high_count or 0}")
        bot.send("\n".join(lines))
    finally: db.close()
