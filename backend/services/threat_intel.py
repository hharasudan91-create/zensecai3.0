"""
ZentraSec Threat Intelligence Service
======================================
Architecture:
    ThreatIntelProvider (abstract base)
        └── LocalDemoProvider  — always available, clearly labeled as DEMO data
        └── VirusTotalProvider — activated when VIRUSTOTAL_API_KEY is set (stub)
        └── AbuseIPDBProvider  — activated when ABUSEIPDB_API_KEY is set (stub)

IOC Types supported: ipv4, domain, url, hash (md5/sha1/sha256)

IMPORTANT: The LocalDemoProvider uses a fixed local dataset.
Data is CLEARLY marked is_simulated=True so it is NEVER presented as live
external intelligence.  External providers (not yet wired) would set
is_simulated=False when returning real feed data.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger("zentrasec.threat_intel")

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique reference (subset relevant to login/network events)
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES = {
    "T1110":   {"id": "T1110",   "name": "Brute Force",                  "tactic": "Credential Access"},
    "T1110.001":{"id":"T1110.001","name":"Password Guessing",             "tactic": "Credential Access"},
    "T1078":   {"id": "T1078",   "name": "Valid Accounts",                "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access"},
    "T1133":   {"id": "T1133",   "name": "External Remote Services",      "tactic": "Initial Access"},
    "T1087":   {"id": "T1087",   "name": "Account Discovery",             "tactic": "Discovery"},
    "T1021":   {"id": "T1021",   "name": "Remote Services",               "tactic": "Lateral Movement"},
    "T1136":   {"id": "T1136",   "name": "Create Account",                "tactic": "Persistence"},
    "T1485":   {"id": "T1485",   "name": "Data Destruction",              "tactic": "Impact"},
    "T1041":   {"id": "T1041",   "name": "Exfiltration Over C2 Channel",  "tactic": "Exfiltration"},
    "T1048":   {"id": "T1048",   "name": "Exfiltration Over Alt Protocol","tactic": "Exfiltration"},
    "T1566":   {"id": "T1566",   "name": "Phishing",                      "tactic": "Initial Access"},
    "T1190":   {"id": "T1190",   "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "T1059":   {"id": "T1059",   "name": "Command and Scripting Interpreter","tactic": "Execution"},
}

# ---------------------------------------------------------------------------
# Local demo IOC dataset — clearly DEMO, is_simulated=True
# ---------------------------------------------------------------------------
_DEMO_IOC_DB: dict[str, dict] = {
    # ---------- Malicious IPs ----------
    "185.220.101.1": {
        "indicator_type": "ipv4",
        "reputation": "MALICIOUS",
        "threat_level": "HIGH",
        "confidence": 0.94,
        "threat_actor": "TorExitRelay-Cluster",
        "campaign": "Anonymous Credential Harvesting",
        "country": "DE",
        "organization": "DigitalOcean LLC",
        "asn": "AS14061",
        "mitre_techniques": ["T1110", "T1110.001", "T1133"],
        "known_target_types": ["Web Applications", "Authentication Portals"],
        "related_indicators": ["185.220.101.2", "185.220.101.47", "brute-scan-net.xyz"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2024-01-10",
        "last_seen": "2026-09-20",
        "tags": ["tor-exit", "credential-stuffing", "brute-force"],
    },
    "45.142.212.100": {
        "indicator_type": "ipv4",
        "reputation": "MALICIOUS",
        "threat_level": "CRITICAL",
        "confidence": 0.97,
        "threat_actor": "APT-SilentPhantom",
        "campaign": "Operation CloudStrike 2026",
        "country": "RU",
        "organization": "Selectel Ltd",
        "asn": "AS49505",
        "mitre_techniques": ["T1078", "T1110", "T1041", "T1059"],
        "known_target_types": ["Financial Institutions", "Government Portals", "Healthcare"],
        "related_indicators": ["45.142.212.101", "silent-phantom.cc", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2025-03-01",
        "last_seen": "2026-10-01",
        "tags": ["apt", "credential-theft", "c2"],
    },
    "198.51.100.7": {
        "indicator_type": "ipv4",
        "reputation": "MALICIOUS",
        "threat_level": "HIGH",
        "confidence": 0.88,
        "threat_actor": "Unknown",
        "campaign": "Credential Spray Campaign",
        "country": "CN",
        "organization": "Shenzhen Tencent Computer Systems",
        "asn": "AS45090",
        "mitre_techniques": ["T1110", "T1110.001"],
        "known_target_types": ["SaaS Portals", "Email Gateways"],
        "related_indicators": ["198.51.100.8"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2025-06-14",
        "last_seen": "2026-08-30",
        "tags": ["credential-spray", "automated"],
    },
    # ---------- Suspicious IPs ----------
    "192.0.2.15": {
        "indicator_type": "ipv4",
        "reputation": "SUSPICIOUS",
        "threat_level": "MEDIUM",
        "confidence": 0.61,
        "threat_actor": "Unknown",
        "campaign": None,
        "country": "US",
        "organization": "IANA Reserved",
        "asn": "AS0",
        "mitre_techniques": ["T1133"],
        "known_target_types": ["Unknown"],
        "related_indicators": [],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2026-07-01",
        "last_seen": "2026-09-15",
        "tags": ["suspicious", "scanning"],
    },
    # ---------- Malicious Domains ----------
    "malicious-login.xyz": {
        "indicator_type": "domain",
        "reputation": "MALICIOUS",
        "threat_level": "CRITICAL",
        "confidence": 0.99,
        "threat_actor": "PhishKit-ProMax",
        "campaign": "Banking Credential Phishing 2026",
        "country": "Unknown",
        "organization": "Namecheap Inc.",
        "asn": None,
        "mitre_techniques": ["T1566", "T1078"],
        "known_target_types": ["Banking Users", "Corporate Employees"],
        "related_indicators": ["185.220.101.1", "phish.malicious-login.xyz"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2026-04-12",
        "last_seen": "2026-09-30",
        "tags": ["phishing", "credential-harvesting"],
    },
    "brute-scan-net.xyz": {
        "indicator_type": "domain",
        "reputation": "MALICIOUS",
        "threat_level": "HIGH",
        "confidence": 0.91,
        "threat_actor": "TorExitRelay-Cluster",
        "campaign": "Anonymous Credential Harvesting",
        "country": "Unknown",
        "organization": "Unknown",
        "asn": None,
        "mitre_techniques": ["T1110", "T1133"],
        "known_target_types": ["Web Applications"],
        "related_indicators": ["185.220.101.1", "185.220.101.2"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2024-08-01",
        "last_seen": "2026-09-10",
        "tags": ["c2", "brute-force"],
    },
    "suspicious-redirect.net": {
        "indicator_type": "domain",
        "reputation": "SUSPICIOUS",
        "threat_level": "MEDIUM",
        "confidence": 0.65,
        "threat_actor": "Unknown",
        "campaign": None,
        "country": "RO",
        "organization": "RCS & RDS SA",
        "asn": "AS8708",
        "mitre_techniques": ["T1566"],
        "known_target_types": ["Unknown"],
        "related_indicators": [],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2026-05-20",
        "last_seen": "2026-09-01",
        "tags": ["suspicious", "redirect"],
    },
    # ---------- Malicious Hashes ----------
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4": {
        "indicator_type": "hash",
        "reputation": "MALICIOUS",
        "threat_level": "CRITICAL",
        "confidence": 0.98,
        "threat_actor": "APT-SilentPhantom",
        "campaign": "Operation CloudStrike 2026",
        "country": None,
        "organization": None,
        "asn": None,
        "mitre_techniques": ["T1059", "T1041"],
        "known_target_types": ["Windows Systems", "Active Directory"],
        "related_indicators": ["45.142.212.100"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2025-03-01",
        "last_seen": "2026-09-28",
        "tags": ["malware", "c2-implant", "powershell"],
    },
    "deadbeefdeadbeefdeadbeefdeadbeef": {
        "indicator_type": "hash",
        "reputation": "MALICIOUS",
        "threat_level": "HIGH",
        "confidence": 0.86,
        "threat_actor": "Unknown",
        "campaign": None,
        "country": None,
        "organization": None,
        "asn": None,
        "mitre_techniques": ["T1059"],
        "known_target_types": ["Linux Servers"],
        "related_indicators": [],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2025-11-15",
        "last_seen": "2026-08-01",
        "tags": ["malware", "dropper"],
    },
    # ---------- Malicious URLs ----------
    "http://malicious-login.xyz/steal.php": {
        "indicator_type": "url",
        "reputation": "MALICIOUS",
        "threat_level": "CRITICAL",
        "confidence": 0.99,
        "threat_actor": "PhishKit-ProMax",
        "campaign": "Banking Credential Phishing 2026",
        "country": "Unknown",
        "organization": None,
        "asn": None,
        "mitre_techniques": ["T1566", "T1078"],
        "known_target_types": ["Banking Users"],
        "related_indicators": ["malicious-login.xyz"],
        "source": "ZentraSec Local Intelligence Feed",
        "first_seen": "2026-04-12",
        "last_seen": "2026-09-30",
        "tags": ["phishing", "credential-harvesting"],
    },
}

# ---------------------------------------------------------------------------
# IOC validation helpers
# ---------------------------------------------------------------------------

def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False


def _is_domain(value: str) -> bool:
    # Simple domain pattern: at least one dot, no slashes, no spaces
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def _is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _is_hash(value: str) -> bool:
    # MD5=32, SHA1=40, SHA256=64 hex chars
    return bool(re.match(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", value))


def detect_ioc_type(value: str) -> Optional[str]:
    """Detect the IOC type for a raw indicator string.

    Returns: 'ipv4' | 'domain' | 'url' | 'hash' | None (invalid)
    """
    v = value.strip()
    if _is_ipv4(v):
        return "ipv4"
    if _is_url(v):
        return "url"
    if _is_hash(v):
        return "hash"
    if _is_domain(v):
        return "domain"
    return None


def validate_ioc(value: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Validate an IOC value.

    Returns (is_valid, ioc_type, error_message).
    """
    if not value or not value.strip():
        return False, None, "IOC value cannot be empty"
    v = value.strip()
    if len(v) > 512:
        return False, None, "IOC value is too long (max 512 characters)"
    ioc_type = detect_ioc_type(v)
    if not ioc_type:
        return False, None, (
            "Unable to identify IOC type. Supported types: IPv4 address, "
            "domain name, URL (http/https), or file hash (MD5/SHA1/SHA256)"
        )
    return True, ioc_type, None


# ---------------------------------------------------------------------------
# Result dataclass (plain dict for JSON serialisation simplicity)
# ---------------------------------------------------------------------------

def _build_result(
    indicator: str,
    indicator_type: str,
    reputation: str,
    threat_level: str,
    confidence: float,
    source: str,
    is_simulated: bool,
    threat_actor: Optional[str] = None,
    campaign: Optional[str] = None,
    country: Optional[str] = None,
    organization: Optional[str] = None,
    asn: Optional[str] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    mitre_techniques: Optional[list] = None,
    known_target_types: Optional[list] = None,
    related_indicators: Optional[list] = None,
    tags: Optional[list] = None,
    threat_score: Optional[float] = None,
) -> dict:
    """Build the canonical TI result dict."""
    # Compute numeric threat score from reputation + confidence
    if threat_score is None:
        rep_score = {"MALICIOUS": 80, "SUSPICIOUS": 50, "CLEAN": 5, "UNKNOWN": 0}.get(reputation, 0)
        threat_score = round(min(100, rep_score + confidence * 20), 1)

    # Expand MITRE technique IDs to full objects
    techniques_expanded = []
    for tid in (mitre_techniques or []):
        tech = MITRE_TECHNIQUES.get(tid)
        if tech:
            techniques_expanded.append(tech)

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation": reputation,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "confidence": round(confidence * 100, 1),  # return as percentage
        "source": source,
        "is_simulated": is_simulated,
        "data_label": "DEMO LOCAL INTELLIGENCE" if is_simulated else "LIVE EXTERNAL INTELLIGENCE",
        "threat_actor": threat_actor or "Unknown",
        "campaign": campaign or None,
        "country": country,
        "organization": organization,
        "asn": asn,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "mitre_techniques": techniques_expanded,
        "known_target_types": known_target_types or [],
        "related_indicators": related_indicators or [],
        "tags": tags or [],
    }


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------

class ThreatIntelProvider(ABC):
    """Abstract base for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> Optional[dict]:
        """Return a TI result dict or None if the IOC is not found/unknown."""
        ...


# ---------------------------------------------------------------------------
# Local Demo Provider — always available
# ---------------------------------------------------------------------------

class LocalDemoProvider(ThreatIntelProvider):
    """Built-in local intelligence dataset.

    Data is clearly marked is_simulated=True.  This provider is ALWAYS
    available as the fallback and will return UNKNOWN for IOCs not in its
    dataset rather than fabricating results.
    """

    @property
    def name(self) -> str:
        return "ZentraSec Local Intelligence Feed (DEMO)"

    @property
    def is_available(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: str) -> Optional[dict]:
        key = indicator.strip().lower()
        # Try exact match first
        record = _DEMO_IOC_DB.get(indicator.strip()) or _DEMO_IOC_DB.get(key)
        if not record:
            return None  # Not in demo dataset → return None → UNKNOWN at service level

        r = record.copy()
        return _build_result(
            indicator=indicator,
            indicator_type=r.get("indicator_type", indicator_type),
            reputation=r["reputation"],
            threat_level=r["threat_level"],
            confidence=r["confidence"],
            source=r["source"],
            is_simulated=True,
            threat_actor=r.get("threat_actor"),
            campaign=r.get("campaign"),
            country=r.get("country"),
            organization=r.get("organization"),
            asn=r.get("asn"),
            first_seen=r.get("first_seen"),
            last_seen=r.get("last_seen"),
            mitre_techniques=r.get("mitre_techniques", []),
            known_target_types=r.get("known_target_types", []),
            related_indicators=r.get("related_indicators", []),
            tags=r.get("tags", []),
        )


# ---------------------------------------------------------------------------
# VirusTotal Provider stub — requires VIRUSTOTAL_API_KEY env var
# ---------------------------------------------------------------------------

class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal provider stub.  Activate by setting VIRUSTOTAL_API_KEY."""

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def is_available(self) -> bool:
        return bool(os.getenv("VIRUSTOTAL_API_KEY"))

    def lookup(self, indicator: str, indicator_type: str) -> Optional[dict]:
        # TODO: implement real VirusTotal API call
        # GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
        # Headers: x-apikey: {VIRUSTOTAL_API_KEY}
        logger.info("[TI] VirusTotal lookup not yet implemented (stub)")
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB Provider stub — requires ABUSEIPDB_API_KEY env var
# ---------------------------------------------------------------------------

class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB provider stub.  Activate by setting ABUSEIPDB_API_KEY."""

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    @property
    def is_available(self) -> bool:
        return bool(os.getenv("ABUSEIPDB_API_KEY"))

    def lookup(self, indicator: str, indicator_type: str) -> Optional[dict]:
        # TODO: implement real AbuseIPDB API call
        # GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}
        # Headers: Key: {ABUSEIPDB_API_KEY}
        logger.info("[TI] AbuseIPDB lookup not yet implemented (stub)")
        return None


# ---------------------------------------------------------------------------
# ThreatIntelService — orchestrator
# ---------------------------------------------------------------------------

class ThreatIntelService:
    """Orchestrates providers and persists results to the database.

    Provider priority (first successful hit wins):
      1. VirusTotalProvider  (if VIRUSTOTAL_API_KEY is set)
      2. AbuseIPDBProvider   (if ABUSEIPDB_API_KEY is set)
      3. LocalDemoProvider   (always available fallback)
    """

    def __init__(self, db: Session):
        self.db = db
        self._providers: list[ThreatIntelProvider] = [
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            LocalDemoProvider(),
        ]

    # ---- public feed status ------------------------------------------------

    def get_feed_status(self) -> dict:
        """Return the current status of all configured providers."""
        statuses = []
        for p in self._providers:
            statuses.append({
                "name": p.name,
                "available": p.is_available,
                "mode": "EXTERNAL" if (p.is_available and not isinstance(p, LocalDemoProvider))
                        else ("DEMO" if isinstance(p, LocalDemoProvider) else "OFFLINE"),
            })
        any_external = any(
            p.is_available and not isinstance(p, LocalDemoProvider)
            for p in self._providers
        )
        return {
            "overall_status": "EXTERNAL_CONNECTED" if any_external else "DEMO_MODE",
            "label": "External feeds connected" if any_external else "Using local demo intelligence dataset",
            "ioc_database": "READY",
            "enrichment": "ACTIVE",
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "providers": statuses,
        }

    # ---- core lookup -------------------------------------------------------

    def lookup_ioc(self, indicator: str, indicator_type: Optional[str] = None) -> dict:
        """Look up an IOC, persist to DB, and return the enriched result.

        Args:
            indicator:      Raw IOC value (IP/domain/URL/hash).
            indicator_type: Optional pre-detected type. Auto-detected if None.

        Returns:
            Full enriched result dict including reputation, score, MITRE,
            threat actor, data_label (DEMO vs LIVE), etc.
        """
        indicator = indicator.strip()

        # Determine type if not provided
        if not indicator_type:
            indicator_type = detect_ioc_type(indicator)
        if not indicator_type:
            return {
                "error": "INVALID_IOC",
                "message": (
                    "Unable to identify IOC type. Supported: IPv4, domain, "
                    "URL (http/https), or file hash (MD5/SHA1/SHA256)"
                ),
            }

        # Check DB cache first (< 1 hour stale)
        from models import ThreatIntelligence
        db_rec = self.db.query(ThreatIntelligence).filter(
            ThreatIntelligence.indicator == indicator,
            ThreatIntelligence.indicator_type == indicator_type,
        ).first()

        if db_rec:
            cache_age = datetime.utcnow() - (db_rec.last_seen or db_rec.created_at)
            if cache_age < timedelta(hours=1):
                logger.info("[TI] Cache hit for %s", indicator)
                return self._db_to_result(db_rec)

        # Query providers in priority order
        result: Optional[dict] = None
        for provider in self._providers:
            if not provider.is_available:
                continue
            try:
                result = provider.lookup(indicator, indicator_type)
                if result is not None:
                    logger.info("[TI] Hit from provider %s for %s", provider.name, indicator)
                    break
            except Exception as exc:
                logger.warning("[TI] Provider %s failed: %s", provider.name, exc)
                continue

        # If no provider returned a result → UNKNOWN
        if result is None:
            result = _build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation="UNKNOWN",
                threat_level="UNKNOWN",
                confidence=0.0,
                source="No matching intelligence found",
                is_simulated=False,
                threat_score=0.0,
            )

        # Persist / update DB
        self._upsert_db(indicator, indicator_type, result)

        return result

    def enrich_ip(self, ip: str) -> dict:
        """Convenience method: look up a source IP from a security event."""
        if not ip:
            return {"error": "MISSING_IP", "message": "No IP address provided"}
        return self.lookup_ioc(ip, "ipv4")

    # ---- summary -----------------------------------------------------------

    def get_summary(self) -> dict:
        """Return summary counts across the ThreatIntelligence table."""
        from models import ThreatIntelligence
        from sqlalchemy import func

        rows = self.db.query(
            ThreatIntelligence.reputation,
            func.count(ThreatIntelligence.id).label("count"),
        ).group_by(ThreatIntelligence.reputation).all()

        counts = {r.reputation: r.count for r in rows}
        total = sum(counts.values())

        # Unique threat actors (non-null, non-"Unknown")
        actor_count = self.db.query(ThreatIntelligence).filter(
            ThreatIntelligence.raw_result.isnot(None),
        ).count()

        return {
            "total_iocs": total,
            "malicious": counts.get("MALICIOUS", 0),
            "suspicious": counts.get("SUSPICIOUS", 0),
            "clean": counts.get("CLEAN", 0),
            "unknown": counts.get("UNKNOWN", 0),
            "threat_actors_seen": actor_count,
        }

    def get_recent_iocs(self, limit: int = 50) -> list[dict]:
        """Return the most recently seen IOCs from the database."""
        from models import ThreatIntelligence
        rows = self.db.query(ThreatIntelligence).order_by(
            ThreatIntelligence.last_seen.desc().nullsfirst(),
            ThreatIntelligence.created_at.desc(),
        ).limit(limit).all()
        return [self._db_to_result(r) for r in rows]

    def get_actors(self) -> list[dict]:
        """Return a deduplicated list of known threat actors from DB records."""
        from models import ThreatIntelligence
        rows = self.db.query(ThreatIntelligence).filter(
            ThreatIntelligence.raw_result.isnot(None),
        ).all()
        actors: dict[str, dict] = {}
        for r in rows:
            raw = r.raw_result or {}
            actor_name = raw.get("threat_actor")
            if not actor_name or actor_name == "Unknown":
                continue
            if actor_name not in actors:
                actors[actor_name] = {
                    "name": actor_name,
                    "campaign": raw.get("campaign"),
                    "confidence": raw.get("confidence", 0),
                    "known_target_types": raw.get("known_target_types", []),
                    "mitre_techniques": raw.get("mitre_techniques", []),
                    "related_iocs": [],
                }
            actors[actor_name]["related_iocs"].append(r.indicator)
        return list(actors.values())

    # ---- private -----------------------------------------------------------

    def _upsert_db(self, indicator: str, indicator_type: str, result: dict):
        from models import ThreatIntelligence
        try:
            db_rec = self.db.query(ThreatIntelligence).filter(
                ThreatIntelligence.indicator == indicator,
                ThreatIntelligence.indicator_type == indicator_type,
            ).first()

            now = datetime.utcnow()
            if db_rec:
                db_rec.reputation = result["reputation"]
                db_rec.threat_level = result["threat_level"]
                db_rec.confidence = result["confidence"] / 100.0
                db_rec.source = result["source"]
                db_rec.last_seen = now
                db_rec.is_simulated = result.get("is_simulated", True)
                db_rec.raw_result = result
            else:
                db_rec = ThreatIntelligence(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    reputation=result["reputation"],
                    threat_level=result["threat_level"],
                    confidence=result["confidence"] / 100.0,
                    source=result["source"],
                    first_seen=now,
                    last_seen=now,
                    is_simulated=result.get("is_simulated", True),
                    raw_result=result,
                )
                self.db.add(db_rec)
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.warning("[TI] DB upsert failed for %s: %s", indicator, exc)

    def _db_to_result(self, db_rec) -> dict:
        """Convert a ThreatIntelligence DB record to the canonical result dict."""
        raw = db_rec.raw_result or {}
        # Return cached raw_result enriched with up-to-date DB fields
        return {
            **raw,
            "indicator": db_rec.indicator,
            "indicator_type": db_rec.indicator_type,
            "reputation": db_rec.reputation,
            "threat_level": db_rec.threat_level,
            "confidence": raw.get("confidence", round(db_rec.confidence * 100, 1)),
            "source": db_rec.source,
            "is_simulated": db_rec.is_simulated,
            "data_label": "DEMO LOCAL INTELLIGENCE" if db_rec.is_simulated else "LIVE EXTERNAL INTELLIGENCE",
            "first_seen": db_rec.first_seen.isoformat() if db_rec.first_seen else raw.get("first_seen"),
            "last_seen": db_rec.last_seen.isoformat() if db_rec.last_seen else raw.get("last_seen"),
        }
