"""
Scoring module: convert multi-source intel + VT evidence into actionable priorities.

Outputs:
- risk_score: 0-100
- priority: P1 (high), P2 (medium), P3 (low)
- reason: brief explanation for humans

Principles:
- Source reliability matters (URLhaus > OTX pulse-only)
- Evidence matters more than labels (VT malicious/suspicious counts drive score)
- Defaults should be conservative when evidence is weak
"""
from scripts.utils import logger

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def score_from_vt(vt_obj: dict) -> tuple[int, str]:
    """
    Convert VT evidence into a score contribution.
    """
    if not vt_obj:
        return 0, "no_vt"

    if vt_obj.get("found") is False:
        return 5, "vt_not_found"  # small score; unknown does not mean safe

    stats = vt_obj.get("last_analysis_stats", {}) or {}
    mal = safe_int(stats.get("malicious", 0))
    sus = safe_int(stats.get("suspicious", 0))
    harmless = safe_int(stats.get("harmless", 0))
    undetected = safe_int(stats.get("undetected", 0))

    # Weight malicious/suspicious heavily
    vt_score = min(70, mal * 15 + sus * 8)

    # If nobody flags it but it exists, keep low but non-zero
    if mal == 0 and sus == 0:
        vt_score = 10

    reason = f"vt(mal={mal},sus={sus})"
    return vt_score, reason

def score_from_source(ioc: dict) -> tuple[int, str]:
    """
    Give a base score based on intel source reliability.
    """
    src = (ioc.get("source") or "").lower()

    # Abuse.ch feeds are curated and typically high signal
    if "abuse.ch" in src or "urlhaus" in src:
        return 25, "source=urlhaus"

    # OTX varies; pulse metadata matters but we haven't fetched it deeply yet.
    if src.startswith("otx:"):
        return 15, "source=otx"

    return 10, "source=unknown"

def compute_risk(ioc: dict) -> dict:
    base, src_reason = score_from_source(ioc)
    vt_score, vt_reason = score_from_vt(ioc.get("vt"))

    # Type-based nudge: hashes often map to concrete malware artifacts
    t = ioc.get("ioc_type")
    type_bonus = 0
    if t == "hash":
        type_bonus = 10
    elif t == "ip":
        type_bonus = 5

    raw_score = base + vt_score + type_bonus
    risk_score = max(0, min(100, raw_score))

    if risk_score >= 80:
        priority = "P1"
    elif risk_score >= 50:
        priority = "P2"
    else:
        priority = "P3"

    reason = f"{src_reason}; {vt_reason}; type={t}"
    return {
        "risk_score": risk_score,
        "priority": priority,
        "reason": reason
    }
