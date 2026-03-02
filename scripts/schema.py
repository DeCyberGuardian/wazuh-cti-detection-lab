from pydantic import BaseModel, Field, ValidationError
from typing import Any, Dict, Optional
from datetime import datetime

class IOCModel(BaseModel):
    ioc_value: str = Field(..., description="The IOC itself (ip/domain/url/hash)")
    ioc_type: str = Field(..., description="ip/domain/url/hash")
    source: str = Field(..., description="Which feed produced this IOC")
    first_seen: Optional[str] = Field(None, description="ISO-ish date when observed")
    confidence: str = Field("unknown", description="high/medium/low/unknown")
    raw_source: Optional[Dict[str, Any]] = Field(None, description="Original feed record for traceability")

    def as_dict(self):
        return {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "source": self.source,
            "first_seen": self.first_seen,
            "confidence": self.confidence,
            "raw_source": self.raw_source or {}
        }

def iso_date_safe(v):
    """Try to normalize a date-ish string to ISO date, fallback to raw."""
    try:
        if not v:
            return None
        # try parse a few common formats
        dt = datetime.fromisoformat(v)
        return dt.isoformat()
    except Exception:
        try:
            # last resort: return raw string (keeps traceability)
            return str(v)
        except Exception:
            return None
