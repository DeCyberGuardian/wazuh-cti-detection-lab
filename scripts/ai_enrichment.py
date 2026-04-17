import json
import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from openai import OpenAI
import html

load_dotenv()

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")
DEFAULT_MITRE = "T1071.004"


SYSTEM_PROMPT = """You are a cyber threat intelligence enrichment assistant.
You analyze Wazuh DNS alerts and return concise, structured JSON only.

Focus on:
- domain
- assessment
- confidence
- likely_category
- mitre_attack
- analyst_action
- reasoning

Rules:
- Return valid JSON only.
- Be concise and operational.
- If evidence is limited, say so.
- Do not invent external facts.
"""


def extract_alert_fields(alert: Dict[str, Any]) -> Dict[str, str]:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    win = alert.get("data", {}).get("win", {}) or {}
    eventdata = win.get("eventdata", {}) or {}
    system = win.get("system", {}) or {}

    domain = eventdata.get("queryName") or eventdata.get("QueryName") or ""
    process = eventdata.get("image") or eventdata.get("Image") or ""
    query_status = eventdata.get("queryStatus") or eventdata.get("QueryStatus") or ""
    event_id = system.get("eventID") or eventdata.get("eventID") or "22"

    return {
        "rule_id": str(rule.get("id", "")),
        "rule_description": rule.get("description", ""),
        "agent_name": agent.get("name", ""),
        "event_id": str(event_id),
        "domain": domain,
        "process": process,
        "query_status": query_status,
    }


def build_user_prompt(alert: Dict[str, Any]) -> str:
    payload = extract_alert_fields(alert)

    return (
        "Enrich this Wazuh DNS alert for SOC triage.\n"
        "Return JSON with keys: "
        "domain, assessment, confidence, likely_category, mitre_attack, "
        "analyst_action, reasoning.\n\n"
        f"{json.dumps(payload, ensure_ascii=False)}"
    )


def fallback_enrichment(alert: Dict[str, Any], reason: str) -> Dict[str, Any]:
    fields = extract_alert_fields(alert)
    domain = fields["domain"] or "unknown"
    process = fields["process"] or "unknown"
    process = html.unescape(process)
    rule_description = fields["rule_description"] or "DNS detection"

    return {
        "domain": domain,
        "assessment": f"DNS alert detected for domain {domain}. AI enrichment unavailable; fallback analysis applied.",
        "confidence": "low",
        "likely_category": "unknown",
        "mitre_attack": DEFAULT_MITRE,
        "analyst_action": (
            "Validate the domain against CTI sources, inspect the originating process, "
            "and review related DNS/network activity on the endpoint."
        ),
        "reasoning": (
            f"Fallback triggered due to: {reason}. "
            f"Observed domain='{domain}', process='{process}'."
        ),
        "provider_status": "fallback",
        "fallback_reason": reason,
    }


def enrich_alert(alert: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return fallback_enrichment(alert, "missing_api_key")

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=model or DEFAULT_MODEL,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(alert)},
            ],
        )

        text = (getattr(response, "output_text", "") or "").strip()

        if not text:
            return fallback_enrichment(alert, "empty_model_output")

        try:
            parsed = json.loads(text)
            parsed["provider_status"] = "success"
            parsed["fallback_reason"] = None
            return parsed
        except json.JSONDecodeError:
            return {
                "domain": extract_alert_fields(alert)["domain"],
                "assessment": "Enrichment parsing failed",
                "confidence": "low",
                "likely_category": "unknown",
                "mitre_attack": DEFAULT_MITRE,
                "analyst_action": "Review raw model output manually",
                "reasoning": text,
                "provider_status": "partial",
                "fallback_reason": "json_parse_failed",
            }

    except Exception as e:
        error_text = str(e).lower()

        if "insufficient_quota" in error_text or "429" in error_text:
            return fallback_enrichment(alert, "insufficient_quota")
        if "rate limit" in error_text:
            return fallback_enrichment(alert, "rate_limited")
        if "timeout" in error_text:
            return fallback_enrichment(alert, "timeout")

        return fallback_enrichment(alert, f"provider_error: {str(e)}")