import json
import os
from demo_mode import sanitize_value

from sentinel_ai_analyst import (
    build_security_context_for_access,
    calculate_analyst_metrics,
    get_top_remediation_items,
    get_persistent_remediation_items,
)


OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.5"
)


def openai_configured():
    return bool(
        os.getenv("OPENAI_API_KEY")
    )


def build_grounded_narrative_payload(
    *,
    client_keys=None,
    is_global_admin=False,
):
    context = build_security_context_for_access(
        client_keys=client_keys,
        is_global_admin=is_global_admin,
    )

    metrics = calculate_analyst_metrics(
        context
    )

    top_items = get_top_remediation_items(
        context,
        limit=10
    )

    persistent_items = get_persistent_remediation_items(
        context,
        minimum_occurrences=2,
        limit=10
    )

    if is_global_admin:
        from sentinel_ai_analyst import (
            compare_latest_caasm_snapshots,
        )

        snapshot_comparison = (
            compare_latest_caasm_snapshots()
        )
    else:
        snapshot_comparison = {
            "available": False,
            "message": (
                "CAASM snapshot comparison is excluded from "
                "tenant-scoped AI analysis until snapshots "
                "have an explicit tenant boundary."
            ),
        }

    payload = {
        "executive_metrics": metrics,
        "top_remediation_items": top_items,
        "persistent_open_findings": persistent_items,
        "caasm_snapshot_comparison": snapshot_comparison,
        "tenant_scope": {
            "is_global_admin": bool(is_global_admin),
            "client_keys": (
                list(client_keys or [])
                if not is_global_admin
                else []
            ),
        },
        "instructions": (
            "Use only the supplied DGS Sentinel AI platform data. "
            "Do not invent findings, assets, clients, or "
            "remediation actions. "
            "Do not infer or disclose data outside the supplied "
            "tenant scope."
        )
    }

    return sanitize_value(payload)


def generate_openai_executive_narrative(
    *,
    client_keys=None,
    is_global_admin=False,
):
    if not openai_configured():
        return {
            "mode": "Local Fallback",
            "success": False,
            "message": (
                "OPENAI_API_KEY is not configured. "
                "Local grounded analyst remains available."
            ),
            "narrative": ""
        }

    try:
        from openai import OpenAI

        client = OpenAI()

        payload = build_grounded_narrative_payload(
            client_keys=client_keys,
            is_global_admin=is_global_admin,
        )

        prompt = (
            "You are the executive cybersecurity analyst for "
            "Data Generated Solutions, LLC. "
            "Create a concise, professional CISO-level narrative "
            "from the grounded platform data below. "
            "Use only the supplied data. "
            "Respect the supplied tenant scope. "
            "Clearly separate: Executive Summary, Highest Risks, "
            "Persistent Findings, Recommended Priorities, "
            "CAASM Posture, and Next Steps. "
            "Use occurrence_count and last_seen_at to identify "
            "recurring unresolved findings. "
            "Do not claim live remediation occurred. "
            "Do not invent data.\n\n"
            + json.dumps(
                payload,
                indent=2,
                default=str
            )
        )

        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt
        )

        return {
            "mode": "OpenAI Narrative",
            "success": True,
            "model": OPENAI_MODEL,
            "narrative": response.output_text
        }

    except Exception as e:
        return {
            "mode": "Local Fallback",
            "success": False,
            "message": str(e),
            "narrative": ""
        }
