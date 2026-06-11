import json
import os

from sentinel_ai_analyst import (
    build_security_context,
    calculate_analyst_metrics,
    get_top_remediation_items,
    compare_latest_caasm_snapshots
)


OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.5"
)


def openai_configured():
    return bool(
        os.getenv("OPENAI_API_KEY")
    )


def build_grounded_narrative_payload():
    context = build_security_context()

    metrics = calculate_analyst_metrics(
        context
    )

    top_items = get_top_remediation_items(
        context,
        limit=10
    )

    snapshot_comparison = (
        compare_latest_caasm_snapshots()
    )

    return {
        "executive_metrics": metrics,
        "top_remediation_items": top_items,
        "caasm_snapshot_comparison": snapshot_comparison,
        "instructions": (
            "Use only the supplied DGS Sentinel AI platform data. "
            "Do not invent findings, assets, clients, or remediation actions."
        )
    }


def generate_openai_executive_narrative():
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

        payload = build_grounded_narrative_payload()

        prompt = (
            "You are the executive cybersecurity analyst for "
            "Data Generated Solutions, LLC. "
            "Create a concise, professional CISO-level narrative from the "
            "grounded platform data below. "
            "Use only the supplied data. "
            "Clearly separate: Executive Summary, Highest Risks, "
            "Recommended Priorities, CAASM Posture, and Next Steps. "
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
