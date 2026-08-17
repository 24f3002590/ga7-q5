from datetime import datetime, timezone
from math import isfinite
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


ALLOWED_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        # Support the required ISO-8601 Z form and offsets.
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def valid_source(source: Any) -> bool:
    if not isinstance(source, dict):
        return False

    required_strings = ("id", "origin", "value", "observedAt")

    for key in required_strings:
        if not isinstance(source.get(key), str):
            return False

    if source.get("type") not in ALLOWED_TYPES:
        return False

    return True


def make_response(
    verdict: str,
    confidence: str,
    sources: list[str],
):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sorted(sources),
    }


@app.post("/corroborate")
async def corroborate(request: Request):
    # Never use the wall clock.
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    # Rule 1: top-level body must be an object.
    if not isinstance(body, dict):
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    claim = body.get("claim")

    # claim.value must be a string.
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    claim_value = claim["value"]

    # asOf must exist and be parseable.
    as_of = parse_timestamp(body.get("asOf"))
    if as_of is None:
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    # stalenessDays must be a JSON number, not bool.
    staleness_days = body.get("stalenessDays")
    if (
        isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
        or not isfinite(float(staleness_days))
    ):
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    # sources must be an array.
    sources = body.get("sources")
    if not isinstance(sources, list):
        return JSONResponse(
            make_response("invalid", "low", []),
            status_code=200,
        )

    max_age_seconds = float(staleness_days) * 86400.0

    fresh_sources = []

    for source in sources:
        # Invalid sources are ignored entirely.
        if not valid_source(source):
            continue

        observed_at = parse_timestamp(source["observedAt"])

        # An otherwise valid source with an unparseable observedAt
        # cannot establish freshness, so ignore it.
        if observed_at is None:
            continue

        age_seconds = (as_of - observed_at).total_seconds()

        # Fresh means:
        # asOf - observedAt <= stalenessDays
        #
        # Do not compare against wall-clock time.
        if age_seconds <= max_age_seconds:
            fresh_sources.append(source)

    # Rule 2:
    # Any fresh authoritative disagreement immediately contradicts.
    contradicting = [
        source["id"]
        for source in fresh_sources
        if source.get("authoritative") is True
        and source["value"] != claim_value
    ]

    if contradicting:
        return JSONResponse(
            make_response(
                "contradicted",
                "low",
                contradicting,
            ),
            status_code=200,
        )

    # Rule 3:
    # Keep fresh sources agreeing with the claim.
    agreeing = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    # One representative per origin.
    representatives_by_origin = {}

    for source in agreeing:
        origin = source["origin"]

        existing = representatives_by_origin.get(origin)

        if existing is None or source["id"] < existing["id"]:
            representatives_by_origin[origin] = source

    representatives = list(representatives_by_origin.values())

    if len(representatives) >= 2:
        representative_ids = sorted(
            source["id"] for source in representatives
        )

        distinct_types = {
            source["type"] for source in representatives
        }

        confidence = (
            "high"
            if len(distinct_types) >= 2
            else "medium"
        )

        return JSONResponse(
            make_response(
                "supported",
                confidence,
                representative_ids,
            ),
            status_code=200,
        )

    # Rule 4.
    return JSONResponse(
        make_response("unverified", "low", []),
        status_code=200,
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
