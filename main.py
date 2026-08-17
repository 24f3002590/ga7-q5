from datetime import datetime, timezone
from math import isfinite
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Corroboration Service",
    docs_url=None,
    redoc_url=None,
)

ALLOWED_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

INVALID_RESPONSE = {
    "verdict": "invalid",
    "confidence": "low",
    "corroboratingSources": [],
}


def result(verdict: str, confidence: str, ids: list[str]) -> dict:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sorted(ids),
    }


def parse_datetime(value: Any) -> datetime | None:
    """
    Parse an ISO-8601 timestamp.

    The service deliberately does not use the current time anywhere.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()

    try:
        # ISO-8601 UTC commonly arrives with Z.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)
    except (TypeError, ValueError, OverflowError):
        return None

    # Treat a timestamp without an explicit offset as UTC.
    # This avoids depending on the server's local timezone.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    try:
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def is_valid_source(source: Any) -> bool:
    if not isinstance(source, dict):
        return False

    if not isinstance(source.get("id"), str):
        return False

    if not isinstance(source.get("origin"), str):
        return False

    if not isinstance(source.get("value"), str):
        return False

    if not isinstance(source.get("observedAt"), str):
        return False

    if source.get("type") not in ALLOWED_TYPES:
        return False

    return True


def is_fresh(
    source: dict,
    as_of: datetime,
    staleness_days: float,
) -> bool:
    observed = parse_datetime(source["observedAt"])

    if observed is None:
        return False

    age_seconds = (as_of - observed).total_seconds()
    allowed_seconds = staleness_days * 86400.0

    return age_seconds <= allowed_seconds


async def read_json(request: Request) -> Any:
    try:
        return await request.json()
    except Exception:
        return None


@app.post("/corroborate")
async def corroborate(request: Request):
    body = await read_json(request)

    # ------------------------------------------------------------
    # RULE 1: invalid
    # ------------------------------------------------------------

    if not isinstance(body, dict):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    as_of = parse_datetime(body.get("asOf"))

    if as_of is None:
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    staleness_days = body.get("stalenessDays")

    # bool is a subclass of int in Python, so explicitly reject it.
    if isinstance(staleness_days, bool):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    if not isinstance(staleness_days, (int, float)):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    try:
        staleness_days = float(staleness_days)
    except (TypeError, ValueError, OverflowError):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    if not isfinite(staleness_days):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    sources = body.get("sources")

    if not isinstance(sources, list):
        return JSONResponse(
            content=INVALID_RESPONSE,
            status_code=200,
        )

    # ------------------------------------------------------------
    # Normalize valid/fresh sources.
    #
    # Invalid sources are ignored completely.
    # ------------------------------------------------------------

    fresh = []

    for source in sources:
        if not is_valid_source(source):
            continue

        if not is_fresh(source, as_of, staleness_days):
            continue

        fresh.append(source)

    # ------------------------------------------------------------
    # RULE 2: contradicted
    #
    # This happens BEFORE support is considered.
    # Only authoritative + fresh + disagreement counts.
    # ------------------------------------------------------------

    contradicting = []

    for source in fresh:
        if (
            source.get("authoritative") is True
            and source["value"] != claim_value
        ):
            contradicting.append(source["id"])

    if contradicting:
        return JSONResponse(
            content=result(
                "contradicted",
                "low",
                contradicting,
            ),
            status_code=200,
        )

    # ------------------------------------------------------------
    # RULE 3: supported
    #
    # Keep only fresh agreement.
    # Then one representative per origin.
    # Representative = lexicographically smallest ID.
    # ------------------------------------------------------------

    representatives: dict[str, dict] = {}

    for source in fresh:
        if source["value"] != claim_value:
            continue

        origin = source["origin"]

        current = representatives.get(origin)

        if current is None or source["id"] < current["id"]:
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:
        ids = [source["id"] for source in reps]

        types = {source["type"] for source in reps}

        if len(types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return JSONResponse(
            content=result(
                "supported",
                confidence,
                ids,
            ),
            status_code=200,
        )

    # ------------------------------------------------------------
    # RULE 4: unverified
    # ------------------------------------------------------------

    return JSONResponse(
        content=result(
            "unverified",
            "low",
            [],
        ),
        status_code=200,
    )


# Simple availability endpoint.
# This does not affect corroboration decisions.
@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# Handle malformed JSON at the application level so that malformed
# requests still receive the exact required response shape.
@app.exception_handler(Exception)
async def unexpected_exception_handler(
    request: Request,
    exc: Exception,
):
    return JSONResponse(
        content=INVALID_RESPONSE,
        status_code=200,
    )
