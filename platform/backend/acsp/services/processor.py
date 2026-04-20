"""HTTP ingestion service — receives Falcosidekick webhook POSTs."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response

from acsp.db import init_db
from acsp.pipeline.orchestrator import process_falco_payload
from acsp.settings import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("acsp.processor")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="ACSP Event Processor", version="0.1.0", lifespan=_lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "acsp-processor"}


@app.post("/ingest/falco")
async def ingest_falco(request: Request) -> Response:
    """Primary entry for Falcosidekick `webhook` output."""
    try:
        body: Any = await request.json()
    except Exception:
        raw = await request.body()
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            logger.warning("invalid json body")
            return Response(status_code=400)

    if not isinstance(body, dict):
        return Response(status_code=400)

    enriched = process_falco_payload(body, db_path=get_settings().database_path)
    return Response(
        content=json.dumps({"id": enriched.id, "severity": enriched.core.severity}),
        media_type="application/json",
        status_code=202,
    )


def main() -> None:
    import uvicorn

    s = get_settings()
    init_db()
    uvicorn.run(
        "acsp.services.processor:app",
        host=s.processor_host,
        port=s.processor_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
