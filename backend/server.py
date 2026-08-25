from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import json
import time
import logging

import requests
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List
import uuid
from datetime import datetime, timezone


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# The feed is published as a release artifact, not stored in this repo. The app
# is a viewer; the data lives in data/entries/ and is built by scripts/build_feed.py.
FEED_URL = os.environ.get(
    'RADAR_FEED_URL',
    'https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/feed.json',
)
FEED_CACHE_SECONDS = int(os.environ.get('RADAR_FEED_CACHE_SECONDS', '300'))
# Local build output, used only when the published feed is unreachable — during
# development, or before the first release exists.
LOCAL_FEED_FALLBACK = ROOT_DIR.parent / 'dist' / 'feed.json'

_feed_cache: dict = {'payload': None, 'fetched_at': 0.0, 'origin': None}


def _load_feed() -> tuple[dict, str]:
    """Return (feed, origin). Serves a cached copy, then the network, then the
    last good copy, then a local build. Never serves placeholder data."""
    now = time.monotonic()
    if _feed_cache['payload'] is not None and now - _feed_cache['fetched_at'] < FEED_CACHE_SECONDS:
        return _feed_cache['payload'], _feed_cache['origin']

    try:
        resp = requests.get(FEED_URL, timeout=10, headers={'Accept': 'application/json'})
        resp.raise_for_status()
        payload = resp.json()
        _feed_cache.update(payload=payload, fetched_at=now, origin='release')
        return payload, 'release'
    except Exception as exc:  # noqa: BLE001 - any failure falls through to a cached or local copy
        logging.warning('feed fetch failed (%s): %s', FEED_URL, exc)

    if _feed_cache['payload'] is not None:
        logging.warning('serving last known good feed')
        return _feed_cache['payload'], 'stale-cache'

    if LOCAL_FEED_FALLBACK.exists():
        payload = json.loads(LOCAL_FEED_FALLBACK.read_text())
        _feed_cache.update(payload=payload, fetched_at=now, origin='local-build')
        return payload, 'local-build'

    raise HTTPException(
        status_code=503,
        detail=(
            'The RADAR feed is unavailable. It is published as a release artifact; '
            'run scripts/build_feed.py to produce dist/feed.json locally, or set '
            'RADAR_FEED_URL to a reachable feed.'
        ),
    )

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")  # Ignore MongoDB's _id field
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Hello World"}


@api_router.get("/feed")
async def get_feed():
    """Thin read-only proxy for the RADAR feed.

    No database is involved. The feed is fetched from the published release
    artifact and held briefly in memory, so the frontend picks up a new
    release without a redeploy."""
    feed, origin = _load_feed()
    return JSONResponse(
        content=feed,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Radar-Feed-Origin": origin,
        },
    )

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    # Convert to dict and serialize datetime to ISO string for MongoDB
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    _ = await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    # Exclude MongoDB's _id field from the query results
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()