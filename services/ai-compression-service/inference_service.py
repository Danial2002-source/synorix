#!/usr/bin/env python3
"""
Combined inference service for:
  - Compression policy
  - Deduplication policy

Endpoints:
  POST /predict_compress
  POST /predict_dedup
  POST /compress-decision (legacy compatibility)

This service:
  - Loads BOTH models + BOTH runtime bundles
  - Encodes features using each model's feature list
  - Applies safety guardrails
  - Returns {prob, decision, reason}
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import xgboost as xgb
import numpy as np
import json
import os
from typing import List, Optional

app = FastAPI(title="Compression + Dedup Policy Inference", version="2.0")

# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
# Compression model
COMPRESS_MODEL_PATH = "compress_policy_xgb.json"
COMPRESS_BUNDLE_PATH = "compress_policy_runtime_bundle.json"
COMPRESS_THRESHOLD = 0.6   # recommended

# Dedup model
DEDUP_MODEL_PATH = "dedup_policy_xgb.json"
DEDUP_BUNDLE_PATH = "dedup_policy_runtime_bundle.json"
DEDUP_THRESHOLD = 0.5  # Cache when model is at least 50% confident this response should be deduplicated

# Guardrails
MAX_CPU = 0.80
MAX_QUEUE = 30

SKIP_CONTENT_TYPE_PREFIXES = ["image/", "video/"]
SKIP_CONTENT_TYPES_EXACT = {"application/zip", "application/octet-stream"}

# -------------------------------------------------------------------
# LOAD MODELS
# -------------------------------------------------------------------
def load_xgb_model(path):
    if not os.path.exists(path):
        raise RuntimeError(f"Model not found: {path}")
    mdl = xgb.XGBClassifier()
    mdl.load_model(path)
    return mdl

compress_model = load_xgb_model(COMPRESS_MODEL_PATH)
dedup_model = load_xgb_model(DEDUP_MODEL_PATH)

# load runtime bundles
with open(COMPRESS_BUNDLE_PATH) as f:
    compress_bundle = json.load(f)

with open(DEDUP_BUNDLE_PATH) as f:
    dedup_bundle = json.load(f)

# Unpack bundles
def unpack_bundle(bundle):
    numeric = bundle["numeric_features"]
    categorical = bundle["categorical_features"]
    bools = bundle["bool_features"]
    mappings = bundle["categorical_mappings"]
    return numeric, categorical, bools, mappings

(C_NUM, C_CAT, C_BOOL, C_MAP) = unpack_bundle(compress_bundle)
(D_NUM, D_CAT, D_BOOL, D_MAP) = unpack_bundle(dedup_bundle)

# -------------------------------------------------------------------
# REQUEST MODEL
# -------------------------------------------------------------------
class PolicyRequest(BaseModel):
    proto: str
    method: str
    content_type: str
    body_bytes: int
    accept_encoding_flags: List[str]
    cacheability_bucket: str
    etag_present: bool
    rtt_ms: float
    ttfb_ms: float
    client_bw_mbps: float
    cpu_load: float
    queue_depth: int
    prior_compress_saving: float
    prior_dedup_hit_rate: float
    cache_control: Optional[str] = None
    pragma: Optional[str] = None
    url: Optional[str] = None

# Legacy request model for backwards compatibility
class LegacyCompressRequest(BaseModel):
    content_type: Optional[str] = ""
    size: Optional[int] = 0
    user_agent: Optional[str] = ""
    url: Optional[str] = ""

# -------------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------------
def is_skippable_content(ct: str) -> bool:
    if not ct:
        return False
    # Strip mime params (e.g. "; charset=utf-8")
    ct = ct.split(";")[0].strip()
    for p in SKIP_CONTENT_TYPE_PREFIXES:
        if ct.startswith(p):
            return True
    if ct in SKIP_CONTENT_TYPES_EXACT:
        return True
    return False

def respect_cache_control(cache_control: Optional[str], pragma: Optional[str]):
    if not cache_control and not pragma:
        return False
    c = (cache_control or "").lower()
    p = (pragma or "").lower()
    if "no-transform" in c or "no-store" in c or "private" in c:
        return True
    if "no-cache" in c or "no-cache" in p:
        return True
    return False

def normalize_proto(proto: str) -> str:
    """Convert HTTP/1.1 → h1, HTTP/2 → h2 (model training format)"""
    if not proto:
        return "h1"
    if "2" in proto:
        return "h2"
    return "h1"

def normalize_cacheability(bucket: str) -> str:
    """Convert 'public' → 'public-cacheable', 'private' → 'private-cacheable'"""
    if not bucket:
        return "public-cacheable"
    b = bucket.lower()
    if b in ("no-store", "no_store"):
        return "no-store"
    if b.startswith("private"):
        return "private-cacheable"
    # 'public', 'public-cacheable', anything else
    return "public-cacheable"

def derive_path_bucket(url: Optional[str], path_map: dict) -> int:
    """Map a URL path to the trained path_bucket index.
    Falls back to /api/* bucket (81) or 0 for unknown."""
    if not url:
        return path_map.get("/api/*", 0)
    # Strip query string
    path = url.split("?")[0] if "?" in url else url
    # Exact check first
    key = path + "/*"
    if key in path_map:
        return path_map[key]
    # Prefix match: find longest prefix
    best_len, best_val = 0, None
    for k, v in path_map.items():
        prefix = k.rstrip("/*")
        if path.startswith(prefix) and len(prefix) > best_len:
            best_len = len(prefix)
            best_val = v
    if best_val is not None:
        return best_val
    # Default to /api/* for API traffic, else first bucket
    return path_map.get("/api/*", 0)

def encode(req: PolicyRequest, NUM, CAT, BOOL, MAP):
    vec = []

    # numeric
    for n in NUM:
        val = getattr(req, n, None)
        vec.append(float(val) if val is not None else -1.0)

    # categorical
    for c in CAT:
        if c == "path_bucket":
            idx = derive_path_bucket(getattr(req, "url", None), MAP.get("path_bucket", {}))
            vec.append(idx)
        elif c == "proto":
            raw = normalize_proto(getattr(req, c, None))
            vec.append(int(MAP.get(c, {}).get(raw, 1)))  # default h1=1
        elif c == "cacheability_bucket":
            raw = normalize_cacheability(getattr(req, c, None))
            vec.append(int(MAP.get(c, {}).get(raw, 0)))  # default public-cacheable=0
        elif c == "content_type":
            raw = getattr(req, c, None)
            # Strip charset/params: "application/json; charset=utf-8" → "application/json"
            if raw:
                raw = raw.split(";")[0].strip()
            if raw is None:
                vec.append(-1)
            else:
                vec.append(int(MAP.get(c, {}).get(raw, -1)))
        else:
            raw = getattr(req, c, None)
            if raw is None:
                vec.append(-1)
            else:
                vec.append(int(MAP.get(c, {}).get(raw, -1)))

    # booleans
    for b in BOOL:
        if b == "supports_gzip":
            vec.append(1 if "gzip" in req.accept_encoding_flags else 0)
        elif b == "supports_zstd":
            vec.append(1 if "zstd" in req.accept_encoding_flags else 0)
        elif b == "supports_br":
            vec.append(1 if "br" in req.accept_encoding_flags else 0)
        else:
            vec.append(1 if getattr(req, b, False) else 0)

    return np.array(vec).reshape(1, -1)

# -------------------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "ok": True,
        "compress_model": os.path.basename(COMPRESS_MODEL_PATH),
        "dedup_model": os.path.basename(DEDUP_MODEL_PATH),
        "compress_threshold": COMPRESS_THRESHOLD,
        "dedup_threshold": DEDUP_THRESHOLD
    }

@app.post("/predict_compress")
def predict_compress(req: PolicyRequest):
    # guardrails
    if is_skippable_content(req.content_type):
        return {"prob": 0.0, "decision": 0, "reason": "content-type-skip"}

    if respect_cache_control(req.cache_control, req.pragma):
        return {"prob": 0.0, "decision": 0, "reason": "cache-control-skip"}

    if req.cpu_load > MAX_CPU:
        return {"prob": 0.0, "decision": 0, "reason": "cpu-high"}

    if req.queue_depth > MAX_QUEUE:
        return {"prob": 0.0, "decision": 0, "reason": "queue-high"}

    x = encode(req, C_NUM, C_CAT, C_BOOL, C_MAP)
    prob = float(compress_model.predict_proba(x)[:, 1])
    decision = 1 if prob >= COMPRESS_THRESHOLD else 0

    return {
        "prob": prob,
        "decision": decision,
        "reason": "model"
    }

@app.post("/predict_dedup")
def predict_dedup(req: PolicyRequest):

    # no dedup for un-transformable content types
    if is_skippable_content(req.content_type):
        return {"prob": 0.0, "decision": 0, "reason": "content-type-skip"}

    if respect_cache_control(req.cache_control, req.pragma):
        return {"prob": 0.0, "decision": 0, "reason": "cache-control-skip"}

    if req.cpu_load > MAX_CPU:
        return {"prob": 0.0, "decision": 0, "reason": "cpu-high"}

    if req.queue_depth > MAX_QUEUE:
        return {"prob": 0.0, "decision": 0, "reason": "queue-high"}

    x = encode(req, D_NUM, D_CAT, D_BOOL, D_MAP)
    prob = float(dedup_model.predict_proba(x)[:, 1])
    decision = 1 if prob >= DEDUP_THRESHOLD else 0

    return {
        "prob": prob,
        "decision": decision,
        "reason": "model"
    }

@app.post("/compress-decision")
def compress_decision(req: LegacyCompressRequest):
    """Legacy endpoint for security proxy compatibility - uses simple heuristics"""
    # Simple heuristic-based decision for legacy compatibility
    content_type = req.content_type or ""
    size = req.size or 0
    
    # Skip binary/media types
    if is_skippable_content(content_type):
        return {
            "should_compress": False,
            "confidence": 0.0,
            "reason": "content-type-skip"
        }
    
    # Compress text-based content over 1KB
    should_compress = size > 1024 and (
        content_type.startswith("text/") or
        "json" in content_type or
        "javascript" in content_type or
        "xml" in content_type
    )
    
    return {
        "should_compress": should_compress,
        "confidence": 0.8 if should_compress else 0.2,
        "reason": "heuristic-legacy"
    }

# -------------------------------------------------------------------
# RUN
# -------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    # Default 8 workers for dev/high-memory machines.
    # Set AI_WORKERS=4 on constrained servers (e.g. 2GB DigitalOcean droplet).
    workers = int(os.environ.get("AI_WORKERS", 4))
    uvicorn.run("inference_service:app", host="127.0.0.1", port=8082, reload=False, workers=workers)
