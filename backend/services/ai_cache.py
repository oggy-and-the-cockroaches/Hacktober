"""SQLite-backed AI Analysis & Proposal Cache for Gemma 4."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.database.schema import get_db

PROMPT_VERSION = "1.0"
SCHEMA_VERSION = "1.0"


class AICacheService:
    """Manages persistent caching of AI analyses and patch proposals."""

    @staticmethod
    def compute_cache_key(
        cache_type: str,
        code_content: str,
        finding_meta: Dict[str, Any],
        model_identifier: str,
        prompt_version: str = PROMPT_VERSION,
        schema_version: str = SCHEMA_VERSION,
    ) -> str:
        """Derive a stable SHA-256 cache key from input metadata and source code hash."""
        code_hash = hashlib.sha256(code_content.encode("utf-8", errors="ignore")).hexdigest()
        finding_norm = f"{finding_meta.get('title')}:{finding_meta.get('category')}:{finding_meta.get('file_path')}:{finding_meta.get('evidence')}:{finding_meta.get('line_number')}:{finding_meta.get('severity')}"
        finding_hash = hashlib.sha256(finding_norm.encode("utf-8")).hexdigest()

        key_input = f"{cache_type}:{code_hash}:{finding_hash}:{model_identifier}:{prompt_version}:{schema_version}"
        return hashlib.sha256(key_input.encode("utf-8")).hexdigest()

    @classmethod
    def get(
        cls,
        cache_type: str,
        code_content: str,
        finding_meta: Dict[str, Any],
        model_identifier: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if valid and key matches all relevant parameters."""
        cache_key = cls.compute_cache_key(cache_type, code_content, finding_meta, model_identifier)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT response_json, created_at FROM ai_analysis_cache
                WHERE cache_key = ? AND is_valid = 1
            """,
                (cache_key,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            try:
                data = json.loads(row[0])
                data["_cached"] = True
                data["_cached_at"] = row[1]
                return data
            except Exception:
                return None

    @classmethod
    def put(
        cls,
        cache_type: str,
        code_content: str,
        finding_meta: Dict[str, Any],
        model_identifier: str,
        response_data: Dict[str, Any],
    ) -> bool:
        """Store a successful AI response in the cache.

        Transient errors, unverified claims, or malformed responses are rejected.
        """
        if not isinstance(response_data, dict):
            return False
        if "error" in response_data or "raw_response" in response_data:
            return False  # Do not cache transient failures or malformed outputs

        cache_key = cls.compute_cache_key(cache_type, code_content, finding_meta, model_identifier)
        code_hash = hashlib.sha256(code_content.encode("utf-8", errors="ignore")).hexdigest()

        # Clean metadata before serializing
        clean_data = {k: v for k, v in response_data.items() if not k.startswith("_")}
        response_json = json.dumps(clean_data)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO ai_analysis_cache (
                    cache_key, cache_type, code_hash, model_identifier,
                    prompt_version, schema_version, response_json, is_valid, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
                (
                    cache_key,
                    cache_type,
                    code_hash,
                    model_identifier,
                    PROMPT_VERSION,
                    SCHEMA_VERSION,
                    response_json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return True

    @classmethod
    def invalidate(cls, cache_key: str) -> None:
        """Invalidate a single cache entry."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE ai_analysis_cache
                SET is_valid = 0, invalidated_at = ?
                WHERE cache_key = ?
            """,
                (datetime.now(timezone.utc).isoformat(), cache_key),
            )
