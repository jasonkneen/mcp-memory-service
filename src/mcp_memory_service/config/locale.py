"""Unified locale configuration for all subsystems."""
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def get_active_locales() -> list[str]:
    """Get active locales from MCP_LOCALE (fallback HARVEST_LOCALE, default 'en')."""
    raw = os.environ.get("MCP_LOCALE") or os.environ.get("HARVEST_LOCALE", "en")
    return [loc.strip() for loc in raw.split(",") if loc.strip()]
