"""Helpers shared by scenario definitions."""
from __future__ import annotations

import json
from pathlib import Path


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def write_json(path: Path, payload: dict) -> None:
    write(path, json.dumps(payload, indent=2) + "\n")


def mentions(text: str, *terms: str) -> bool:
    lowered = text.lower()
    return any(t.lower() in lowered for t in terms)


BASE_README = """# invoice-service

A small internal service. Node 22, no framework.

## Development

    npm install
    npm test
"""
