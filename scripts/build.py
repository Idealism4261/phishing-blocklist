#!/usr/bin/env python3

import csv
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "lists" / "sources"
DATA_DIR = ROOT / "data"

SOURCE_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": "phishing-blocklist/1.0 (GitHub Actions)"
}

SOURCES = {
    "phishing_database": (
        "https://raw.githubusercontent.com/"
        "Phishing-Database/Phishing.Database/master/"
        "phishing-domains-ACTIVE.txt"
    ),

    "openphish": (
        "https://raw.githubusercontent.com/"
        "openphish/public_feed/main/feed.txt"
    ),

    "cert_polska": (
        "https://hole.cert.pl/domains/v2/domains.txt"
    ),

    "destroylist": (
        "https://raw.githubusercontent.com/"
        "phishdestroy/destroylist/main/rootlist/formats/"
        "primary_active/domains.txt"
    ),
}


def download(url: str) -> str:
    print(f"Downloading: {url}")

    response = requests.get(
        url,
        headers=HEADERS,
        timeout=60,
    )

    response.raise_for_status()

    if not response.text.strip():
        raise RuntimeError("Feed is empty")

    return response.text


def clean_domain(value: str):
    value = value.strip().lower()

    if not value or value.startswith("#"):
        return None

    # Remove trailing dot.
    value = value.rstrip(".")

    # Remove AdBlock syntax if a source happens to provide it.
    value = re.sub(r"^\|\|", "", value)
    value = re.sub(r"\^.*$", "", value)

    # If this is a URL, extract the hostname.
    if "://" in value:
        try:
            parsed = urlparse(value)
            value = parsed.hostname or ""
        except Exception:
            return None

    # Remove accidental whitespace.
    value = value.strip()

    if not value:
        return None

    # Don't accept obvious non-domain entries.
    if "/" in value or " " in value:
        return None

    # Basic hostname sanity check.
    if len(value) > 253:
        return None

    if not re.match(
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$",
        value,
    ):
        return None

    return value


def parse_domain_feed(text: str):
    domains = set()

    for line in text.splitlines():
        domain = clean_domain(line)

        if domain:
            domains.add(domain)

    return domains


def parse_openphish(text: str):
    domains = set()

    for line in text.splitlines():
        domain = clean_domain(line)

        if domain:
            domains.add(domain)

    return domains


def parse_source(name: str, text: str):
    if name == "openphish":
        return parse_openphish(text)

    return parse_domain_feed(text)


def save_source(name: str, domains):
    path = SOURCE_DIR / f"{name}.txt"

    with path.open("w", encoding="utf-8") as f:
        for domain in sorted(domains):
            f.write(domain + "\n")


def main():
    statistics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {},
    }

    failed = False

    for name, url in SOURCES.items():
        try:
            text = download(url)
            domains = parse_source(name, text)

            print(f"{name}: {len(domains):,} domains")

            if not domains:
                raise RuntimeError("Parser returned zero domains")

            save_source(name, domains)

            statistics["sources"][name] = {
                "count": len(domains),
                "status": "ok",
            }

        except Exception as exc:
            print(f"ERROR: {name}: {exc}", file=sys.stderr)

            statistics["sources"][name] = {
                "count": 0,
                "status": "failed",
                "error": str(exc),
            }

            failed = True

    with (DATA_DIR / "statistics.json").open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            statistics,
            f,
            indent=2,
            ensure_ascii=False,
        )

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
