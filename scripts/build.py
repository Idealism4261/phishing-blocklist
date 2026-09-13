#!/usr/bin/env python3

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

SOURCE_DIR = ROOT / "lists" / "sources"
OUTPUT_DIR = ROOT / "lists"
DATA_DIR = ROOT / "data"
ALLOWLIST_FILE = ROOT / "allowlist.txt"

SOURCE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

HEADERS = {
    "User-Agent": "phishing-blocklist/1.0"
}

TIMEOUT = 60


SOURCES = {
    "phishing_database": {
        "name": "Phishing.Database",
        "url": (
            "https://raw.githubusercontent.com/"
            "Phishing-Database/Phishing.Database/master/"
            "phishing-domains-ACTIVE.txt"
        ),
    },

    "openphish": {
        "name": "OpenPhish Community Feed",
        "url": (
            "https://raw.githubusercontent.com/"
            "openphish/public_feed/main/feed.txt"
        ),
    },

    "cert_polska": {
        "name": "CERT Polska Warning List",
        "url": (
            "https://hole.cert.pl/domains/v2/domains.txt"
        ),
    },

    "destroylist": {
        "name": "Destroylist Primary Active",
        "url": (
            "https://raw.githubusercontent.com/"
            "phishdestroy/destroylist/main/rootlist/formats/"
            "primary_active/domains.txt"
        ),
    },
}


# ------------------------------------------------------------
# Download
# ------------------------------------------------------------

def download(url):
    print(f"Downloading: {url}")

    response = requests.get(
        url,
        headers=HEADERS,
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    if not response.text.strip():
        raise RuntimeError("Feed is empty")

    return response.text


# ------------------------------------------------------------
# IDN / hostname normalization
# ------------------------------------------------------------

def normalize_hostname(value):
    """
    Convert a URL/domain into a normalized hostname.

    Examples:

        HTTPS://Example.COM/login
            ->
        example.com

        ||Example.COM^
            ->
        example.com
    """

    value = value.strip()

    if not value or value.startswith("#"):
        return None

    # Remove surrounding whitespace.
    value = value.strip()

    # Handle AdGuard/uBlock syntax if encountered.
    if value.startswith("||"):
        value = value[2:]

    value = value.rstrip("^")

    # URL -> hostname.
    if "://" in value:
        try:
            parsed = urlparse(value)
            value = parsed.hostname or ""
        except Exception:
            return None

    # Remove a trailing DNS dot.
    value = value.rstrip(".")

    value = value.lower()

    if not value:
        return None

    # Remove accidental whitespace.
    if any(char.isspace() for char in value):
        return None

    # A hostname must not contain URL paths.
    if "/" in value:
        return None

    # IPv4 / IPv6 addresses are not wanted in this domain list.
    if re.fullmatch(r"[0-9.]+", value):
        return None

    if ":" in value:
        return None

    # Convert Unicode IDNs to ASCII/Punycode.
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    # Maximum DNS hostname length.
    if len(value) > 253:
        return None

    # Basic hostname validation.
    labels = value.split(".")

    # We require a real domain rather than a single hostname label.
    if len(labels) < 2:
        return None

    for label in labels:
        if not label:
            return None

        if len(label) > 63:
            return None

        if label.startswith("-") or label.endswith("-"):
            return None

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None

    # Require a plausible TLD.
    if not re.fullmatch(r"[a-z0-9-]{2,63}", labels[-1]):
        return None

    return value


# ------------------------------------------------------------
# Parse feed
# ------------------------------------------------------------

def parse_feed(text):
    domains = set()

    for line in text.splitlines():
        domain = normalize_hostname(line)

        if domain:
            domains.add(domain)

    return domains


# ------------------------------------------------------------
# Allowlist
# ------------------------------------------------------------

def load_allowlist():
    allowlist = set()

    if not ALLOWLIST_FILE.exists():
        return allowlist

    with ALLOWLIST_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            domain = normalize_hostname(line)

            if domain:
                allowlist.add(domain)

    return allowlist


def apply_allowlist(domains, allowlist):
    """
    Remove exact allowlisted hostnames.

    We intentionally do NOT automatically remove all subdomains
    of an allowlisted domain. This prevents an accidentally broad
    allowlist entry from weakening the blocklist.
    """

    return domains - allowlist


# ------------------------------------------------------------
# Save source data
# ------------------------------------------------------------

def save_source(name, domains):
    path = SOURCE_DIR / f"{name}.txt"

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        for domain in sorted(domains):
            file.write(domain + "\n")


# ------------------------------------------------------------
# Build AdGuard list
# ------------------------------------------------------------

def build_adguard_list(domains, statistics):
    path = OUTPUT_DIR / "phishing.txt"

    generated = statistics["generated_at"]

    lines = [
        "! Title: Community Phishing Blocklist",
        "! Description: Aggregated phishing domains from multiple threat-intelligence sources",
        "! Format: AdGuard DNS filtering syntax",
        f"! Updated: {generated}",
        f"! Total unique domains: {len(domains):,}",
        "!",
        "! Sources:",
    ]

    for source_id, source in SOURCES.items():
        count = statistics["sources"][source_id]["count"]

        lines.append(
            f"!   {source['name']}: {count:,}"
        )

    lines.extend([
        "!",
        "! Repository:",
        "! https://github.com/Idealism4261/phishing-blocklist",
        "!",
    ])

    for domain in sorted(domains):
        lines.append(f"||{domain}^")

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write("\n".join(lines))
        file.write("\n")

    return path


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    generated_at = datetime.now(timezone.utc).isoformat()

    statistics = {
        "generated_at": generated_at,
        "sources": {},
        "total_unique_domains": 0,
        "allowlisted_domains": 0,
    }

    all_domains = set()

    allowlist = load_allowlist()

    print(
        f"Loaded {len(allowlist):,} allowlisted domains"
    )

    failed = False

    # --------------------------------------------------------
    # Download and process each source
    # --------------------------------------------------------

    for source_id, source in SOURCES.items():

        try:
            text = download(source["url"])

            domains = parse_feed(text)

            if not domains:
                raise RuntimeError(
                    "Parser returned zero valid domains"
                )

            # Apply local allowlist.
            original_count = len(domains)

            domains = apply_allowlist(
                domains,
                allowlist,
            )

            removed = original_count - len(domains)

            save_source(
                source_id,
                domains,
            )

            all_domains.update(domains)

            statistics["sources"][source_id] = {
                "name": source["name"],
                "url": source["url"],
                "count": len(domains),
                "allowlisted": removed,
                "status": "ok",
            }

            print(
                f"{source['name']}: "
                f"{len(domains):,} domains "
                f"({removed:,} allowlisted)"
            )

        except Exception as exc:

            print(
                f"ERROR: {source['name']}: {exc}",
                file=sys.stderr,
            )

            statistics["sources"][source_id] = {
                "name": source["name"],
                "url": source["url"],
                "count": 0,
                "allowlisted": 0,
                "status": "failed",
                "error": str(exc),
            }

            failed = True

    # --------------------------------------------------------
    # Never publish a combined list if a source failed.
    # --------------------------------------------------------

    if failed:
        print(
            "One or more feeds failed. "
            "The combined list will NOT be generated.",
            file=sys.stderr,
        )

        with (DATA_DIR / "statistics.json").open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                statistics,
                file,
                indent=2,
                ensure_ascii=False,
            )

        sys.exit(1)

    # --------------------------------------------------------
    # Combined statistics
    # --------------------------------------------------------

    statistics["total_unique_domains"] = len(all_domains)

    statistics["allowlisted_domains"] = len(allowlist)

    # Count how many sources detected each domain.
    source_membership = {}

    for source_id in SOURCES:

        source_file = SOURCE_DIR / f"{source_id}.txt"

        with source_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                domain = line.strip()

                if not domain:
                    continue

                source_membership.setdefault(
                    domain,
                    set(),
                ).add(source_id)

    overlap = {
        "one_source": 0,
        "two_sources": 0,
        "three_sources": 0,
        "four_sources": 0,
    }

    for sources in source_membership.values():

        count = len(sources)

        if count == 1:
            overlap["one_source"] += 1
        elif count == 2:
            overlap["two_sources"] += 1
        elif count == 3:
            overlap["three_sources"] += 1
        elif count == 4:
            overlap["four_sources"] += 1

    statistics["source_overlap"] = overlap

    # --------------------------------------------------------
    # Generate final AdGuard list
    # --------------------------------------------------------

    output = build_adguard_list(
        all_domains,
        statistics,
    )

    # --------------------------------------------------------
    # Save statistics
    # --------------------------------------------------------

    with (DATA_DIR / "statistics.json").open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            statistics,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print("=" * 60)
    print("BUILD COMPLETE")
    print("=" * 60)
    print(
        f"Total unique domains: "
        f"{len(all_domains):,}"
    )
    print(
        f"AdGuard list: {output}"
    )
    print()
    print("Source overlap:")

    for key, value in overlap.items():
        print(
            f"  {key.replace('_', ' ')}: "
            f"{value:,}"
        )


if __name__ == "__main__":
    main()
