from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "lists" / "sources"
OUTPUT_DIR = ROOT / "lists"
DATA_DIR = ROOT / "data"
ALLOWLIST_FILE = ROOT / "allowlist.txt"
STATE_FILE = DATA_DIR / "source_state.json"

USER_AGENT = "phishing-blocklist/1.0"
TIMEOUT = 60

IST = ZoneInfo("Asia/Kolkata")


SOURCES = {
    "phishing_database": {
        "name": "Phishing.Database",
        "url": (
            "https://raw.githubusercontent.com/"
            "Phishing-Database/Phishing.Database/master/"
            "phishing-domains-ACTIVE.txt"
        ),
        "interval_hours": 2,
        "parser": "domains",
    },

    "openphish": {
        "name": "OpenPhish Community Feed",
        "url": (
            "https://raw.githubusercontent.com/"
            "openphish/public_feed/main/feed.txt"
        ),
        "interval_hours": 12,
        "parser": "urls",
    },

    "cert_polska": {
        "name": "CERT Polska Warning List v2",
        "url": (
            "https://hole.cert.pl/domains/v2/domains.txt"
        ),
        "interval_hours": 2,
        "parser": "domains",
    },

    "destroylist": {
        "name": "PhishDestroy Destroylist Primary Active",
        "url": (
            "https://cdn.jsdelivr.net/gh/"
            "phishdestroy/destroylist@main/"
            "rootlist/formats/primary_active/domains.txt"
        ),
        "interval_hours": 2,
        "parser": "domains",
    },

    "phishtank": {
        "name": "PhishTank online-valid",
        "url": (
            "https://data.phishtank.com/data/online-valid.csv"
        ),
        "interval_hours": 12,
        "parser": "phishtank",
    },
}


ALLOWLIST_SOURCES = {
    "anudeepnd": {
        "name": "AnudeepND Whitelist",
        "url": (
            "https://raw.githubusercontent.com/"
            "anudeepND/whitelist/master/domains/whitelist.txt"
        ),
        "interval_hours": 24,
        "parser": "domains",
    },

    "dandelionsprout": {
        "name": "DandelionSprout AdGuard Home Whitelist",
        "url": (
            "https://raw.githubusercontent.com/"
            "DandelionSprout/AdGuard-Home-Whitelist/master/"
            "whitelist.txt"
        ),
        "interval_hours": 24,
        "parser": "allowlist",
    },
}


def utc_now() -> datetime:
    """Return the current time as timezone-aware UTC."""
    return datetime.now(timezone.utc)


def utc_string(value: datetime) -> str:
    """Return an ISO-8601 UTC timestamp."""
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def ist_string(value: datetime) -> str:
    """Return a human-readable India Standard Time timestamp."""
    return value.astimezone(IST).strftime(
        "%Y-%m-%d %H:%M:%S IST"
    )


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO timestamp from the state file."""
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return None


def normalize_hostname(value: str) -> str | None:
    """
    Normalize a hostname or URL into a valid ASCII hostname.

    Returns None for invalid values, IP addresses, comments,
    or otherwise unusable entries.
    """

    value = value.strip()

    if not value or value.startswith("#"):
        return None

    # Remove inline comments.
    value = value.split("#", 1)[0].strip()

    # AdGuard / AdBlock syntax.
    if value.startswith("||"):
        value = value[2:]

    value = value.rstrip("^").strip()

    if not value:
        return None

    # Remove surrounding quotes.
    value = value.strip("\"'")

    # URL -> hostname.
    if "://" in value:
        try:
            parsed = urlparse(value)
            value = parsed.hostname or ""
        except ValueError:
            return None

    # Handle accidental protocol-relative URLs.
    if value.startswith("//"):
        try:
            parsed = urlparse("https:" + value)
            value = parsed.hostname or ""
        except ValueError:
            return None

    value = value.strip().rstrip(".").lower()

    if not value:
        return None

    # Reject IPv4/IPv6 addresses.
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    # Remove a possible port.
    if ":" in value and value.count(":") == 1:
        host, port = value.rsplit(":", 1)

        if port.isdigit():
            value = host

    # Convert internationalized domain names to ASCII.
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(value) > 253:
        return None

    labels = value.split(".")

    # Require at least domain.tld.
    if len(labels) < 2:
        return None

    label_re = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    for label in labels:
        if not label_re.fullmatch(label):
            return None

    # Basic TLD sanity check.
    tld = labels[-1]

    if len(tld) < 2:
        return None

    if not re.fullmatch(r"[a-z0-9-]+", tld):
        return None

    return value


def looks_like_html(text: str) -> bool:
    """
    Detect obvious HTML error pages returned instead of a feed.
    """

    sample = text.lstrip().lower()[:1000]

    return (
        sample.startswith("<!doctype html")
        or sample.startswith("<html")
        or "<html" in sample[:500]
    )


def parse_domains(text: str) -> set[str]:
    """Parse a one-domain-per-line or AdGuard-style feed."""

    domains: set[str] = set()

    for line in text.splitlines():
        hostname = normalize_hostname(line)

        if hostname:
            domains.add(hostname)

    return domains


def parse_urls(text: str) -> set[str]:
    """Parse a URL feed such as OpenPhish."""

    return parse_domains(text)


def parse_allowlist_domains(text: str) -> set[str]:
    """Parse exact-hostname entries from an AdGuard allowlist."""

    domains: set[str] = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Accept only exact AdGuard allow rules.
        # Wildcards, regular expressions, paths, and other rule types
        # are intentionally ignored because this project uses exact
        # hostname matching for its phishing allowlist.
        if not line.startswith("@@||"):
            continue

        rule = line[4:]

        # Remove AdGuard rule modifiers and the rule terminator.
        rule = rule.split("^", 1)[0]
        rule = rule.split("$", 1)[0]
        rule = rule.strip()

        hostname = normalize_hostname(rule)

        if hostname:
            domains.add(hostname)

    return domains


def parse_phishtank(text: str) -> set[str]:
    """
    Parse PhishTank online-valid CSV.

    Only entries with:
        verified == yes
        online == yes

    are included.
    """

    domains: set[str] = set()

    reader = csv.DictReader(
        io.StringIO(text)
    )

    required_columns = {
        "url",
        "verified",
        "online",
    }

    if not reader.fieldnames:
        raise ValueError(
            "PhishTank CSV has no header"
        )

    actual_columns = {
        column.strip()
        for column in reader.fieldnames
    }

    missing = required_columns - actual_columns

    if missing:
        raise ValueError(
            "PhishTank CSV missing required columns: "
            f"{missing}"
        )

    for row in reader:
        verified = row.get(
            "verified",
            ""
        ).strip().lower()

        online = row.get(
            "online",
            ""
        ).strip().lower()

        if verified != "yes":
            continue

        if online != "yes":
            continue

        url = row.get(
            "url",
            ""
        ).strip()

        if not url:
            continue

        hostname = normalize_hostname(url)

        if hostname:
            domains.add(hostname)

    return domains


def parse_feed(
    text: str,
    parser: str,
) -> set[str]:
    """Parse a downloaded feed using its configured parser."""

    if not text.strip():
        raise ValueError(
            "Feed is empty"
        )

    if looks_like_html(text):
        raise ValueError(
            "Feed appears to contain HTML "
            "instead of feed data"
        )

    if parser == "domains":
        return parse_domains(text)

    if parser == "urls":
        return parse_urls(text)

    if parser == "allowlist":
        return parse_allowlist_domains(text)

    if parser == "phishtank":
        return parse_phishtank(text)

    raise ValueError(
        f"Unknown parser: {parser}"
    )


def load_state() -> dict:
    """Load persistent source refresh state."""

    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open(
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

        return data if isinstance(data, dict) else {}

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return {}


def save_state(state: dict) -> None:
    """Save persistent source refresh state."""

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with STATE_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            state,
            f,
            indent=2,
            sort_keys=True,
        )

        f.write("\n")


def load_snapshot(
    source_id: str,
) -> set[str]:
    """Load the last-known-good normalized source snapshot."""

    path = SOURCE_DIR / f"{source_id}.txt"

    if not path.exists():
        return set()

    try:
        return parse_domains(
            path.read_text(
                encoding="utf-8"
            )
        )

    except OSError:
        return set()


def save_snapshot(
    source_id: str,
    domains: set[str],
) -> None:
    """Save a normalized source snapshot."""

    SOURCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = SOURCE_DIR / f"{source_id}.txt"

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        for domain in sorted(domains):
            f.write(domain + "\n")


def is_due(
    source_id: str,
    source: dict,
    state: dict,
    snapshot: set[str],
) -> bool:
    """Determine whether a source needs refreshing."""

    # No snapshot means we must download it.
    if not snapshot:
        return True

    source_state = state.get(
        source_id,
        {},
    )

    last_success = parse_timestamp(
        source_state.get(
            "last_success"
        )
    )

    # No known successful update.
    if not last_success:
        return True

    elapsed = utc_now() - last_success

    return elapsed >= timedelta(
        hours=source["interval_hours"]
    )


def download_feed(
    url: str,
) -> str:
    """Download a feed."""

    response = requests.get(
        url,
        headers={
            "User-Agent": USER_AGENT
        },
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    if not response.text.strip():
        raise ValueError(
            "Downloaded feed is empty"
        )

    return response.text


def refresh_source(
    source_id: str,
    source: dict,
    state: dict,
) -> tuple[set[str], str]:
    """
    Refresh one source.

    Returns:
        (domains, status)

    Status values:
        updated
        cached
        stale
    """

    snapshot = load_snapshot(
        source_id
    )

    if not is_due(
        source_id,
        source,
        state,
        snapshot,
    ):
        return snapshot, "cached"

    print(
        f"Refreshing {source['name']} "
        f"(interval: {source['interval_hours']}h)"
    )

    previous_count = len(snapshot)

    try:
        text = download_feed(
            source["url"]
        )

        domains = parse_feed(
            text,
            source["parser"],
        )

        if not domains:
            raise ValueError(
                "Feed produced zero valid domains"
            )

        # Protect against catastrophic feed corruption.
        #
        # If a previously healthy feed suddenly falls below
        # 5% of its previous size, treat it as suspicious.
        if (
            previous_count >= 100
            and len(domains)
            < previous_count * 0.05
        ):
            raise ValueError(
                "Suspicious feed size drop: "
                f"{previous_count:,} -> "
                f"{len(domains):,} domains"
            )

        save_snapshot(
            source_id,
            domains,
        )

        now = utc_now()

        state[source_id] = {
            "last_success": utc_string(now),
            "last_success_ist": ist_string(now),
            "last_count": len(domains),
        }

        print(
            f"  Updated: "
            f"{len(domains):,} domains"
        )

        return domains, "updated"

    except Exception as exc:

        if snapshot:
            print(
                f"  WARNING: refresh failed: {exc}"
                f"\n  Using last-known-good snapshot: "
                f"{len(snapshot):,} domains"
            )

            return snapshot, "stale"

        raise RuntimeError(
            f"{source['name']} failed and no "
            f"previous snapshot exists: {exc}"
        ) from exc


def load_allowlist() -> set[str]:
    """Load the local exact-match allowlist."""

    if not ALLOWLIST_FILE.exists():
        return set()

    allowlist: set[str] = set()

    for line in ALLOWLIST_FILE.read_text(
        encoding="utf-8"
    ).splitlines():

        hostname = normalize_hostname(
            line
        )

        if hostname:
            allowlist.add(hostname)

    return allowlist


def build_combined(
    source_domains: dict[str, set[str]],
    local_allowlist: set[str],
    external_allowlists: dict[str, set[str]],
) -> tuple[set[str], dict[str, int], dict[str, int]]:
    """Build the final unique domain set using exact-match allowlists."""

    all_domains: set[str] = set()

    for domains in source_domains.values():
        all_domains.update(domains)

    external_allowlist_union: set[str] = set()

    for domains in external_allowlists.values():
        external_allowlist_union.update(domains)

    combined_allowlist = (
        local_allowlist | external_allowlist_union
    )

    blocked_by_allowlist = (
        all_domains & combined_allowlist
    )

    external_matches = {
        source_id: len(all_domains & domains)
        for source_id, domains
        in external_allowlists.items()
    }

    final_domains = (
        all_domains - combined_allowlist
    )

    return final_domains, {
        "raw_unique": len(all_domains),
        "allowlisted": len(blocked_by_allowlist),
        "local_allowlisted": len(
            all_domains & local_allowlist
        ),
        "external_allowlisted": len(
            all_domains & external_allowlist_union
        ),
        "final_unique": len(
            final_domains
        ),
    }, external_matches


def calculate_overlap(
    source_domains: dict[str, set[str]],
) -> dict:
    """Calculate how many sources contain each domain."""

    domain_sources: dict[str, int] = {}

    for domains in source_domains.values():

        for domain in domains:
            domain_sources[domain] = (
                domain_sources.get(
                    domain,
                    0,
                ) + 1
            )

    distribution: dict[int, int] = {}

    for count in domain_sources.values():
        distribution[count] = (
            distribution.get(
                count,
                0,
            ) + 1
        )

    return {
        "source_count_distribution": {
            f"{count}_source": amount
            for count, amount in sorted(
                distribution.items()
            )
        }
    }


def write_statistics(
    source_domains: dict[str, set[str]],
    source_status: dict[str, str],
    allowlist_domains: dict[str, set[str]],
    allowlist_status: dict[str, str],
    state: dict,
    local_allowlist: set[str],
    final_domains: set[str],
    allowlist_matches: dict[str, int],
) -> None:
    """Write machine-readable statistics."""

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    now = utc_now()

    overlap = calculate_overlap(
        source_domains
    )

    sources = {}

    for source_id, source in SOURCES.items():

        source_state = state.get(
            source_id,
            {},
        )

        sources[source_id] = {
            "name": source["name"],
            "url": source["url"],
            "refresh_interval_hours": (
                source["interval_hours"]
            ),
            "status": source_status.get(
                source_id,
                "unknown",
            ),
            "domain_count": len(
                source_domains.get(
                    source_id,
                    set(),
                )
            ),
            "last_success": source_state.get(
                "last_success"
            ),
            "last_success_ist": source_state.get(
                "last_success_ist"
            ),
        }

    external_sources = {}

    for source_id, source in ALLOWLIST_SOURCES.items():

        source_state = state.get(
            source_id,
            {},
        )

        external_sources[source_id] = {
            "name": source["name"],
            "url": source["url"],
            "refresh_interval_hours": (
                source["interval_hours"]
            ),
            "status": allowlist_status.get(
                source_id,
                "unknown",
            ),
            "domain_count": len(
                allowlist_domains.get(
                    source_id,
                    set(),
                )
            ),
            "matched_blocked_domains": (
                allowlist_matches.get(source_id, 0)
            ),
            "last_success": source_state.get(
                "last_success"
            ),
            "last_success_ist": source_state.get(
                "last_success_ist"
            ),
        }

    all_domains = set().union(
        *source_domains.values()
    )

    raw_unique = len(all_domains)

    external_union = (
        set().union(*allowlist_domains.values())
        if allowlist_domains
        else set()
    )

    combined_allowlist = (
        local_allowlist | external_union
    )

    stats = {
        "generated_at": utc_string(now),
        "generated_at_ist": ist_string(now),
        "sources": sources,
        "allowlist_sources": external_sources,
        "raw_unique_domains": raw_unique,
        "local_allowlist_entries": len(
            local_allowlist
        ),
        "external_allowlist_entries": len(
            external_union
        ),
        "allowlist_entries": len(
            combined_allowlist
        ),
        "local_allowlist_matches": len(
            all_domains & local_allowlist
        ),
        "external_allowlist_matches": len(
            all_domains & external_union
        ),
        "final_unique_domains": len(
            final_domains
        ),
        "overlap": overlap,
    }

    with (
        DATA_DIR / "statistics.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            stats,
            f,
            indent=2,
            sort_keys=True,
        )

        f.write("\n")


def write_final_list(
    source_domains: dict[str, set[str]],
    final_domains: set[str],
    local_allowlist: set[str],
    external_allowlists: dict[str, set[str]],
    allowlist_matches: dict[str, int],
) -> None:
    """Write the final AdGuard Home blocklist."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = OUTPUT_DIR / "phishing.txt"

    now = utc_now()

    source_counts = {
        source_id: len(domains)
        for source_id, domains
        in source_domains.items()
    }

    all_domains = set().union(
        *source_domains.values()
    )

    external_union = (
        set().union(*external_allowlists.values())
        if external_allowlists
        else set()
    )

    combined_allowlist = (
        local_allowlist | external_union
    )

    allowlisted = len(
        all_domains & combined_allowlist
    )

    local_matches = len(
        all_domains & local_allowlist
    )

    external_matches = len(
        all_domains & external_union
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            "# Phishing Blocklist - "
            "AdGuard Home format\n"
        )

        f.write(
            f"# Generated: "
            f"{ist_string(now)}\n"
        )

        f.write(
            f"# Final unique domains: "
            f"{len(final_domains):,}\n"
        )

        f.write(
            f"# Allowlisted domains removed: "
            f"{allowlisted:,}\n"
        )

        f.write(
            f"# Local allowlist matches removed: "
            f"{local_matches:,}\n"
        )

        f.write(
            f"# External allowlist matches removed: "
            f"{external_matches:,}\n"
        )

        for source_id, source in SOURCES.items():

            f.write(
                f"# {source['name']}: "
                f"{source_counts.get(source_id, 0):,}\n"
            )

        for source_id, source in ALLOWLIST_SOURCES.items():

            f.write(
                f"# Allowlist - {source['name']}: "
                f"{len(external_allowlists.get(source_id, set())):,} entries, "
                f"{allowlist_matches.get(source_id, 0):,} matches\n"
            )

        f.write("#\n")

        for domain in sorted(
            final_domains
        ):
            f.write(
                f"||{domain}^\n"
            )


def main() -> None:
    print(
        "=== Phishing Blocklist Builder ==="
    )

    print()

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    SOURCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    state = load_state()

    source_domains: dict[
        str,
        set[str],
    ] = {}

    source_status: dict[
        str,
        str,
    ] = {}

    for source_id, source in SOURCES.items():

        domains, status = refresh_source(
            source_id,
            source,
            state,
        )

        source_domains[source_id] = (
            domains
        )

        source_status[source_id] = (
            status
        )

    allowlist_domains: dict[
        str,
        set[str],
    ] = {}

    allowlist_status: dict[
        str,
        str,
    ] = {}

    print()
    print("=== External Allowlist Sources ===")

    for source_id, source in ALLOWLIST_SOURCES.items():

        domains, status = refresh_source(
            source_id,
            source,
            state,
        )

        allowlist_domains[source_id] = (
            domains
        )

        allowlist_status[source_id] = (
            status
        )

    save_state(state)

    local_allowlist = load_allowlist()

    (
        final_domains,
        summary,
        allowlist_matches,
    ) = build_combined(
        source_domains,
        local_allowlist,
        allowlist_domains,
    )

    write_final_list(
        source_domains,
        final_domains,
        local_allowlist,
        allowlist_domains,
        allowlist_matches,
    )

    write_statistics(
        source_domains,
        source_status,
        allowlist_domains,
        allowlist_status,
        state,
        local_allowlist,
        final_domains,
        allowlist_matches,
    )

    print()
    print("=== Summary ===")

    for source_id, source in SOURCES.items():

        print(
            f"{source['name']}: "
            f"{len(source_domains[source_id]):,} "
            f"[{source_status[source_id]}]"
        )

    print()
    print("=== Allowlist Summary ===")
    print(
        f"Local allowlist entries:     "
        f"{len(local_allowlist):,}"
    )

    for source_id, source in ALLOWLIST_SOURCES.items():
        print(
            f"{source['name']}: "
            f"{len(allowlist_domains[source_id]):,} entries "
            f"[{allowlist_status[source_id]}], "
            f"{allowlist_matches[source_id]:,} matches"
        )

    print()
    print(
        f"Raw unique domains: "
        f"{summary['raw_unique']:,}"
    )

    print(
        f"Allowlisted:        "
        f"{summary['allowlisted']:,}"
    )

    print(
        f"Final unique:       "
        f"{summary['final_unique']:,}"
    )

    print()
    print(
        f"Generated IST:      "
        f"{ist_string(utc_now())}"
    )

    print()
    print(
        "Build completed successfully."
    )


if __name__ == "__main__":
    main()
