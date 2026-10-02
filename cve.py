#!/usr/bin/env python3
"""pentrix-cve: a tiny CVE lookup CLI backed by the NVD API 2.0.

Usage:
    python3 cve.py --id CVE-2021-44228
    python3 cve.py --search "apache log4j" --limit 5
    python3 cve.py --search "openssl" --json
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "pentrix-cve/1.0 (https://github.com/mizazhaider-ceh)"
DEFAULT_TIMEOUT = 15
RATE_LIMIT_DELAY = 6  # seconds between paged requests, per NVD keyless limits


def fetch_json(url, timeout):
    """GET a URL and return the parsed JSON body.

    Raises CveToolError on HTTP errors (403/429 get a rate-limit hint),
    network failures, or bad JSON.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise CveToolError(
                "NVD rate-limited this request (HTTP %d). Wait a few minutes "
                "and try again, or request a free API key at "
                "https://nvd.nist.gov/developers/request-an-api-key" % exc.code
            )
        raise CveToolError("NVD returned HTTP %d for %s" % (exc.code, url))
    except urllib.error.URLError as exc:
        raise CveToolError("Network error reaching NVD: %s" % exc.reason)
    except json.JSONDecodeError:
        raise CveToolError("NVD returned a response that was not valid JSON.")


class CveToolError(Exception):
    """A user-facing error with a clear message. Exit code 1."""


def cvss_for(cve):
    """Return (version, score, severity) preferring CVSS v3.x, falling back to v2.

    cve is a single "cve" object from the NVD API. Returns (None, None, None)
    when no CVSS data is present.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return (data.get("version"), data.get("baseScore"),
                    data.get("baseSeverity"))
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0]["cvssData"]
        return (data.get("version"), data.get("baseScore"),
                entries[0].get("baseSeverity"))
    return (None, None, None)


def english_description(cve):
    """Return the English description of a CVE, or a fallback message."""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return "No English description available."


def truncate(text, limit=280):
    """Shorten text to roughly `limit` chars, cutting at a word boundary."""
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "..."


def normalize(cve):
    """Flatten one NVD "cve" object into a plain dict for display/JSON."""
    version, score, severity = cvss_for(cve)
    return {
        "id": cve.get("id", "UNKNOWN"),
        "cvss_version": version,
        "cvss_score": score,
        "severity": severity or "UNKNOWN",
        "published": (cve.get("published") or "UNKNOWN")[:10],
        "description": truncate(english_description(cve)),
        "references": len(cve.get("references", [])),
    }


def lookup_by_id(cve_id, timeout):
    """Fetch one CVE by exact ID. Returns a normalized dict."""
    url = NVD_BASE + "?" + urllib.parse.urlencode({"cveId": cve_id.upper()})
    data = fetch_json(url, timeout)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise CveToolError("No CVE found with ID %s" % cve_id.upper())
    return normalize(vulns[0]["cve"])


def search(keyword, limit, timeout):
    """Search NVD by keyword, returning up to `limit` normalized dicts."""
    results = []
    start_index = 0
    page_size = min(max(limit, 1), 50)
    while len(results) < limit:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        url = NVD_BASE + "?" + urllib.parse.urlencode(params)
        data = fetch_json(url, timeout)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        results.extend(normalize(v["cve"]) for v in vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total:
            break
        time.sleep(RATE_LIMIT_DELAY)
    return results[:limit]


def print_card(item):
    """Print one CVE as a clean human-readable card."""
    score = item["cvss_score"]
    score_str = ("%.1f" % score) if score is not None else "N/A"
    version = "v%s" % item["cvss_version"] if item["cvss_version"] else "no CVSS"
    print("=" * 64)
    print("CVE ID     : %s" % item["id"])
    print("Severity   : %s (%s, CVSS %s)" % (item["severity"], score_str, version))
    print("Published  : %s" % item["published"])
    print("References : %d" % item["references"])
    print("-" * 64)
    print(item["description"])
    print("=" * 64)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cve.py",
        description=(
            "Look up CVEs from the National Vulnerability Database (NVD). "
            "Fetch one CVE by ID, or search by keyword and browse the top hits."
        ),
        epilog=(
            "Examples:\n"
            "  python3 cve.py --id CVE-2021-44228\n"
            "  python3 cve.py --search \"apache log4j\" --limit 5\n"
            "  python3 cve.py --search \"openssl\" --json > results.json\n"
            "\n"
            "Data: NVD API 2.0 (https://nvd.nist.gov). Keyless requests are "
            "rate-limited by NIST; be patient and do not hammer the API."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", metavar="CVE-ID",
                       help="look up one CVE by exact ID, e.g. CVE-2021-44228")
    group.add_argument("--search", metavar="KEYWORD",
                       help="keyword search, e.g. \"apache log4j\"")
    parser.add_argument("--limit", type=int, default=5, metavar="N",
                        help="max results for --search (default: 5)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        metavar="SECONDS",
                        help="HTTP timeout per request (default: %d)"
                             % DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of cards")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.limit is not None and args.limit < 1:
        print("error: --limit must be at least 1", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("error: --timeout must be at least 1 second", file=sys.stderr)
        return 2

    try:
        if args.id:
            items = [lookup_by_id(args.id, args.timeout)]
        else:
            items = search(args.search, args.limit, args.timeout)
            if not items:
                raise CveToolError(
                    "No CVEs matched %r" % args.search)
    except CveToolError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(items if len(items) > 1 else items[0], indent=2))
    else:
        for item in items:
            print_card(item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
