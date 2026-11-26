#!/usr/bin/env python3
"""
OSINT Task 1 - analyse a website with five public OSINT services and export a
side-by-side comparison to Excel.

Tools (all from "Labs OSINT Lecture 1"):
  1. ICANN Lookup      -> RDAP registration data               (no API key)
  2. Google Public DNS -> dns.google JSON API, DNS records     (no API key)
  3. crt.sh            -> Certificate Transparency search      (no API key)
  4. Wayback Machine   -> CDX API, archive history             (no API key)
  5. Search engine     -> Brave Search API: site:, filetype:, -site:   (API KEY)

Only the search engine needs a key. Google's own Custom Search JSON API is
closed to new customers, so Brave Search is used instead. Put the key in the
BRAVE_API_KEY environment variable or in a .env file (see .env.example).
Without a key the Brave column is marked [SKIPPED]; nothing is invented.

The script is passive: it never sends a request to the target host itself, only
to the five third-party services above. Do not use it on targets you are not
authorised to research.

Usage:
    python osint_analyzer.py example.com
    python osint_analyzer.py https://www.example.com/page -o report.xlsx
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

VERSION = "1.0"
UA = "OSINT-Task1/%s (university OSINT lab; passive queries only)" % VERSION

T_RDAP = "ICANN RDAP"
T_DNS = "Google Public DNS"
T_CRT = "crt.sh"
T_WB = "Wayback Machine"
T_BRAVE = "Brave Search"
TOOLS = [T_RDAP, T_DNS, T_CRT, T_WB, T_BRAVE]
NA = "–"  # tool does not provide this attribute

IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = "https://rdap.org/"
GOOGLE_DNS = "https://dns.google/resolve"
CRTSH = "https://crt.sh/"
CDX = "https://web.archive.org/cdx/search/cdx"
BRAVE = "https://api.search.brave.com/res/v1/web/search"

RETRY_STATUS = {429, 502, 503, 504}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT",
             28: "AAAA", 43: "DS", 257: "CAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ToolError(Exception):
    """A tool could not produce a result (reported in the workbook, never hidden)."""


@dataclass
class ToolResult:
    tool: str
    status: str = "skipped"          # ok | error | skipped
    message: str = ""
    facts: dict = field(default_factory=dict)
    retrieved_at: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------- #
# Input handling and configuration
# --------------------------------------------------------------------------- #
def normalize_target(raw: str) -> str:
    """Accept a domain or URL, return a lower-case ASCII (punycode) hostname."""
    s = raw.strip()
    if not s:
        raise ValueError("empty target")
    if "://" not in s:
        s = "//" + s
    host = urlparse(s).hostname
    if not host:
        raise ValueError("could not read a hostname from %r" % raw)
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported; give a domain name")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid internationalised domain name: %r" % raw)
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or not all(LABEL_RE.match(x) for x in labels):
        raise ValueError("%r is not a valid domain name" % raw)
    return host


def load_env_file(path: str) -> None:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


# --------------------------------------------------------------------------- #
# HTTP layer: every request is recorded for the Evidence Log sheet
# --------------------------------------------------------------------------- #
class Http:
    def __init__(self, timeout: int = 30):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = UA
        self.timeout = timeout
        self.log: list[dict] = []

    def _record(self, tool, url, when, observation, caveat):
        self.log.append({"tool": tool, "url": url, "time": when,
                         "observation": observation, "caveat": caveat})

    def get(self, tool, url, *, params=None, headers=None, what="", caveat="",
            timeout=None, retries=2):
        last = "no attempt made"
        for attempt in range(retries + 1):
            when = now_utc()
            try:
                resp = self.session.get(url, params=params, headers=headers,
                                        timeout=timeout or self.timeout)
            except requests.RequestException as exc:
                last = "could not reach %s (%s)" % (urlparse(url).hostname, type(exc).__name__)
                shown = requests.Request("GET", url, params=params).prepare().url
                self._record(tool, shown, when,
                             "%s - request failed (%s)" % (what, type(exc).__name__), caveat)
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
                continue
            self._record(tool, resp.url, when,
                         "%s - HTTP %s, %d bytes" % (what, resp.status_code, len(resp.content)),
                         caveat)
            if resp.status_code in RETRY_STATUS and attempt < retries:
                time.sleep(3 * (attempt + 1))
                last = "HTTP %s" % resp.status_code
                continue
            return resp
        raise ToolError(last)


# --------------------------------------------------------------------------- #
# Tool 1 - ICANN Lookup (RDAP)
# --------------------------------------------------------------------------- #
def _vcard_value(entity: dict, name: str):
    arr = entity.get("vcardArray")
    if isinstance(arr, list) and len(arr) > 1:
        for item in arr[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == name:
                return str(item[3])
    return None


def run_rdap(http: Http, target: str) -> ToolResult:
    res = ToolResult(T_RDAP)
    base = None
    try:
        boot = http.get(T_RDAP, IANA_BOOTSTRAP, what="IANA RDAP bootstrap lookup",
                        caveat="Maps the TLD to its authoritative RDAP server")
        if boot.status_code == 200:
            tld = target.rsplit(".", 1)[1]
            for svc in boot.json().get("services", []):
                if tld in svc[0] and svc[1]:
                    base = next((u for u in svc[1] if u.startswith("https://")), svc[1][0])
                    break
    except (ToolError, ValueError, KeyError, IndexError):
        base = None
    if base is None:
        base = RDAP_FALLBACK
    if not base.endswith("/"):
        base += "/"

    caveat = ("Registry-reported data. Registrant contact details are usually redacted "
              "(GDPR/ICANN policy), so absence of a registrant is expected.")
    labels = target.split(".")
    # Try the name as given, then its parents, so www.example.com resolves to example.com.
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        r = http.get(T_RDAP, "%sdomain/%s" % (base, cand),
                     headers={"Accept": "application/rdap+json"},
                     what="RDAP domain query for %s" % cand, caveat=caveat)
        if r.status_code == 404:
            continue
        if r.status_code != 200:
            raise ToolError("RDAP server answered HTTP %s for %s" % (r.status_code, cand))
        data = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        registrar = iana_id = None
        registrant = "Not listed in the RDAP response (withheld or not published)"
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                registrar = _vcard_value(ent, "fn") or _vcard_value(ent, "org")
                for pid in ent.get("publicIds", []):
                    if "iana" in str(pid.get("type", "")).lower():
                        iana_id = pid.get("identifier")
            if "registrant" in roles:
                if "redact" in str(ent).lower():
                    registrant = "Redacted by registry/registrar"
                else:
                    registrant = "Entity present (contact details deliberately not recorded)"
        ns = sorted({str(n.get("ldhName", "")).lower().rstrip(".")
                     for n in data.get("nameservers", []) if n.get("ldhName")})
        res.facts = {
            "rdap_name": cand, "rdap_server": base,
            "registrar": registrar, "registrar_iana_id": iana_id,
            "registrant": registrant,
            "created": events.get("registration"), "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "statuses": data.get("status", []), "nameservers": ns,
            "dnssec_signed": (data.get("secureDNS") or {}).get("delegationSigned"),
        }
        if cand != target:
            res.message = "Registrable domain %s used (target %s is a subdomain)" % (cand, target)
        res.status, res.retrieved_at = "ok", now_utc()
        return res
    raise ToolError("no RDAP record found for %s or its parent domains (HTTP 404)" % target)


# --------------------------------------------------------------------------- #
# Tool 2 - Google Public DNS
# --------------------------------------------------------------------------- #
def run_dns(http: Http, target: str, apex: str) -> ToolResult:
    res = ToolResult(T_DNS)
    plan = [(target, "A"), (target, "AAAA")]
    if target != apex:
        plan.append((target, "CNAME"))
    plan += [(apex, t) for t in ("NS", "SOA", "MX", "TXT", "CAA", "DS")]
    caveat = "Recursive resolver answer (cached); may differ from the authoritative servers."
    rows, errors, ok_queries = [], [], 0
    ad_flag, ds_checked = None, False
    for name, rtype in plan:
        try:
            r = http.get(T_DNS, GOOGLE_DNS, params={"name": name, "type": rtype},
                         what="DNS %s query for %s" % (rtype, name), caveat=caveat)
        except ToolError as exc:
            errors.append("%s %s: %s" % (rtype, name, exc))
            if ok_queries == 0 and len(errors) >= 2:
                break  # service unreachable: stop instead of waiting through every retry
            continue
        if r.status_code != 200:
            errors.append("%s %s: HTTP %s" % (rtype, name, r.status_code))
            continue
        try:
            j = r.json()
        except ValueError:
            errors.append("%s %s: non-JSON response" % (rtype, name))
            continue
        ok_queries += 1
        if rtype == "DS":
            ds_checked = True
        if rtype == "A" and name == target:
            ad_flag = j.get("AD")
        rcode = RCODES.get(j.get("Status"), str(j.get("Status")))
        found = 0
        for a in j.get("Answer") or []:
            if DNS_TYPES.get(a.get("type"), str(a.get("type"))) != rtype:
                continue  # ignore CNAME chain entries etc.
            found += 1
            rows.append({"queried": name, "type": rtype,
                         "name": str(a.get("name", "")).rstrip("."),
                         "ttl": a.get("TTL"), "data": str(a.get("data", "")), "rcode": rcode})
        if not found:
            rows.append({"queried": name, "type": rtype, "name": "", "ttl": None,
                         "data": "(no records returned)", "rcode": rcode})
    if ok_queries == 0:
        raise ToolError("all DNS queries failed: " + "; ".join(errors[:3]))
    by_type: dict[str, list] = {}
    for row in rows:
        if row["data"] != "(no records returned)":
            by_type.setdefault(row["type"], []).append(row["data"])
    res.facts = {
        "rows": rows, "by_type": by_type, "ad_flag": ad_flag,
        "ns": sorted({d.lower().rstrip(".") for d in by_type.get("NS", [])}),
        "ds_present": bool(by_type.get("DS")) if ds_checked else None,
        "spf": any("v=spf1" in d.lower() for d in by_type.get("TXT", [])),
        "apex": apex,
    }
    if errors:
        res.message = "%d of %d queries failed: %s" % (len(errors), len(plan), "; ".join(errors[:3]))
    res.status, res.retrieved_at = "ok", now_utc()
    return res


# --------------------------------------------------------------------------- #
# Tool 3 - crt.sh (Certificate Transparency)
# --------------------------------------------------------------------------- #
def _issuer_label(issuer: str) -> str:
    for key in ("O", "CN"):
        m = re.search(r"\b%s=([^,]+)" % key, issuer or "")
        if m:
            return m.group(1).strip().strip('"')
    return issuer or "unknown"


def run_crtsh(http: Http, apex: str) -> ToolResult:
    res = ToolResult(T_CRT)
    caveat = ("CT logs show certificates issued for names, not which servers are live. "
              "crt.sh JSON output is undocumented and rate-limited, so results can be partial.")
    data, last_err, clean_empty = None, "", False
    for q in ("%." + apex, apex):  # subdomain wildcard first, then the bare name
        try:
            r = http.get(T_CRT, CRTSH, params={"q": q, "output": "json", "deduplicate": "Y"},
                         what="crt.sh identity search q=%s" % q, caveat=caveat,
                         timeout=90, retries=2)
        except ToolError as exc:
            last_err = str(exc)
            continue
        if r.status_code != 200:
            last_err = "HTTP %s" % r.status_code
            continue
        try:
            parsed = r.json()
        except ValueError:
            last_err = "non-JSON reply (crt.sh returns an HTML error page when overloaded)"
            continue
        if isinstance(parsed, list) and parsed:
            data = parsed
            res.facts["query"] = q
            break
        clean_empty = True
    if data is None:
        if not clean_empty:
            raise ToolError("crt.sh unavailable: %s" % last_err)
        res.facts = {"cert_count": 0, "hostnames": [], "wildcards": [], "issuers": [], "rows": []}
        res.message = "crt.sh returned no certificates for %s" % apex
        res.status, res.retrieved_at = "ok", now_utc()
        return res

    names, wild = set(), set()
    for row in data:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower()
            if not n or not re.fullmatch(r"[a-z0-9*._-]+", n):
                continue  # skips e-mail identities and junk
            (wild if n.startswith("*.") else names).add(n)
    hostnames = sorted(n for n in names if n == apex or n.endswith("." + apex))
    issuers = Counter(_issuer_label(str(r.get("issuer_name", ""))) for r in data)
    nb = sorted(str(r["not_before"]) for r in data if r.get("not_before"))
    na = sorted(str(r["not_after"]) for r in data if r.get("not_after"))
    logged = sorted(str(r["entry_timestamp"]) for r in data if r.get("entry_timestamp"))
    res.facts.update({
        "cert_count": len(data), "hostnames": hostnames, "wildcards": sorted(wild),
        "issuers": issuers.most_common(),
        "earliest_not_before": nb[0] if nb else None, "latest_not_before": nb[-1] if nb else None,
        "latest_not_after": na[-1] if na else None, "first_logged": logged[0] if logged else None,
        "rows": sorted(data, key=lambda r: str(r.get("not_before", "")), reverse=True),
    })
    res.status, res.retrieved_at = "ok", now_utc()
    return res


# --------------------------------------------------------------------------- #
# Tool 4 - Wayback Machine (CDX API)
# --------------------------------------------------------------------------- #
def _cdx(http: Http, params: dict, what: str) -> list[dict]:
    r = http.get(T_WB, CDX, params=dict(params, output="json"), what=what, timeout=60,
                 caveat="Archive coverage is sporadic: captures are samples, not a full record.")
    if r.status_code != 200:
        raise ToolError("CDX API answered HTTP %s" % r.status_code)
    if not r.text.strip():
        return []
    data = r.json()
    if not data:
        return []
    return [dict(zip(data[0], row)) for row in data[1:]]


def _capture(row: dict) -> dict:
    ts = row.get("timestamp", "")
    return {"timestamp": ts, "date": "%s-%s-%s" % (ts[:4], ts[4:6], ts[6:8]),
            "status": row.get("statuscode"), "digest": row.get("digest"),
            "url": "https://web.archive.org/web/%s/%s" % (ts, row.get("original", ""))}


def run_wayback(http: Http, target: str) -> ToolResult:
    res = ToolResult(T_WB)
    fl = "timestamp,original,statuscode,digest"
    first = _cdx(http, {"url": target, "fl": fl, "limit": 1}, "CDX first capture of %s" % target)
    last = _cdx(http, {"url": target, "fl": fl, "limit": -1}, "CDX latest capture of %s" % target)
    yearly = _cdx(http, {"url": target, "fl": fl, "collapse": "timestamp:4",
                         "filter": "statuscode:200"},
                  "CDX one HTTP-200 capture per year for %s" % target)
    caps = [_capture(r) for r in yearly]
    changed, prev = [], None
    for c in caps:
        if prev is not None and c["digest"] != prev:
            changed.append(c["timestamp"][:4])
        prev = c["digest"]
    res.facts = {
        "first": _capture(first[0]) if first else None,
        "latest": _capture(last[0]) if last else None,
        "yearly": caps, "changed_years": changed,
        "distinct_digests": len({c["digest"] for c in caps}),
    }
    if not first:
        res.message = "No captures found for %s" % target
    res.status, res.retrieved_at = "ok", now_utc()
    return res


# --------------------------------------------------------------------------- #
# Tool 5 - search engine (Brave Search API, key required)
# --------------------------------------------------------------------------- #
def run_brave(http: Http, apex: str, api_key: str) -> ToolResult:
    res = ToolResult(T_BRAVE)
    if not api_key:
        res.message = "BRAVE_API_KEY not set - search column skipped (see .env.example)"
        return res
    queries = [
        ("site", "site:%s" % apex),
        ("pdf", "site:%s filetype:pdf" % apex),
        ("external", '"%s" -site:%s' % (apex, apex)),
    ]
    headers = {"Accept": "application/json", "X-Subscription-Token": api_key}
    out = []
    for i, (kind, q) in enumerate(queries):
        if i:
            time.sleep(1.1)  # free plan allows ~1 request/second
        r = http.get(T_BRAVE, BRAVE, params={"q": q, "count": 20}, headers=headers,
                     what="Brave web search: %s" % q,
                     caveat="Index coverage is partial; counts are capped at 20 results per query.")
        if r.status_code in (401, 403):
            raise ToolError("Brave rejected the API key (HTTP %s)" % r.status_code)
        if r.status_code != 200:
            raise ToolError("Brave answered HTTP %s for query %s" % (r.status_code, q))
        j = r.json()
        results = []
        for rank, item in enumerate((j.get("web") or {}).get("results", []), start=1):
            url = item.get("url", "")
            results.append({"rank": rank, "title": item.get("title", ""), "url": url,
                            "host": (urlparse(url).hostname or "").lower(),
                            "snippet": str(item.get("description", ""))[:300]})
        out.append({"kind": kind, "query": q, "results": results,
                    "more": (j.get("query") or {}).get("more_results_available"),
                    "time": now_utc()})
    by = {o["kind"]: o for o in out}
    hosts = sorted({x["host"] for x in by["site"]["results"]
                    if x["host"] == apex or x["host"].endswith("." + apex)})
    res.facts = {"queries": out, "hosts": hosts,
                 "pdf_urls": [x["url"] for x in by["pdf"]["results"]]}
    res.status, res.retrieved_at = "ok", now_utc()
    return res


def guarded(tool: str, fn, *args) -> ToolResult:
    """Run one tool; a failure becomes a documented 'error' result, never a crash."""
    try:
        return fn(*args)
    except ToolError as exc:
        msg = str(exc)
    except Exception as exc:  # noqa: BLE001 - report anything unexpected in the workbook
        msg = "Unexpected %s: %s" % (type(exc).__name__, exc)
    return ToolResult(tool, "error", msg, retrieved_at=now_utc())


# --------------------------------------------------------------------------- #
# Comparison table
# --------------------------------------------------------------------------- #
def cell(res: ToolResult, getter) -> str:
    if res.status != "ok":
        return "[%s]" % res.status.upper()
    try:
        v = getter(res.facts)
    except (KeyError, TypeError, IndexError, AttributeError):
        return NA
    if v in (None, "", [], {}, ()):
        return NA
    if isinstance(v, (list, tuple, set)):
        return "\n".join(str(x) for x in v)
    return str(v)


def _compare_sets(a, b, left, right) -> str:
    a, b = set(a), set(b)
    if not a or not b:
        return "Insufficient data"
    if a == b:
        return "Agree (%d shared)" % len(a)
    shared = a & b
    if shared:
        return "Partial overlap (%d shared; only %s: %d; only %s: %d)" % (
            len(shared), left, len(a - b), right, len(b - a))
    return "DISAGREE (no common values between %s and %s)" % (left, right)


def check_dates(R) -> str:
    vals = {}
    if R[T_RDAP].ok and R[T_RDAP].facts.get("created"):
        vals["registration (RDAP)"] = R[T_RDAP].facts["created"][:10]
    if R[T_CRT].ok and R[T_CRT].facts.get("earliest_not_before"):
        vals["first certificate (crt.sh)"] = R[T_CRT].facts["earliest_not_before"][:10]
    if R[T_WB].ok and R[T_WB].facts.get("first"):
        vals["first archive capture (Wayback)"] = R[T_WB].facts["first"]["date"]
    reg = vals.get("registration (RDAP)")
    if not reg or len(vals) < 2:
        return "Insufficient data (needs RDAP plus one more source)"
    earlier = [k for k, v in vals.items() if k != "registration (RDAP)" and v < reg]
    if earlier:
        return "INCONSISTENT: %s predates the RDAP registration date" % " and ".join(earlier)
    return "Consistent: registration is on or before the other first-seen dates"


def check_dnssec(R) -> str:
    signed = R[T_RDAP].facts.get("dnssec_signed") if R[T_RDAP].ok else None
    ds = R[T_DNS].facts.get("ds_present") if R[T_DNS].ok else None
    if signed is None or ds is None:
        return "Insufficient data"
    if bool(signed) == bool(ds):
        return "Agree (%s)" % ("signed" if ds else "unsigned")
    return "DISAGREE (RDAP says %s, DNS DS lookup says %s)" % (
        "signed" if signed else "unsigned", "DS present" if ds else "no DS")


def check_hostnames(R, apex) -> str:
    if not (R[T_CRT].ok and R[T_BRAVE].ok):
        return "Single source (only one tool produced hostnames)"
    a, b = set(R[T_CRT].facts["hostnames"]), set(R[T_BRAVE].facts["hosts"])
    if not a or not b:
        return "Single source (the other tool found none)"
    shared = a & b
    if not shared:
        return "No overlap (crt.sh %d, Brave %d)" % (len(a), len(b))
    return "Partial overlap (%d shared of crt.sh %d / Brave %d)" % (len(shared), len(a), len(b))


def build_comparison(R: dict, apex: str) -> list[dict]:
    rows = []

    def add(attr, getters, check="Not comparable", note=""):
        vals = {t: (cell(R[t], getters[t]) if t in getters else NA) for t in TOOLS}
        rows.append({"attribute": attr, "values": vals, "check": check, "note": note})

    rows.append({"attribute": "Query status",
                 "values": {t: R[t].status for t in TOOLS}, "check": "n/a",
                 "note": "ok = data returned; error = tool failed; skipped = no API key supplied"})
    add("Registrar", {T_RDAP: lambda f: "%s%s" % (f["registrar"], " (IANA ID %s)" % f["registrar_iana_id"]
                                                  if f.get("registrar_iana_id") else "")},
        "Single source")
    add("Registrant data", {T_RDAP: lambda f: f["registrant"]}, "Single source",
        "Withheld registrant data is normal; this script never stores personal contact details.")
    add("Earliest date observed", {
        T_RDAP: lambda f: "registered %s" % f["created"][:10],
        T_CRT: lambda f: "first certificate %s" % f["earliest_not_before"][:10],
        T_WB: lambda f: "first capture %s" % f["first"]["date"]},
        check_dates(R),
        "Three different events, so exact equality is not expected. A later registration date than "
        "a first-seen date can mean the domain was dropped and re-registered, or an earlier owner.")
    add("Expiry / validity", {
        T_RDAP: lambda f: "domain expires %s" % f["expires"][:10],
        T_CRT: lambda f: "latest certificate expires %s" % f["latest_not_after"][:10]},
        "Not comparable", "Domain expiry and certificate expiry are independent.")
    add("Domain status (EPP)", {T_RDAP: lambda f: f["statuses"]}, "Single source")
    add("Nameservers", {T_RDAP: lambda f: f["nameservers"], T_DNS: lambda f: f["ns"]},
        _compare_sets(R[T_RDAP].facts.get("nameservers", []) if R[T_RDAP].ok else [],
                      R[T_DNS].facts.get("ns", []) if R[T_DNS].ok else [], "RDAP", "DNS"),
        "RDAP shows the delegation recorded at the registry; DNS shows what resolvers return. "
        "A mismatch can mean a recent change, caching, or a stale registry record.")
    add("DNSSEC", {
        T_RDAP: lambda f: "delegation signed: %s" % ("yes" if f["dnssec_signed"] else "no")
        if f["dnssec_signed"] is not None else None,
        T_DNS: lambda f: "DS published: %s; resolver AD flag: %s" % (
            "yes" if f["ds_present"] else "no", f["ad_flag"]) if f["ds_present"] is not None else None},
        check_dnssec(R), "AD=true means Google validated the A answer with DNSSEC.")
    add("IPv4 (A)", {T_DNS: lambda f: f["by_type"]["A"]}, "Single source")
    add("IPv6 (AAAA)", {T_DNS: lambda f: f["by_type"]["AAAA"]}, "Single source")
    add("CNAME (host)", {T_DNS: lambda f: f["by_type"]["CNAME"]}, "Single source",
        "Only queried when the target is not the registrable domain.")
    add("Mail (MX)", {T_DNS: lambda f: f["by_type"]["MX"]}, "Single source")
    add("TXT records", {T_DNS: lambda f: "%d record(s); SPF %s" % (
        len(f["by_type"].get("TXT", [])), "present" if f["spf"] else "not found")
        if f["by_type"].get("TXT") else None}, "Single source", "Full values: 'DNS Records' sheet.")
    add("CAA (permitted CAs)", {T_DNS: lambda f: f["by_type"]["CAA"]}, "Single source")
    add("Certificates logged", {T_CRT: lambda f: "%d certificate entries; top issuers: %s" % (
        f["cert_count"], ", ".join("%s (%d)" % i for i in f["issuers"][:3])) if f["cert_count"] else None},
        "Single source", "CT shows issuance, not whether a server is live or who operates it.")
    add("Hostnames observed", {
        T_CRT: lambda f: "%d hostnames (+%d wildcard names)" % (len(f["hostnames"]), len(f["wildcards"]))
        if f["hostnames"] else None,
        T_BRAVE: lambda f: "%d hostnames in search results" % len(f["hosts"]) if f["hosts"] else None},
        check_hostnames(R, apex),
        "Different evidence types (certificate names vs indexed pages): differences are expected.")
    add("Archive history", {T_WB: lambda f: "first %s (HTTP %s); latest %s (HTTP %s); %d yearly 200-captures" % (
        f["first"]["date"], f["first"]["status"], f["latest"]["date"], f["latest"]["status"],
        len(f["yearly"]))}, "Single source", "Captures are samples; see 'Archive Snapshots'.")
    add("Content change across years", {T_WB: lambda f: "%d distinct content hashes; changed in: %s" % (
        f["distinct_digests"], ", ".join(f["changed_years"]) or "none")
        if f["yearly"] else None}, "Single source",
        "A hash change means the HTML bytes differ (ads, timestamps and redesigns all count).")

    def brave_q(kind):
        def g(f):
            q = next(x for x in f["queries"] if x["kind"] == kind)
            n = len(q["results"])
            return "%d result(s)%s for %s" % (n, " (capped; more available)" if q["more"] else "", q["query"])
        return g
    add("Search-indexed pages", {T_BRAVE: brave_q("site")}, "Single source")
    add("Public PDFs", {T_BRAVE: brave_q("pdf")}, "Single source", "Candidate documents for metadata review.")
    add("External mentions", {T_BRAVE: brave_q("external")}, "Single source")
    rows.append({"attribute": "Tool notes",
                 "values": {t: (R[t].message or NA) for t in TOOLS}, "check": "n/a", "note": ""})
    return rows


# --------------------------------------------------------------------------- #
# Excel export
# --------------------------------------------------------------------------- #
FONT = "Arial"
HDR_FILL = PatternFill("solid", fgColor="1F3864")
GREEN = PatternFill("solid", fgColor="C6EFCE")
RED = PatternFill("solid", fgColor="FFC7CE")
AMBER = PatternFill("solid", fgColor="FFEB9C")
GREY = PatternFill("solid", fgColor="EDEDED")
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def _clean(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float)):
        return v
    return ILLEGAL_CHARACTERS_RE.sub("", str(v))[:32000]


def _put(ws, r, c, v, bold=False, fill=None, color=None):
    cl = ws.cell(row=r, column=c, value=_clean(v))
    if isinstance(cl.value, str) and cl.value.startswith("="):
        cl.data_type = "s"  # web data must never become a live Excel formula
    cl.font = Font(name=FONT, size=10, bold=bold, color=color)
    cl.alignment = Alignment(wrap_text=True, vertical="top")
    cl.border = BORDER
    if fill:
        cl.fill = fill
    return cl


def _table(ws, headers, rows, widths):
    for c, h in enumerate(headers, 1):
        _put(ws, 1, c, h, bold=True, fill=HDR_FILL, color="FFFFFF")
    for r, row in enumerate(rows, 2):
        for c, v in enumerate(row, 1):
            _put(ws, r, c, v)
    for c, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(c)].width = w
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(headers)), len(rows) + 1)


def _check_fill(text: str):
    t = text.lower()
    if t.startswith(("agree", "consistent")):
        return GREEN
    if t.startswith(("disagree", "inconsistent")):
        return RED
    if t.startswith(("partial", "no overlap")):
        return AMBER
    return None


def write_workbook(path, target, apex, started, R, comparison, http, key_given, max_certs):
    wb = Workbook()

    ws = wb.active
    ws.title = "Comparison"
    headers = ["Attribute"] + TOOLS + ["Cross-check", "Interpretation note"]
    _table(ws, headers, [[r["attribute"]] + [r["values"][t] for t in TOOLS] + [r["check"], r["note"]]
                         for r in comparison], [26, 34, 34, 34, 34, 34, 36, 54])
    for r in range(2, len(comparison) + 2):
        ws.cell(row=r, column=1).font = Font(name=FONT, size=10, bold=True)
        fill = _check_fill(str(ws.cell(row=r, column=7).value))
        if fill:
            ws.cell(row=r, column=7).fill = fill
        for c in range(2, 7):
            v = str(ws.cell(row=r, column=c).value)
            if v in ("[ERROR]", "[SKIPPED]", "error", "skipped"):
                ws.cell(row=r, column=c).fill = GREY

    # Run summary
    ws = wb.create_sheet("Run Summary")
    info = [("Target (as analysed)", target),
            ("Registrable domain used for zone-level queries", apex),
            ("Run started", started), ("Script version", VERSION),
            ("Traffic to the target host", "None - only the five third-party services were queried"),
            ("Tools returning data", "%d of %d" % (sum(R[t].ok for t in TOOLS), len(TOOLS)))]
    for i, (k, v) in enumerate(info, 1):
        _put(ws, i, 1, k, bold=True)
        _put(ws, i, 2, v)
    top = len(info) + 2
    hdr = ["Tool", "Lecture reference", "Endpoint", "Needs API key?", "Key supplied?", "Status",
           "Retrieved", "Message"]
    refs = {T_RDAP: ("ICANN Lookup (lookup.icann.org)", IANA_BOOTSTRAP + " -> registry RDAP server", "no"),
            T_DNS: ("Google Public DNS", GOOGLE_DNS, "no"),
            T_CRT: ("crt.sh", CRTSH + "?output=json", "no"),
            T_WB: ("Internet Archive Wayback Machine", CDX, "no"),
            T_BRAVE: ("Search engine (site:, filetype:, minus)", BRAVE, "YES")}
    for c, h in enumerate(hdr, 1):
        _put(ws, top, c, h, bold=True, fill=HDR_FILL, color="FFFFFF")
    for r, t in enumerate(TOOLS, top + 1):
        ref, ep, needs = refs[t]
        vals = [t, ref, ep, needs, ("yes" if key_given else "no") if t == T_BRAVE else "n/a",
                R[t].status, R[t].retrieved_at or NA, R[t].message or NA]
        for c, v in enumerate(vals, 1):
            _put(ws, r, c, v)
    lim = top + len(TOOLS) + 2
    notes = ["Limitations",
             "- DNS answers come from a recursive resolver and may be cached.",
             "- crt.sh JSON is unofficial and rate-limited; large domains can time out.",
             "- Wayback captures are sporadic samples, not a complete or current copy of the site.",
             "- Search counts are capped at 20 results per query and reflect one engine's index.",
             "- If RDAP failed, the target host itself was used for zone-level DNS queries."]
    for i, line in enumerate(notes):
        _put(ws, lim + i, 1, line, bold=(i == 0))
    for c, w in enumerate([44, 34, 52, 16, 14, 12, 24, 60], 1):
        ws.column_dimensions[get_column_letter(c)].width = w

    # DNS records
    ws = wb.create_sheet("DNS Records")
    rows = []
    if R[T_DNS].ok:
        rows = [[x["queried"], x["type"], x["name"], x["ttl"], x["data"], x["rcode"],
                 R[T_DNS].retrieved_at] for x in R[T_DNS].facts["rows"]]
    _table(ws, ["Queried name", "Type", "Record name", "TTL (s)", "Data", "Resolver status",
                "Retrieved"], rows, [28, 8, 28, 10, 70, 16, 24])

    # Certificates
    ws = wb.create_sheet("Certificates")
    rows = []
    if R[T_CRT].ok:
        for x in R[T_CRT].facts["rows"][:max_certs]:
            rows.append([x.get("id"), x.get("entry_timestamp"), x.get("not_before"), x.get("not_after"),
                         x.get("common_name"), x.get("issuer_name"),
                         str(x.get("name_value", "")).replace("\n", "; "),
                         "https://crt.sh/?id=%s" % x.get("id")])
        total = R[T_CRT].facts["cert_count"]
        if total > max_certs:
            rows.append(["", "", "", "", "", "", "Sheet truncated: %d of %d entries shown (--max-certs)"
                         % (max_certs, total), ""])
    _table(ws, ["crt.sh ID", "Logged at", "Not before", "Not after", "Common name", "Issuer",
                "Names (SAN)", "crt.sh URL"], rows, [14, 22, 20, 20, 30, 44, 60, 34])

    # Hostnames
    ws = wb.create_sheet("Hostnames")
    a = set(R[T_CRT].facts["hostnames"]) if R[T_CRT].ok else set()
    b = set(R[T_BRAVE].facts["hosts"]) if R[T_BRAVE].ok else set()
    rows = [[h, "yes" if h in a else "no", "yes" if h in b else "no", (h in a) + (h in b)]
            for h in sorted(a | b)]
    _table(ws, ["Hostname", "In crt.sh", "In Brave results", "Found by (tools)"], rows, [50, 12, 18, 16])

    # Archive
    ws = wb.create_sheet("Archive Snapshots")
    rows = []
    if R[T_WB].ok:
        f = R[T_WB].facts
        for kind, cap in (("first capture", f["first"]), ("latest capture", f["latest"])):
            if cap:
                rows.append([kind, cap["timestamp"], cap["status"], cap["digest"], "", cap["url"]])
        prev = None
        for cap in f["yearly"]:
            rows.append(["yearly (HTTP 200)", cap["timestamp"], cap["status"], cap["digest"],
                         "" if prev is None else ("yes" if cap["digest"] != prev else "no"), cap["url"]])
            prev = cap["digest"]
    _table(ws, ["Kind", "Timestamp (UTC)", "HTTP status", "Content digest", "Changed vs previous year",
                "Archive URL"], rows, [20, 18, 12, 36, 24, 80])

    # Search results
    ws = wb.create_sheet("Search Results")
    rows = []
    if R[T_BRAVE].ok:
        for q in R[T_BRAVE].facts["queries"]:
            if not q["results"]:
                rows.append([q["query"], "", "(no results)", "", "", "", q["time"]])
            for x in q["results"]:
                rows.append([q["query"], x["rank"], x["title"], x["url"], x["host"], x["snippet"], q["time"]])
    _table(ws, ["Query", "Rank", "Title", "URL", "Host", "Snippet", "Retrieved"], rows,
           [34, 7, 40, 56, 28, 60, 24])

    # Evidence log (same columns as the lecture's template, plus the tool name)
    ws = wb.create_sheet("Evidence Log")
    rows = [["E%02d" % i, e["tool"], e["observation"], e["url"], e["time"], e["caveat"]]
            for i, e in enumerate(http.log, 1)]
    _table(ws, ["ID", "Tool", "Observation", "Source URL", "Date/time (UTC)", "Confidence / caveat"],
           rows, [8, 18, 56, 70, 24, 60])

    wb.save(path)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Analyse a website with five OSINT services "
                                             "and export a comparison table to Excel.")
    ap.add_argument("target", help="domain or URL, e.g. example.com")
    ap.add_argument("-o", "--output", help="output .xlsx path (default: osint_<domain>_<time>.xlsx)")
    ap.add_argument("--max-certs", type=int, default=500,
                    help="max certificate rows written to the Certificates sheet (default 500)")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default 30)")
    args = ap.parse_args(argv)
    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        ap.error(str(exc))

    load_env_file(os.path.join(os.getcwd(), ".env"))
    load_env_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    key = os.environ.get("BRAVE_API_KEY", "").strip()

    started = now_utc()
    http = Http(args.timeout)
    R: dict[str, ToolResult] = {}
    print("Target: %s" % target)
    R[T_RDAP] = guarded(T_RDAP, run_rdap, http, target)
    apex = R[T_RDAP].facts.get("rdap_name") or target
    R[T_DNS] = guarded(T_DNS, run_dns, http, target, apex)
    R[T_CRT] = guarded(T_CRT, run_crtsh, http, apex)
    R[T_WB] = guarded(T_WB, run_wayback, http, target)
    R[T_BRAVE] = guarded(T_BRAVE, run_brave, http, apex, key)
    for t in TOOLS:
        extra = " - %s" % R[t].message if R[t].message else ""
        print("  %-18s %s%s" % (t, R[t].status.upper(), extra))

    out = args.output or "osint_%s_%s.xlsx" % (
        apex.replace(".", "_"), datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
    write_workbook(out, target, apex, started, R, build_comparison(R, apex), http, bool(key),
                   args.max_certs)
    print("Wrote %s" % out)
    return 0 if any(R[t].ok for t in TOOLS) else 2


if __name__ == "__main__":
    sys.exit(main())
