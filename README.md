# OSINT Task 1 – five-tool website analysis → Excel

`osint_analyzer.py` queries five public OSINT services about a domain, puts the results side by side and
saves them as an `.xlsx` workbook. It is passive: nothing is sent to the target, only to the services below.

| # | Tool (Lecture 1) | Used for | API key |
|---|---|---|---|
| 1 | ICANN Lookup | RDAP registration data | none |
| 2 | Google Public DNS | A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS | none |
| 3 | crt.sh | Certificate Transparency entries, hostnames | none |
| 4 | Wayback Machine | first/latest capture, one capture per year, content hash changes | none |
| 5 | Search engine (Brave Search API) | `site:`, `site:… filetype:pdf`, `"domain" -site:domain` | **required** |

Only tool 5 uses a key. Without one its column shows `[SKIPPED]`; no values are invented.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # then paste your key after BRAVE_API_KEY=
python osint_analyzer.py wikipedia.org
python osint_analyzer.py https://www.example.com -o report.xlsx
```

The key is read from the `BRAVE_API_KEY` environment variable or `.env` only (never a command-line flag, so it
stays out of shell history). Each run makes 3 Brave queries.

## Workbook sheets

`Comparison` (main table: one row per attribute, one column per tool, a cross-check column and a note) ·
`Run Summary` · `DNS Records` · `Certificates` · `Hostnames` · `Archive Snapshots` · `Search Results` ·
`Evidence Log` (ID, observation, URL, UTC time, caveat – the same columns as the lab's evidence template).

Cross-checks: nameservers (RDAP vs DNS), DNSSEC (RDAP vs DS record), earliest date (RDAP vs first certificate vs
first archive capture), hostnames (crt.sh vs search results).

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests mock every HTTP call with **synthetic** responses. They check parsing, cross-checks, failure handling
and that web text cannot become an Excel formula. They are not observations about any real domain.

## Known limits

- crt.sh's JSON output is unofficial and rate-limited (about 5 requests/minute/IP); big domains can time out.
  The tool then shows `[ERROR]` for that column – re-run later.
- Wayback captures are samples, not a complete or current copy of a site.
- Brave counts are capped at 20 results per query.
- If RDAP fails, the target host itself is used for zone-level DNS queries.
