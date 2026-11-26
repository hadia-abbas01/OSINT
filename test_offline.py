"""Offline tests: every HTTP call is mocked, so no network and no API key are needed.

The fixtures are SYNTHETIC (shaped like each service's documented response). They prove the
parsing, comparison and Excel export logic; they are not observations about any real domain.
Run:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

import requests
from openpyxl import load_workbook

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import osint_analyzer as oa  # noqa: E402


def resp(status, body, url="https://x.test/"):
    r = requests.Response()
    r.status_code = status
    r.url = url
    r._content = body if isinstance(body, bytes) else (
        body.encode() if isinstance(body, str) else __import__("json").dumps(body).encode())
    return r


def dns(name, rtype, answers, status=0, ad=False):
    code = {"A": 1, "AAAA": 28, "NS": 2, "MX": 15, "TXT": 16, "SOA": 6, "CAA": 257, "DS": 43, "CNAME": 5}
    j = {"Status": status, "AD": ad, "Question": [{"name": name + ".", "type": code[rtype]}]}
    if answers:
        j["Answer"] = [{"name": name + ".", "type": code[rtype], "TTL": 300, "data": d} for d in answers]
    return j


CDX_HDR = ["timestamp", "original", "statuscode", "digest"]


def router(brave_status=200, crt_status=200, ds=True):
    def fake_get(self, url, params=None, headers=None, timeout=None, **kw):
        p = params or {}
        if url == oa.IANA_BOOTSTRAP:
            return resp(200, {"services": [[["org"], ["https://rdap.registry.test/"]]]}, url)
        if url.startswith("https://rdap.registry.test/domain/"):
            name = url.rsplit("/", 1)[1]
            if name == "www.example.org":
                return resp(404, {}, url)
            return resp(200, {
                "ldhName": name,
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                           {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
                           {"eventAction": "last changed", "eventDate": "2025-07-01T00:00:00Z"}],
                "status": ["client transfer prohibited"],
                "nameservers": [{"ldhName": "NS1.Example.NET"}, {"ldhName": "ns2.example.net"}],
                "secureDNS": {"delegationSigned": True},
                "entities": [
                    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar Inc"]]],
                     "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}]},
                    {"roles": ["registrant"], "remarks": [{"title": "REDACTED FOR PRIVACY"}]}]}, url)
        if url == oa.GOOGLE_DNS:
            n, t = p["name"], p["type"]
            table = {
                ("www.example.org", "A"): dns(n, "A", ["192.0.2.10", "192.0.2.11"], ad=True),
                ("www.example.org", "AAAA"): dns(n, "AAAA", ["2001:db8::10"]),
                ("www.example.org", "CNAME"): dns(n, "CNAME", []),
                ("example.org", "NS"): dns(n, "NS", ["ns1.example.net.", "ns2.example.net."]),
                ("example.org", "SOA"): dns(n, "SOA", ["ns1.example.net. hostmaster.example.org. 1 2 3 4 5"]),
                ("example.org", "MX"): dns(n, "MX", ["10 mail.example.org."]),
                ("example.org", "TXT"): dns(n, "TXT", ['"v=spf1 -all"', '"=HYPERLINK(\\"http://evil.test\\",\\"x\\")"']),
                ("example.org", "CAA"): dns(n, "CAA", ['0 issue "letsencrypt.org"']),
                ("example.org", "DS"): dns(n, "DS", ["12345 13 2 ABCDEF"] if ds else []),
            }
            return resp(200, table[(n, t)], url)
        if url == oa.CRTSH:
            if crt_status != 200:
                return resp(crt_status, "<html>busy</html>", url)
            if p["q"] == "%.example.org":
                return resp(200, [
                    {"id": 111, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "www.example.org",
                     "name_value": "www.example.org\nexample.org\nadmin@example.org", "entry_timestamp": "2024-05-01T10:00:00.1",
                     "not_before": "2024-05-01T09:00:00", "not_after": "2024-07-30T09:00:00", "serial_number": "aa"},
                    {"id": 110, "issuer_name": "C=US, O=DigiCert Inc, CN=CA1", "common_name": "*.example.org",
                     "name_value": "*.example.org\nmail.example.org", "entry_timestamp": "2016-01-01T00:00:00",
                     "not_before": "2015-12-31T00:00:00", "not_after": "2017-01-01T00:00:00", "serial_number": "bb"}], url)
            return resp(200, [], url)
        if url == oa.CDX:
            if p.get("limit") == 1:
                return resp(200, [CDX_HDR, ["20010203040506", "http://www.example.org/", "200", "AAA"]], url)
            if p.get("limit") == -1:
                return resp(200, [CDX_HDR, ["20251101000000", "https://www.example.org/", "200", "CCC"]], url)
            return resp(200, [CDX_HDR, ["20010203040506", "http://www.example.org/", "200", "AAA"],
                              ["20150303000000", "http://www.example.org/", "200", "AAA"],
                              ["20251101000000", "https://www.example.org/", "200", "CCC"]], url)
        if url == oa.BRAVE:
            if brave_status != 200:
                return resp(brave_status, {}, url)
            assert headers["X-Subscription-Token"] == "KEY123"
            q = p["q"]
            mk = lambda u, t: {"url": u, "title": t, "description": "d"}  # noqa: E731
            if "filetype:pdf" in q:
                web = [mk("https://www.example.org/docs/report.pdf", "Report")]
            elif q.startswith("site:"):
                web = [mk("https://www.example.org/", "Home"), mk("https://mail.example.org/x", "Mail"),
                       mk("https://blog.example.org/", "Blog")]
            else:
                web = [mk("https://news.test/story", "=cmd|' /C calc'!A0")]
            return resp(200, {"web": {"results": web}, "query": {"more_results_available": False}}, url)
        raise AssertionError("unexpected URL " + url)
    return fake_get


def run_main(out, key="KEY123", **kw):
    env = {"BRAVE_API_KEY": key} if key else {}
    with mock.patch.object(requests.Session, "get", router(**kw)), \
            mock.patch.object(time, "sleep"), \
            mock.patch.dict(os.environ, env, clear=False), \
            mock.patch.object(oa, "load_env_file"):
        if not key:
            os.environ.pop("BRAVE_API_KEY", None)
        return oa.main(["https://www.example.org/path?x=1", "-o", out])


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "r.xlsx")

    def comparison(self):
        ws = load_workbook(self.out)["Comparison"]
        return {r[0].value: [c.value for c in r] for r in ws.iter_rows(min_row=2)}

    def test_full_run_and_cross_checks(self):
        self.assertEqual(run_main(self.out), 0)
        wb = load_workbook(self.out)
        self.assertEqual(wb.sheetnames, ["Comparison", "Run Summary", "DNS Records", "Certificates",
                                         "Hostnames", "Archive Snapshots", "Search Results", "Evidence Log"])
        rows = self.comparison()
        hdr = [c.value for c in wb["Comparison"][1]]
        self.assertEqual(hdr[1:6], oa.TOOLS)
        self.assertTrue(all(rows["Query status"][i] == "ok" for i in range(1, 6)))
        self.assertIn("Test Registrar Inc (IANA ID 9999)", rows["Registrar"][1])
        self.assertIn("Redacted", rows["Registrant data"][1])
        self.assertTrue(rows["Nameservers"][6].startswith("Agree"), rows["Nameservers"][6])
        self.assertTrue(rows["DNSSEC"][6].startswith("Agree"), rows["DNSSEC"][6])
        self.assertTrue(rows["Earliest date observed"][6].startswith("Consistent"))
        self.assertTrue(rows["Hostnames observed"][6].startswith("Partial overlap"), rows["Hostnames observed"][6])
        self.assertIn("2 certificate entries", rows["Certificates logged"][3])
        self.assertIn("2 distinct content hashes", rows["Content change across years"][4])
        self.assertIn("changed in: 2025", rows["Content change across years"][4])
        # RDAP resolved the parent of www.example.org and zone queries used it
        dnsws = load_workbook(self.out)["DNS Records"]
        zone = {(r[0].value, r[1].value) for r in dnsws.iter_rows(min_row=2)}
        self.assertIn(("example.org", "NS"), zone)
        self.assertIn(("www.example.org", "A"), zone)

    def test_untrusted_text_never_becomes_a_formula(self):
        run_main(self.out)
        with zipfile.ZipFile(self.out) as z:
            for n in z.namelist():
                if n.startswith("xl/worksheets/"):
                    self.assertNotIn(b"<f>", z.read(n), n)
        wb = load_workbook(self.out)
        # the hostile search-result title starts with "=" and must survive as plain text
        hostile = [c for r in wb["Search Results"].iter_rows(min_row=2) for c in r
                   if str(c.value).startswith("=")]
        self.assertEqual(len(hostile), 1)
        self.assertEqual(hostile[0].data_type, "s")
        for ws in wb:
            for row in ws.iter_rows():
                for c in row:
                    self.assertNotEqual(c.data_type, "f", "%s!%s" % (ws.title, c.coordinate))

    def test_missing_key_is_skipped_not_faked(self):
        self.assertEqual(run_main(self.out, key=""), 0)
        rows = self.comparison()
        self.assertEqual(rows["Query status"][5], "skipped")
        self.assertEqual(rows["Search-indexed pages"][5], "[SKIPPED]")
        self.assertTrue(rows["Hostnames observed"][6].startswith("Single source"))

    def test_failed_tools_are_documented_and_workbook_still_written(self):
        self.assertEqual(run_main(self.out, crt_status=503, brave_status=401), 0)
        rows = self.comparison()
        self.assertEqual(rows["Query status"][3], "error")
        self.assertEqual(rows["Query status"][5], "error")
        self.assertIn("rejected the API key", rows["Tool notes"][5])
        self.assertIn("crt.sh unavailable", rows["Tool notes"][3])

    def test_dnssec_disagreement_is_flagged(self):
        self.assertEqual(run_main(self.out, ds=False), 0)
        self.assertTrue(self.comparison()["DNSSEC"][6].startswith("DISAGREE"))

    def test_date_inconsistency_is_flagged(self):
        R = {t: oa.ToolResult(t) for t in oa.TOOLS}
        R[oa.T_RDAP] = oa.ToolResult(oa.T_RDAP, "ok", facts={"created": "2020-01-01T00:00:00Z"})
        R[oa.T_CRT] = oa.ToolResult(oa.T_CRT, "ok", facts={"earliest_not_before": "2016-01-01T00:00:00"})
        self.assertTrue(oa.check_dates(R).startswith("INCONSISTENT"))

    def test_evidence_log_has_one_row_per_request_and_no_key(self):
        run_main(self.out)
        ws = load_workbook(self.out)["Evidence Log"]
        ids = [r[0].value for r in ws.iter_rows(min_row=2)]
        self.assertEqual(ids[0], "E01")
        self.assertEqual(len(ids), len(set(ids)))
        with zipfile.ZipFile(self.out) as z:
            self.assertFalse(any(b"KEY123" in z.read(n) for n in z.namelist()))

    def test_normalize_target(self):
        n = oa.normalize_target
        self.assertEqual(n("HTTPS://User@WWW.Example.org:8443/a?b#c"), "www.example.org")
        self.assertEqual(n("example.org."), "example.org")
        self.assertEqual(n("bücher.example"), "xn--bcher-kva.example")
        for bad in ("", "localhost", "192.0.2.1", "exa mple.org", "-a.org", "http://"):
            with self.assertRaises(ValueError, msg=bad):
                n(bad)


if __name__ == "__main__":
    unittest.main()
