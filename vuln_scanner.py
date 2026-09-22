#!/usr/bin/env python3
"""
vuln_scanner.py — Basic authorized web vulnerability scanner
Author: Ariyan

USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
This tool requires you to explicitly confirm authorization before it runs
any scan. Unauthorized scanning of systems you do not own or have written
permission to test is illegal in most countries.

Features (Phase 1 - basic recon):
  - Security header check
  - SSL/TLS certificate check
  - Server / technology fingerprinting
  - Common sensitive file/path exposure check
  - Common open port scan

Features (Phase 2 - common web vulns):
  - Reflected XSS probe (safe, non-destructive payloads)
  - Error-based SQL injection probe
  - Form / input field discovery

Usage:
  python3 vuln_scanner.py https://example.com --i-have-permission
  python3 vuln_scanner.py https://example.com --i-have-permission --full
"""

import argparse
import socket
import ssl
import sys
import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

TIMEOUT = 6

# ---------- Utility / output helpers ----------

class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def section(title):
    print(f"\n{C.BOLD}{C.B}== {title} =={C.END}")


def finding(level, msg):
    color = {"HIGH": C.R, "MED": C.Y, "LOW": C.Y, "OK": C.G, "INFO": C.B}.get(level, C.END)
    print(f"  [{color}{level}{C.END}] {msg}")


# ---------- Phase 1: Basic recon ----------

def check_security_headers(url, results):
    section("Security Headers")
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        finding("HIGH", f"Could not connect: {e}")
        results["errors"].append(str(e))
        return

    headers = {k.lower(): v for k, v in r.headers.items()}

    expected = {
        "content-security-policy": "Mitigates XSS/data injection",
        "strict-transport-security": "Forces HTTPS, prevents downgrade attacks",
        "x-frame-options": "Prevents clickjacking",
        "x-content-type-options": "Prevents MIME sniffing",
        "referrer-policy": "Controls referrer leakage",
        "permissions-policy": "Restricts browser feature access",
    }

    for header, why in expected.items():
        if header in headers:
            finding("OK", f"{header}: present")
        else:
            finding("MED", f"Missing '{header}' — {why}")
            results["missing_headers"].append(header)

    # Server banner leakage
    if "server" in headers:
        finding("LOW", f"Server header exposes: {headers['server']}")
        results["server_banner"] = headers["server"]
    if "x-powered-by" in headers:
        finding("LOW", f"X-Powered-By exposes: {headers['x-powered-by']}")
        results["powered_by"] = headers["x-powered-by"]

    results["status_code"] = r.status_code
    results["final_url"] = r.url


def check_ssl(url, results):
    section("SSL/TLS Certificate")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        finding("HIGH", "Site is not served over HTTPS")
        return
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 0:
                    finding("HIGH", f"Certificate EXPIRED ({not_after.date()})")
                elif days_left < 14:
                    finding("MED", f"Certificate expires soon: {days_left} days ({not_after.date()})")
                else:
                    finding("OK", f"Certificate valid, expires {not_after.date()} ({days_left} days)")
                results["cert_expiry"] = str(not_after.date())
    except ssl.SSLCertVerificationError as e:
        finding("HIGH", f"Certificate verification failed: {e}")
    except Exception as e:
        finding("MED", f"Could not check certificate: {e}")


SENSITIVE_PATHS = [
    ".git/HEAD", ".env", ".env.local", "wp-config.php.bak", "config.php.bak",
    "backup.zip", "backup.sql", "database.sql", ".DS_Store",
    "admin/", "administrator/", "phpinfo.php", ".htaccess",
    "server-status", "web.config", ".well-known/security.txt",
]


def check_sensitive_paths(url, results):
    section("Sensitive File / Path Exposure")
    base = url if url.endswith("/") else url + "/"
    exposed = []
    for path in SENSITIVE_PATHS:
        target = urljoin(base, path)
        try:
            r = requests.get(target, timeout=TIMEOUT, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                finding("HIGH", f"Accessible: {path} (200 OK)")
                exposed.append(path)
            elif r.status_code in (301, 302, 403):
                finding("INFO", f"{path} -> {r.status_code} (exists but restricted/redirected)")
        except requests.RequestException:
            continue
    if not exposed:
        finding("OK", "No commonly-exposed sensitive paths found")
    results["exposed_paths"] = exposed


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]


def scan_ports(url, results):
    section("Common Open Ports")
    host = urlparse(url).hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        finding("HIGH", "Could not resolve hostname")
        return
    finding("INFO", f"Resolved {host} -> {ip}")
    open_ports = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                finding("INFO", f"Port {port} open")
        except socket.error:
            pass
        finally:
            s.close()
    if not open_ports:
        finding("OK", "No common ports found open (besides expected web ports)")
    results["open_ports"] = open_ports


# ---------- Phase 2: Common web vulns ----------

XSS_PAYLOAD = "<scriptx>alert(1)</scriptx>"  # inert marker, won't execute, just tests reflection
XSS_MARKER = "scriptx"

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]
SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlstate", "pg_query()", "sqlite3.operationalerror",
    "ora-01756", "microsoft odbc",
]


def discover_forms(url, results):
    section("Form / Input Discovery")
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        finding("HIGH", f"Could not fetch page: {e}")
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        finding("INFO", "No <form> elements found on this page")
    for f in forms:
        action = f.get("action") or "(self)"
        method = (f.get("method") or "GET").upper()
        inputs = [i.get("name") for i in f.find_all(["input", "textarea"]) if i.get("name")]
        finding("INFO", f"Form -> action={action} method={method} fields={inputs}")
    results["forms_found"] = len(forms)
    return forms


def test_reflected_xss(url, results):
    section("Reflected XSS Probe (safe payload)")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        finding("INFO", "No query parameters on this URL to test. "
                         "Try running against a URL with parameters, e.g. site.com/search?q=test")
        return
    vulnerable = []
    for param in qs:
        test_qs = qs.copy()
        test_qs[param] = [XSS_PAYLOAD]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            r = requests.get(test_url, timeout=TIMEOUT, verify=False)
            if XSS_MARKER in r.text:
                finding("HIGH", f"Param '{param}' reflects input unescaped (possible XSS)")
                vulnerable.append(param)
            else:
                finding("OK", f"Param '{param}' does not reflect raw payload")
        except requests.RequestException:
            continue
    results["xss_candidates"] = vulnerable


def test_sqli(url, results):
    section("SQL Injection Probe (error-based)")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        finding("INFO", "No query parameters on this URL to test.")
        return
    vulnerable = []
    for param in qs:
        for payload in SQLI_PAYLOADS:
            test_qs = qs.copy()
            test_qs[param] = [payload]
            new_query = urlencode(test_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                r = requests.get(test_url, timeout=TIMEOUT, verify=False)
                lowered = r.text.lower()
                if any(sign in lowered for sign in SQL_ERROR_SIGNS):
                    finding("HIGH", f"Param '{param}' triggered a DB error with payload {payload!r}")
                    vulnerable.append(param)
                    break
            except requests.RequestException:
                continue
        else:
            finding("OK", f"Param '{param}' — no SQL error signatures triggered")
    results["sqli_candidates"] = vulnerable


# ---------- Report ----------

def print_summary(results):
    section("Summary")
    risk_points = 0
    risk_points += len(results.get("missing_headers", [])) * 1
    risk_points += len(results.get("exposed_paths", [])) * 3
    risk_points += len(results.get("xss_candidates", [])) * 4
    risk_points += len(results.get("sqli_candidates", [])) * 5
    risk_points += len(results.get("open_ports", [])) * 1

    if risk_points == 0:
        finding("OK", "No significant issues flagged by this scan")
    elif risk_points < 5:
        finding("LOW", f"Low risk score: {risk_points} — minor hardening suggested")
    elif risk_points < 12:
        finding("MED", f"Medium risk score: {risk_points} — review flagged items")
    else:
        finding("HIGH", f"High risk score: {risk_points} — prioritize remediation")

    print(f"\n  Missing headers : {results.get('missing_headers', [])}")
    print(f"  Exposed paths   : {results.get('exposed_paths', [])}")
    print(f"  Open ports      : {results.get('open_ports', [])}")
    print(f"  XSS candidates  : {results.get('xss_candidates', [])}")
    print(f"  SQLi candidates : {results.get('sqli_candidates', [])}")
    print(f"\n  Note: This is a lightweight recon-level scan, not a substitute for a")
    print(f"  full manual pentest or a tool like Burp Suite / OWASP ZAP / Nessus.")


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Basic authorized web vulnerability scanner")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--i-have-permission", action="store_true",
                         help="Confirm you are authorized to test this target")
    parser.add_argument("--full", action="store_true",
                         help="Also run XSS/SQLi probes (needs a URL with query params for best results)")
    args = parser.parse_args()

    if not args.i_have_permission:
        print(f"{C.R}{C.BOLD}Refusing to scan.{C.END}")
        print("You must pass --i-have-permission to confirm you are authorized")
        print("(e.g. by written agreement with the company) to test this target.")
        sys.exit(1)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"{C.BOLD}Target: {url}{C.END}")
    print(f"Scan started: {datetime.datetime.now().isoformat()}")

    results = {"missing_headers": [], "errors": []}

    check_security_headers(url, results)
    check_ssl(url, results)
    check_sensitive_paths(url, results)
    scan_ports(url, results)
    discover_forms(url, results)

    if args.full:
        test_reflected_xss(url, results)
        test_sqli(url, results)
    else:
        section("Skipping XSS/SQLi probes")
        finding("INFO", "Run with --full to include XSS and SQLi probes")

    print_summary(results)


if __name__ == "__main__":
    main()
