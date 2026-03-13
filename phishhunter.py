#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ADVANCED PHISHING DETECTION & INFRASTRUCTURE ANALYZER
-----------------------------------------------------

Features
• DNS intelligence
• Domain age analysis
• SSL certificate inspection
• Redirect chain tracing
• Credential harvesting detection
• Suspicious keyword analysis
• Random domain detection
• JavaScript endpoint discovery
• Infrastructure mapping
• Phishing probability scoring
• Clean terminal report
• TXT logging
"""

import requests
import socket
import ssl
import re
import json
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

LOGFILE = "phishing_report.txt"


# ---------------------------------------------------
# Logging
# ---------------------------------------------------

def log(data):
    with open(LOGFILE, "a") as f:
        f.write(json.dumps(data, indent=4) + "\n\n")


# ---------------------------------------------------
# URL Parsing
# ---------------------------------------------------

def parse_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


# ---------------------------------------------------
# DNS Lookup
# ---------------------------------------------------

def dns_lookup(domain):

    records = {"A": [], "MX": [], "NS": []}

    try:
        answers = dns.resolver.resolve(domain, "A")
        records["A"] = [r.to_text() for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, "MX")
        records["MX"] = [str(r.exchange) for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, "NS")
        records["NS"] = [r.to_text() for r in answers]
    except:
        pass

    return records


# ---------------------------------------------------
# Domain Age
# ---------------------------------------------------

def domain_age(domain):

    try:
        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age = (datetime.now() - creation).days

        return creation, age

    except:
        return None, None


# ---------------------------------------------------
# SSL Certificate Info
# ---------------------------------------------------

def ssl_info(domain):

    try:

        ctx = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])
        expiry = cert["notAfter"]

        return issuer, expiry

    except:
        return None, None


# ---------------------------------------------------
# Redirect Chain
# ---------------------------------------------------

def get_redirect_chain(url):

    chain = []

    try:

        r = requests.get(url, allow_redirects=True, timeout=10)

        for resp in r.history:
            chain.append(resp.url)

        chain.append(r.url)

    except:
        pass

    return chain


# ---------------------------------------------------
# Fetch HTML
# ---------------------------------------------------

def fetch_html(url):

    try:
        r = requests.get(url, timeout=10)
        return r.text
    except:
        return ""


# ---------------------------------------------------
# Suspicious Keyword Scan
# ---------------------------------------------------

def keyword_scan(html):

    keywords = [
        "login",
        "verify",
        "update",
        "password",
        "confirm",
        "bank",
        "wallet",
        "secure",
        "account",
        "crypto"
    ]

    found = []

    html_lower = html.lower()

    for k in keywords:
        if k in html_lower:
            found.append(k)

    return found


# ---------------------------------------------------
# Credential Harvesting Detection
# ---------------------------------------------------

def detect_forms(html):

    soup = BeautifulSoup(html, "html.parser")

    alerts = []

    for form in soup.find_all("form"):

        inputs = form.find_all("input")

        types = [i.get("type") for i in inputs]

        if "password" in types:
            alerts.append("Password input field detected")

    return alerts


# ---------------------------------------------------
# External Endpoint Discovery
# ---------------------------------------------------

def extract_endpoints(html):

    endpoints = set()

    urls = re.findall(r'https?://[^\s\'"]+', html)

    for u in urls:
        endpoints.add(urlparse(u).netloc)

    return list(endpoints)


# ---------------------------------------------------
# IP Intelligence
# ---------------------------------------------------

def ip_info(domain):

    try:

        ip = socket.gethostbyname(domain)

        data = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()

        return {
            "ip": ip,
            "org": data.get("org"),
            "country": data.get("country")
        }

    except:
        return {}


# ---------------------------------------------------
# Random Domain Detection
# ---------------------------------------------------

def random_domain(domain):

    stripped = domain.replace(".", "")

    if re.match(r"[a-f0-9]{12,}", stripped):
        return True

    return False


# ---------------------------------------------------
# Phishing Risk Scoring
# ---------------------------------------------------

def phishing_score(domain, age, dns_records, redirects, keywords, forms, endpoints):

    score = 0
    reasons = []

    if age is None:
        score += 10
        reasons.append("Unknown domain age")

    elif age < 30:
        score += 25
        reasons.append("Very new domain")

    if random_domain(domain):
        score += 15
        reasons.append("Random / hashed domain name")

    if len(dns_records["MX"]) == 0:
        score += 5
        reasons.append("No MX records")

    if len(redirects) > 2:
        score += 10
        reasons.append("Multiple redirect hops")

    if len(keywords) >= 2:
        score += 10
        reasons.append("Credential related keywords")

    if len(forms) > 0:
        score += 25
        reasons.append("Password harvesting form detected")

    if len(endpoints) > 5:
        score += 10
        reasons.append("Many external endpoints")

    probability = min(score, 100)

    return probability, reasons


# ---------------------------------------------------
# Report Output
# ---------------------------------------------------

def report(domain, creation, age, dns_records, redirects,
           ipdata, keywords, forms, endpoints,
           probability, reasons):

    console.print(Panel(f"[bold red]Phishing Intelligence Report[/bold red]\n{domain}"))

    table = Table(title="Domain Intelligence")

    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Domain", domain)
    table.add_row("Creation Date", str(creation))
    table.add_row("Domain Age (days)", str(age))
    table.add_row("IP Address", str(ipdata.get("ip")))
    table.add_row("Hosting Org", str(ipdata.get("org")))
    table.add_row("Country", str(ipdata.get("country")))

    console.print(table)

    console.print("\n[bold yellow]DNS Records[/bold yellow]")
    console.print(dns_records)

    console.print("\n[bold cyan]Redirect Chain[/bold cyan]")

    for r in redirects:
        console.print(" →", r)

    console.print("\n[bold magenta]Suspicious Keywords[/bold magenta]")
    console.print(keywords)

    console.print("\n[bold red]Credential Indicators[/bold red]")
    console.print(forms)

    console.print("\n[bold green]External Endpoints[/bold green]")

    for e in endpoints:
        console.print(" •", e)

    console.print("\n[bold red]Phishing Probability[/bold red]")

    if probability > 70:
        console.print(f"[bold red]{probability}% HIGH RISK — Likely phishing[/bold red]")

    elif probability > 40:
        console.print(f"[bold yellow]{probability}% Suspicious[/bold yellow]")

    else:
        console.print(f"[bold green]{probability}% Likely safe[/bold green]")

    console.print("\n[bold]Risk Factors[/bold]")

    for r in reasons:
        console.print(" •", r)

    log({
        "domain": domain,
        "age": age,
        "dns": dns_records,
        "redirects": redirects,
        "ipinfo": ipdata,
        "keywords": keywords,
        "forms": forms,
        "endpoints": endpoints,
        "phishing_probability": probability,
        "reasons": reasons
    })


# ---------------------------------------------------
# Main
# ---------------------------------------------------

def main():

    console.print("\n[bold green]Advanced Phishing Detection Toolkit[/bold green]\n")

    url = input("Enter URL to analyze: ").strip()

    domain = parse_domain(url)

    console.print("\n[cyan]Collecting intelligence...[/cyan]\n")

    dns_records = dns_lookup(domain)

    creation, age = domain_age(domain)

    redirects = get_redirect_chain(url)

    ipdata = ip_info(domain)

    html = fetch_html(url)

    keywords = keyword_scan(html)

    forms = detect_forms(html)

    endpoints = extract_endpoints(html)

    probability, reasons = phishing_score(
        domain,
        age,
        dns_records,
        redirects,
        keywords,
        forms,
        endpoints
    )

    report(
        domain,
        creation,
        age,
        dns_records,
        redirects,
        ipdata,
        keywords,
        forms,
        endpoints,
        probability,
        reasons
    )


if __name__ == "__main__":
    main()
