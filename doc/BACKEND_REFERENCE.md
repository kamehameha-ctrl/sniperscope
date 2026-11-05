# SniperScope v3.5 // Backend Technical Reference (FastAPI & OSINT Engines)

The **SniperScope** backend is built on **Python 3.11+**, **FastAPI**, and asynchronous I/O (`asyncio` + `httpx`), structured into specialized micro-services located within [`backend/services/`](file:///c:/Users/kiike/desarrolloweb/backend/services/).

---

## 1. Backend Module Architecture

```text
backend/
├── main.py                      # FastAPI Orchestrator, HMAC-SHA256 Auth, Risk Engine & RAW Traces
├── requirements.txt             # Python dependencies (fastapi, uvicorn, shodan, dnspython, httpx, dotenv)
├── .env.example                 # Secure environment configuration template
├── .env                         # Private local configuration (SHODAN_API_KEY, OUTBOUND_PROXY, credentials)
└── services/
    ├── dns_scanner.py           # Multi-record DNS resolution, CAA policy verification & SPF/DMARC audit
    ├── crtsh_scanner.py         # Certificate Transparency logs (crt.sh) & Origin IP subdomain resolver
    ├── rdap_scanner.py          # RDAP domain, IP netblock, ASN & BGP routing lookups
    ├── http_scanner.py          # TLS X.509 (who.is style), Uptime, Web Technology heuristics, WAF & cookie audit
    ├── sca_scanner.py           # Software Composition Analysis (SCA) & web component CVE correlation
    ├── shodan_scanner.py        # Official Shodan API integration + Shodan InternetDB fallback
    ├── cve_enricher.py          # Deep enrichment via Shodan CVEDB (CVSS, EPSS, CISA KEV, Ransomware)
    ├── graph_builder.py         # Cytoscape topological graph constructor with anti-collision layouts
    ├── sherlock_data.py         # 400+ platforms catalog organized across 10 specialized categories
    ├── sherlock_engine.py       # Asynchronous Server-Sent Events (SSE) streaming engine for username hunting
    ├── phone_osint.py           # Telephone forensics, Spanish CNMC carrier routing & spam databases
    └── email_osint.py           # Email domain intelligence, MX validation, Gravatar avatars & breach dorks
```

---

## 2. Reconnaissance Services Specification

### 2.1. [`dns_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/dns_scanner.py) — DNS Zone & Anti-Spoofing Audit
- Utilizes `dns.resolver.Resolver` (`dnspython`) with strict timeouts (`lifetime = 3.0s`) executed non-blockingly via `asyncio.to_thread`.
- Concurrently resolves **`A`**, **`AAAA`**, **`MX`**, **`NS`**, **`TXT`**, **`SOA`**, **`CNAME`**, and **`CAA`** records.
- **CAA (Certificate Authority Authorization) Verification:**
  - Extracts authorized CA issue properties (`issue`, `issuewild`, `iodef`).
  - Verifies whether the CA that issued the active SSL/TLS certificate possesses explicit authorization to sign certificates for the target domain.
- **Anti-Spoofing & Email Security Audit:**
  - Evaluates `TXT` records for standard **`v=spf1`** syntax and enforcement qualifiers (`-all`, `~all`, `?all`).
  - Queries `_dmarc.<target>` to verify the presence and policy (`p=none`, `p=quarantine`, `p=reject`) of **`v=DMARC1`** records.

### 2.2. [`crtsh_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/crtsh_scanner.py) — Subdomain Discovery & Origin IPs
- Queries the public **Certificate Transparency** log database (`https://crt.sh/?q=%.<target>&output=json`) with bounded request timeouts.
- Normalizes domain labels, strips wildcard prefixes (`*.`), and eliminates duplicates.
- **Function `resolve_subdomains_map()`:** Resolves `A` records for the first 15 discovered subdomains in parallel, uncovering real *Origin IP addresses* that bypass perimeter Cloud WAFs/CDNs.

### 2.3. [`rdap_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/rdap_scanner.py) — RDAP / ASN & BGP Routing
- Queries authoritative Registration Data Access Protocol (RDAP) endpoints (`rdap.org`, LACNIC, RIPE, ARIN, APNIC) for domain names and IP netblocks.
- Extracts Autonomous System Numbers (**ASN**), ISP entities, and generates verified technical links to `ipinfo.io/AS...` and `bgp.he.net/AS...`.

### 2.4. [`shodan_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/shodan_scanner.py) — Host Intelligence & Banners
- **Level 1 — Official Shodan API (`api.shodan.io`):** Queries registered API keys to retrieve organization, ISP, ASN, OS, geolocation coordinates, CPEs, open ports (`port`, `transport`, `product`, `version`), and raw service banners.
- **Level 2 — Shodan InternetDB Fallback (`internetdb.shodan.io`):** Provides zero-configuration host reconnaissance (ports, CPEs, hostnames, vulnerabilities) when no Shodan API key is supplied or rate limits are reached.

### 2.5. [`cve_enricher.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/cve_enricher.py) — Shodan CVEDB Vulnerability Intelligence
- Enriches every detected CVE in parallel against `https://cvedb.shodan.io/cve/{cve_id}` with memory caching.
- Attributes extracted: **CVSS v3/v2 Scores**, **EPSS Probability (%)**, **EPSS Percentile**, presence in the **CISA KEV** catalog, and active **Ransomware Campaign** flags.
- Direct outbound links to NIST NVD, Exploit-DB, and GitHub Proof-of-Concepts (PoCs).

### 2.6. [`http_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/http_scanner.py) — TLS X.509, Uptime & Web Security
- **who.is-Style TLS/SSL Crypto Inspection:**
  - Protocol version (`TLSv1.3`), cipher suite, public key algorithm and bit size (`EC 256-bit`, `RSA 2048-bit`), SHA-256 fingerprint, serial number in hexadecimal, full trust chain (`Root CA -> Intermediate -> Leaf`), and Subject Alternative Names (SANs).
- **Web Diagnostic & Uptime:**
  - Availability status, latency in milliseconds, Server header, parsed `<title>`, meta-description, meta-keywords, and redirect counts.
- **Web Technology Heuristic Engine (SCA):**
  - High-precision regex engine detecting frontend frameworks, CMS engines, CSS frameworks, JavaScript libraries, and reverse proxies (Astro, Next.js, React, Vue, Angular, WordPress, WooCommerce, Nginx, Apache, Cloudflare, etc.).
- **Security Headers & Cookies:**
  - Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS access-control headers, and cookie security flags (`Secure`, `HttpOnly`, `SameSite`).
- **Active Sensitive Path Probes:**
  - In Active Mode, verifies exposure of `/.git/HEAD`, `/.env`, `/swagger.json`, `/robots.txt`, and `/.well-known/security.txt`.

### 2.7. [`sca_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/sca_scanner.py) — Software Composition Analysis (SCA)
- Parses detected software component versions discovered by `http_scanner.py`.
- Correlates outdated versions (e.g., jQuery `< 3.5.0`, Bootstrap, Lodash, WordPress Core, Apache HTTP Server, Nginx, PHP) directly with known CVEs, CVSS severity ratings, attack vectors (XSS, Prototype Pollution, RCE, Path Traversal), and remediation guidelines.

### 2.8. [`sherlock_engine.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/sherlock_engine.py) & [`sherlock_data.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/sherlock_data.py) — SOCMINT Streaming
- Asynchronous generator streaming cross-platform reconnaissance over Server-Sent Events (SSE).
- Catalog of 400+ platforms across 10 categories (Coding & Dev, Social Media, Gaming, Tech, Finance, etc.).
- Custom error message matching, redirect tracking, and HTTP status verification to eliminate false positive username claims.

### 2.9. [`phone_osint.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/phone_osint.py) — Telephone Forensics
- E.164 phone number formatting and country code extraction.
- Spanish CNMC (Comisión Nacional de los Mercados y la Competencia) geographic and mobile operator block allocation.
- Direct queries to anti-spam reputation services (Listaspam) and automated PhoneInfoga Google Dork generation.

### 2.10. [`email_osint.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/email_osint.py) — Email Intelligence
- Domain and mail exchange (MX) extraction with SPF anti-spoofing diagnostics.
- Gravatar profile and avatar discovery using MD5 and SHA-256 email hashes.
- Verified Google Hacking Dorks for cross-referencing against breach databases and OSINT search engines (Epieos, Hunter.io, Hudson Rock, IntelX).

---

## 3. REST API & SSE Endpoints Reference

### 3.1. Operator Authentication

#### `POST /api/auth/login`
Authenticates operator credentials against environment variables using constant-time HMAC-SHA256 comparison.
- **Request Body:**
  ```json
  {
    "username": "sniperadmin",
    "password": "your_secure_password"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "authenticated": true,
    "username": "sniperadmin",
    "token": "sniperadmin:a8f9c0...",
    "proxy_configured": true,
    "proxy_active": true
  }
  ```

#### `GET /api/auth/verify`
Validates an existing session token.
- **Header:** `X-SniperScope-Token: <token>`
- **Response (200 OK):**
  ```json
  {
    "authenticated": true,
    "username": "sniperadmin",
    "proxy_configured": true,
    "proxy_active": true
  }
  ```

---

### 3.2. System Health & Infrastructure

#### `GET /api/health`
System status check returning backend version and proxy status.
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "engine": "SniperScope v3.1",
    "shodan_configured": true,
    "proxy_configured": true,
    "proxy_active": true
  }
  ```

#### `GET /api/shodan-status`
Checks Shodan API key connectivity, subscription plan, and query/scan credits.
- **Header:** `X-SniperScope-Token: <token>`
- **Response (200 OK):**
  ```json
  {
    "configured": true,
    "plan": "oss",
    "query_credits": 100,
    "scan_credits": 0,
    "proxy_configured": true,
    "proxy_active": true
  }
  ```

---

### 3.3. Attack Surface Reconnaissance (EASM)

#### `GET /api/scan`
Orchestrates the full parallel attack surface intelligence pipeline.
- **Header:** `X-SniperScope-Token: <token>`
- **Query Parameters:**
  - `target` (string, required): Clean domain, URL, or IPv4/IPv6 address.
  - `mode` (string, optional, default `"passive"`): `"passive"` (Stealth Mode) or `"active"` (Authorized Active Probes).
  - `refresh` (boolean, optional, default `false`): Force re-scan, bypassing 300s cache.
- **Response Schema Overview (200 OK):**
  ```json
  {
    "target": "example.com",
    "scan_mode": "passive",
    "scan_timestamp": "2026-11-04 03:00:00 UTC",
    "scan_duration_sec": 4.12,
    "is_ip": false,
    "risk": {
      "score": 12,
      "grade": "A",
      "findings": [
        {
          "title": "Missing HTTP Security Headers",
          "severity": "MEDIUM",
          "description": "Target is missing HSTS, CSP, and X-Frame-Options headers."
        }
      ]
    },
    "dns": {
      "records": { "A": ["93.184.215.14"], "MX": [], "TXT": [], "CAA": [] },
      "primary_ips": ["93.184.215.14"],
      "email_security": { "spf_present": false, "dmarc_present": false }
    },
    "subdomains": ["www.example.com", "api.example.com"],
    "subdomain_ips": [{ "subdomain": "api.example.com", "ip": "93.184.215.15" }],
    "rdap_domain": { "registrar": "Example Registrar LLC", "asn": "AS15133" },
    "http_audit": {
      "reachable": true,
      "status_code": 200,
      "server": "ECS (dcb/7ea3)",
      "tls": {
        "enabled": true,
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "public_key": "EC 256-bit",
        "fingerprint_sha256": "4A:21:..."
      },
      "wappalyzer": [],
      "security_headers": [],
      "cookies_audit": []
    },
    "shodan": [],
    "geo": {
      "ip": "93.184.215.14",
      "country": "United States",
      "country_code": "US",
      "flag": "🇺🇸",
      "city": "Norwell",
      "region": "Massachusetts",
      "coordinates": { "lat": 42.15, "lon": -70.82 },
      "isp": "MCI Communications Services",
      "asn": "AS15133",
      "asn_name": "Edgecast Inc.",
      "infra_provider": "Verizon Digital Media",
      "infra_category": "CDN / Edge Platform",
      "is_cdn": true,
      "is_hosting": true,
      "is_anycast": true
    },
    "perimeter_hosts": {
      "is_behind_cdn": true,
      "cdn_provider": "Verizon Digital Media",
      "unproxied_hosts": [],
      "has_unproxied_hosts": false
    },
    "summary": {
      "subdomains_count": 2,
      "ips_count": 1,
      "open_ports_count": 2,
      "vulnerabilities_count": 0
    },
    "vulnerabilities": [],
    "execution_trace": [
      {
        "step": "01",
        "timestamp": "2026-11-04 03:00:00.100 UTC",
        "phase": "TARGET_INITIALIZATION",
        "title": "Target Sanitization, OPSEC Profile & Classification",
        "command": "sniperscope --init --target example.com --mode passive",
        "request": "Internal Parser -> Input='example.com' | Mode='PASSIVE' | Type='DOMAIN_NAME'",
        "reasoning": "Target is normalized by stripping URI schemes and paths, configuring the OPSEC profile.",
        "raw_output": "{ ... }"
      }
    ],
    "graph": {
      "nodes": [],
      "edges": []
    }
  }
  ```

---

### 3.4. Sherlock SOCMINT & Public OSINT

#### `GET /api/sherlock/sites`
Returns the complete catalog of supported platforms and categories.
- **Header:** `X-SniperScope-Token: <token>`
- **Response (200 OK):**
  ```json
  {
    "total": 420,
    "categories": ["All", "Coding & Dev", "Social Media", "Gaming", "Tech", "Finance"],
    "sites": [
      { "name": "GitHub", "category": "Coding & Dev", "icon": "github" },
      { "name": "Twitter / X", "category": "Social Media", "icon": "twitter" }
    ]
  }
  ```

#### `GET /api/sherlock/stream/{username}`
Streams real-time platform reconnaissance results via **Server-Sent Events (SSE)**.
- **Path Parameter:** `username` (string, required)
- **Query Parameters:**
  - `category` (string, optional): Filter by category (e.g., `"Coding & Dev"`).
  - `token` (string, optional): Fallback session token for native EventSource clients.
- **Header:** `X-SniperScope-Token: <token>`
- **Response Stream (`text/event-stream`):**
  ```text
  data: {"event": "init", "username": "octocat", "total": 420}

  data: {"event": "progress", "site": "GitHub", "found": true, "url": "https://github.com/octocat", "category": "Coding & Dev", "checked": 1, "total": 420, "elapsed_ms": 140}

  data: {"event": "complete", "username": "octocat", "total_found": 15, "total_checked": 420, "elapsed_seconds": 12.4}
  ```

#### `GET /api/osint/phone/{phone_number}`
Performs phone intelligence, carrier allocation, and spam database correlation.
- **Header:** `X-SniperScope-Token: <token>`
- **Path Parameter:** `phone_number` (string, required, e.g., `"+34612345678"`)
- **Response (200 OK):**
  ```json
  {
    "query": "+34612345678",
    "valid": true,
    "country_code": "34",
    "country": "Spain",
    "operator_spain": "Telefónica Móviles España, S.A.U.",
    "phone_type": "Mobile",
    "spam_reports": 0,
    "dorks": [
      {
        "title": "PhoneInfoga Global Web Lookup",
        "dork": "\"+34612345678\" OR \"34612345678\""
      }
    ]
  }
  ```

#### `GET /api/osint/email/{email_address}`
Performs email domain verification, SPF checks, Gravatar resolution, and breach search dorks.
- **Header:** `X-SniperScope-Token: <token>`
- **Path Parameter:** `email_address` (string, required, e.g., `"audit@example.com"`)
- **Response (200 OK):**
  ```json
  {
    "email": "audit@example.com",
    "domain": "example.com",
    "mx_records": ["mail.example.com"],
    "spf_record": "v=spf1 mx ~all",
    "gravatar": {
      "exists": false,
      "avatar_url": null
    },
    "dorks": [
      {
        "title": "Epieos & Digital Identity Footprint",
        "url": "https://epieos.com/?q=audit@example.com"
      }
    ]
  }
  ```
