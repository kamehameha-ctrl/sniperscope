# SniperScope v3.5 // System Architecture & Execution Flow

This document details the technical architecture of **SniperScope**, the execution flow of its concurrent asynchronous attack surface intelligence engine (EASM / OSINT), its real-time Server-Sent Events (SSE) streaming pipelines, optional outbound proxy transport, and the mathematical risk scoring model.

---

## 1. High-Level System Architecture

**SniperScope** implements a decoupled **Client-Server** architecture engineered for low-latency local execution (`localhost`) and network-wide LAN deployments (`0.0.0.0:5173` / `0.0.0.0:8000`) utilizing Vite's reverse proxy forwarding directly to FastAPI.

```mermaid
flowchart TD
    subgraph Client["Web Client (React 19 + Vite 8 + Tailwind CSS v4)"]
        AuthGate["LoginScreen\n(Operator Credentials + Constant-Time HMAC-SHA256)"]
        UI_Header["Shell Header & View Switcher\n(Split / Dossier / Topology / Digital Footprint Station)"]
        WarpIndicator["Outbound Proxy Monitor\n(Online/Standby · Latency ms · Public Egress IP)"]
        TargetInput["Target Normalizer & OPSEC Switcher\n(Passive Stealth vs Authorized Active)"]
        SessionCache["Session Storage\n(localStorage v3 - Instant Resume)"]
        Dossier["IntelDossier\n(KPIs, Open Ports, Shodan CVEDB, TLS X.509, SCA, OWASP 2025 Playbook)"]
        FootprintView["Digital Footprint Station\n(400+ Platforms SSE · Spain OSINT · Phone Hunter · Email Hunter)"]
        Graph["GraphCanvas (Cytoscape.js)\n(Force-Directed cose / Concentric Radial / Tree)"]
        NodeInspector["NodeDetails\n(Floating Side Inspector for Nodes & Attributes)"]
        ReportExporter["ForensicReportModal\n(Executive PDF / HTML / Markdown TLP:AMBER / RAW Trace .log)"]
    end

    subgraph Proxy["Transport & Proxy Layer"]
        ViteProxy["Vite Dev Server Proxy (/api -> http://127.0.0.1:8000)"]
        WARP_Tunnel["Local Forward Proxy Daemon (127.0.0.1:40000)"]
    end

    subgraph Backend["FastAPI v3.5 Asynchronous Core (Python 3.11+)"]
        AuthValidator["Operator Auth Guard (require_operator_auth via HMAC-SHA256)"]
        Orchestrator["Scan Orchestrator (/api/scan)\n(Target Normalization & Parallel Asyncio Tasks)"]
        SherlockStreamer["Sherlock Real-Time Engine (/api/sherlock/stream/{username})\n(Server-Sent Events)"]
        PhoneAnalyzer["Phone Forensics Engine (/api/osint/phone/{number})\n(CNMC Routing & Spam DBs)"]
        EmailAnalyzer["Email Intelligence Engine (/api/osint/email/{address})\n(MX/SPF, Gravatar & Dorks)"]
        MemCache["In-Memory Scan Cache (_SCAN_CACHE TTL 300s + ?refresh=true)"]
        RiskEngine["Dynamic Risk Engine (Score 0-100 · Grades A-F · Weighted Penalties)"]
        TraceBuilder["RAW Forensic Trace Logger (execution_trace Chronological Steps)"]
        GraphBuilder["Cytoscape Topological Graph Constructor (Anti-Collision Layouts)"]
    end

    subgraph Services["Reconnaissance Services (backend/services/)"]
        S_DNS["dns_scanner.py\n(A, AAAA, MX, NS, TXT, CAA, SPF, DMARC)"]
        S_CRT["crtsh_scanner.py\n(crt.sh CT Logs + Origin IP Subdomain Resolution)"]
        S_RDAP["rdap_scanner.py\n(RDAP Domain, IP, ASN & BGP Routing)"]
        S_HTTP["http_scanner.py\n(TLS X.509, CAA Validation, Uptime, WAF, CORS)"]
        S_SCA["sca_scanner.py\n(Software Composition Analysis & Component CVE Correlation)"]
        S_SHODAN["shodan_scanner.py\n(Shodan Official API + InternetDB Fallback)"]
        S_CVEDB["cve_enricher.py\n(Shodan CVEDB: CVSS, EPSS, CISA KEV, Ransomware)"]
        S_SHERLOCK["sherlock_engine.py\n(400+ Platforms Asynchronous SSE Scanner)"]
    end

    subgraph External["External Intelligence Providers & Target Perimeter"]
        Ext_DNS["Authoritative & Recursive DNS Servers"]
        Ext_CRT["crt.sh (Certificate Transparency Log)"]
        Ext_RDAP["rdap.org / Regional Internet Registries (RIRs)"]
        Ext_Shodan["api.shodan.io & internetdb.shodan.io"]
        Ext_CVEDB["cvedb.shodan.io (NIST NVD / FIRST EPSS / CISA KEV)"]
        Ext_Gazettes["Spanish Public Registries (BOE, BORME, CENDOJ, Catastro, PLACSP)"]
        Ext_Target["Target Perimeter (TLS Handshake, Security Headers, Port 22 SSH)"]
    end

    AuthGate --> UI_Header
    UI_Header --> WarpIndicator
    TargetInput --> ViteProxy
    WarpIndicator --> ViteProxy
    SherlockView -->|SSE Stream| ViteProxy
    ViteProxy --> AuthValidator
    AuthValidator --> Orchestrator
    AuthValidator --> SherlockStreamer
    AuthValidator --> PhoneAnalyzer
    AuthValidator --> EmailAnalyzer
    Orchestrator --> MemCache
    Orchestrator --> Services
    Services --> WARP_Tunnel
    WARP_Tunnel --> External
    Services --> RiskEngine
    RiskEngine --> TraceBuilder
    TraceBuilder --> GraphBuilder
```

---

## 2. Parallel Asynchronous Reconnaissance Pipeline

When an operator triggers a scan request (`GET /api/scan?target=...&mode=passive|active`), the backend initiates an asynchronous pipeline designed to minimize wall-clock latency:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Operator (Browser UI)
    participant API as FastAPI Orchestrator
    participant DNS as dns_scanner
    participant Shodan as shodan_scanner
    participant CT as crtsh_scanner
    participant HTTP as http_scanner & sca_scanner
    participant RDAP as rdap_scanner
    participant CVEDB as cve_enricher
    participant Risk as RiskEngine

    Operator->>API: GET /api/scan?target=example.com&mode=passive (Token Header)
    API->>API: Normalize target & verify HMAC-SHA256 session
    API->>DNS: Resolve DNS records (A, AAAA, MX, NS, TXT, CAA, SPF, DMARC)
    DNS-->>API: Primary IPv4/IPv6 addresses (~80ms)
    
    par Concurrent Intelligence Gathering
        API->>Shodan: Query Shodan API & InternetDB for resolved IPs
        API->>CT: Query crt.sh Certificate Transparency logs
        API->>HTTP: TLS X.509 handshake, Uptime, Security Headers, WAF, SCA Audit
        API->>RDAP: Query RDAP domain and ASN netblocks
    end

    Shodan-->>API: Ports, banners, CPEs, service vulnerabilities
    CT-->>API: Discovered subdomains list
    HTTP-->>API: TLS crypto, certificates, Web Technology components & SCA CVEs
    RDAP-->>API: Registrar, netblock, ASN & BGP info

    par Deep Enrichment
        API->>CVEDB: Enrich discovered CVEs via Shodan CVEDB (CVSS, EPSS, CISA KEV)
        API->>DNS: Resolve first 15 subdomain A records (Origin IP Detection)
    end
    CVEDB-->>API: Enriched vulnerability records
    DNS-->>API: Resolved subdomain IP mappings

    API->>Risk: Compute dynamic risk score (0-100) and findings
    API->>API: Build chronological RAW execution trace
    API->>API: Generate Cytoscape anti-collision topology
    API-->>Operator: Complete Attack Surface Intelligence JSON Payload
```

---

## 3. Sherlock SOCMINT & Spanish Public Registries Pipeline

The Sherlock reconnaissance workstation operates independently via **Server-Sent Events (SSE)**, streaming live target findings without blocking the user interface:

1. **Username SOCMINT Scanner (`/api/sherlock/stream/{username}`):**
   - Dispatches non-blocking HTTP probes across 400+ platforms across 10 categories (Coding, Social, Tech, Gaming, Finance, etc.).
   - Implements custom status code, redirect, and error-text validation to eliminate false positives.
   - Emits structured SSE events: `init`, `progress` (checked/found metrics), and `complete`.
2. **Spain OSINT Hub:**
   - Dedicated investigative hub targeting official gazettes and public administration databases:
     - **BOE** (Boletín Oficial del Estado)
     - **BORME** (Boletín Oficial del Registro Mercantil)
     - **CENDOJ** (Poder Judicial - Jurisprudencia)
     - **Sede Electrónica del Catastro**
     - **PLACSP** (Plataforma de Contratación del Sector Público)
     - **DGT** (Sanciones y distintivo ambiental)
     - **CNMV** (Comisión Nacional del Mercado de Valores)
     - **INE** (Frecuencia de apellidos y nombres)
3. **Phone Hunter (`/api/osint/phone/{number}`):**
   - International E.164 normalization, carrier routing allocation, line classification (Mobile, Fixed, VoIP), and live anti-spam reputation scoring.
4. **Email Hunter (`/api/osint/email/{address}`):**
   - Domain parsing, MX record validation, SPF/DMARC anti-spoofing audit, passive SMTP mailbox verification, live account probing, and data breach cross-referencing.

---

## 4. OPSEC Modes: Passive Stealth vs Authorized Active

| Capability | Passive / Stealth Mode (Default) | Authorized Active Mode |
| :--- | :--- | :--- |
| **Target Perimeter Probing** | **Zero packets sent to target perimeter** (100% third-party intelligence) | Targeted non-destructive active probes |
| **Web Header Inspection** | Standard root `GET /` with modern browser User-Agent | Root `GET /` + CORS Origin probing |
| **Sensitive Path Probes** | Strictly forbidden (`/.env`, `/.git/` are never queried) | Active verification of `/.git/HEAD`, `/.env`, `/swagger.json`, `/robots.txt`, `/.well-known/security.txt` |
| **SSH / Banner Grabbing** | Only passive banners retrieved via Shodan/InternetDB | Direct raw TCP socket probe to port 22 SSH to fingerprint Linux OS and package revisions |
| **Technology Versions** | Passive HTML/DOM regex and static asset URL inspection | Deep streaming Range header probes for unversioned JavaScript libraries |
| **Active CLI Playbook** | Read-only guidance | Complete 39-command playbook mapped to **OWASP Top 10: 2025** |
| **IDS / WAF Detection Risk** | None / Negligible | Low to Moderate (Strictly for authorized audit engagements) |

---

## 5. Mathematical Risk Evaluation Model

The **Risk Engine** computes a deterministic security posture score ($0 \le S \le 100$) and assigns a letter grade based on observed security weaknesses:

$$\text{Risk Score} = \min\left(100, \sum P_i\right)$$

### Penalty Weights ($P_i$)

| Condition | Penalty ($P_i$) | Severity Level |
| :--- | :---: | :---: |
| Critical exposed file path (`/.git/HEAD` or `/.env`) | $+40$ | CRITICAL |
| CISA KEV Known Exploited Vulnerabilities ($N \ge 1$) | $+35$ | CRITICAL |
| Vulnerability with active Ransomware campaign correlation | $+30$ | CRITICAL |
| Critical Severity CVEs ($\text{CVSS} \ge 9.0$) | $+25$ | CRITICAL |
| Database / Management port exposed to public Internet (3306, 5432, 27017, 6379, 3389, 23, 445) | $+20$ | HIGH |
| High Severity CVEs ($7.0 \le \text{CVSS} \le 8.9$) | $+15$ | HIGH |
| High EPSS Exploitation Probability ($\text{EPSS} \ge 20\%$) | $+15$ | HIGH |
| Missing SPF or DMARC Anti-Spoofing Records | $+10$ | MEDIUM |
| Missing Critical HTTP Security Headers ($\ge 3$ missing from HSTS, CSP, XFO, etc.) | $+8$ | MEDIUM |
| Insecure Cookie Flags (Missing `Secure` or `HttpOnly`) | $+8$ | MEDIUM |
| Medium Severity CVEs ($4.0 \le \text{CVSS} \le 6.9$) | $+8$ | MEDIUM |
| Low Severity CVEs ($\text{CVSS} < 4.0$) | $+3$ | LOW |

### Grade Mapping Scale

$$\text{Grade} = \begin{cases}
\mathbf{A} & \text{if } S < 15 \quad (\text{Optimal posture}) \\
\mathbf{B} & \text{if } 15 \le S < 30 \quad (\text{Low risk}) \\
\mathbf{C} & \text{if } 30 \le S < 50 \quad (\text{Moderate risk}) \\
\mathbf{D} & \text{if } 50 \le S < 75 \quad (\text{High risk}) \\
\mathbf{F} & \text{if } S \ge 75 \quad (\text{Critical compromise risk})
\end{cases}$$
