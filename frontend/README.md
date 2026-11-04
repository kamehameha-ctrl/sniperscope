# 🎯 SniperScope // Frontend Application

High-density reactive Single Page Application (SPA) built with **React 19**, **Vite 8**, **Tailwind CSS v4**, and **Cytoscape.js**.

---

## 🚀 Development & Build

```bash
# Install frontend dependencies
npm install

# Start development server bound to LAN (0.0.0.0:5173)
npm run dev -- --host 0.0.0.0

# Production build (optimized via Vite 8 & Rolldown)
npm run build

# Static analysis and linting (Oxlint)
npm run lint
```

---

## 🏗️ Component Architecture

- **`App.jsx`**: Main application shell, Gatekeeper session management, reactive state orchestration, view layout switcher (`split`, `text`, `graph`, `sherlock`), and local session history (`localStorage`).
- **`components/LoginScreen.jsx`**: Cryptographic Gatekeeper login enforcing constant-time HMAC-SHA256 session token verification and explicit Rules of Engagement (RoE).
- **`components/TargetInput.jsx`**: Target normalizer (domains, full URLs, IPv4/IPv6), Cloudflare WARP proxy status monitor, and OPSEC profile toggle (`Passive Stealth` vs `Authorized Active`).
- **`components/IntelDossier.jsx`**: Technical intelligence dossier featuring KPI cards, open ports and services, Shodan CVEDB intelligence, TLS X.509 who.is-style crypto inspection, Web Technology Fingerprinting & SCA, security headers/cookies, DNS anti-spoofing (SPF/DMARC), and the 39-command Active CLI Playbook mapped strictly to **OWASP Top 10: 2025**.
- **`components/CveTable.jsx`**: Dynamic vulnerability matrix with filters by severity (CRITICAL, HIGH, MEDIUM, LOW), search queries, CVSS/EPSS badges, and instant graph node centering.
- **`components/GraphCanvas.jsx`**: Interactive anti-collision topological attack surface graph powered by Cytoscape.js with multi-layout switching (**Force-Directed `cose`**, **Concentric Radial `concentric`**, and **Hierarchical Tree `breadthfirst`**).
- **`components/NodeDetails.jsx`**: Floating forensic inspector displaying real-time attributes, banners, certificates, and vulnerabilities for selected graph nodes.
- **`components/SherlockView.jsx`**: Specialized **Digital Footprint** workspace featuring 4 forensic stations:
  1. **Username SOCMINT Hunter:** Real-time multi-platform scanning across 400+ platforms over Server-Sent Events (SSE).
  2. **Spain OSINT Hub:** Direct public investigative queries across official gazettes and registries (BOE, BORME, CENDOJ, Catastro, PLACSP, DGT, CNMV, INE).
  3. **Phone Hunter:** International E.164 normalization, Spanish CNMC operator block allocation, and spam reputation databases.
  4. **Email Hunter:** Domain intelligence, MX/SPF verification, Gravatar avatar resolution, and breach search dorks.
- **`components/ForensicReportModal.jsx`**: One-click exporter generating 4 compliance report formats: Executive PDF, standalone single-file HTML, Markdown tagged `TLP:AMBER`, and chronological RAW execution trace `.log`.
