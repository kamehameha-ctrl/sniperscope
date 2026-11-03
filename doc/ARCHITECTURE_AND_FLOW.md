# SniperScope v3.2 // Arquitectura del Sistema y Flujo de Ejecución

Este documento describe la arquitectura técnica de **SniperScope**, el flujo de ejecución de su motor asíncrono de reconocimiento de superficie de ataque (EASM / OSINT), el túnel de anonimización de salida y el modelo matemático de evaluación de riesgo.

---

## 1. Esquema General de Arquitectura

**SniperScope** sigue una arquitectura desacoplada **Cliente-Servidor** diseñada para operar tanto en estación local (`localhost`) como en red local (`0.0.0.0:5173` / `0.0.0.0:8000`) mediante el proxy inverso de Vite hacia el motor FastAPI.

```mermaid
flowchart TD
    subgraph Client["Cliente Web (React 19 + Vite 8 + Tailwind CSS v4)"]
        AuthGate["LoginScreen (Credenciales Operador + HMAC-SHA256)"]
        UI_Header["Cabecera Shell & Selector de Vista (Split / Texto / Grafo)"]
        WarpIndicator["Indicador WARP / Proxy Egress (Estado · Latencia · IP Salida)"]
        TargetInput["Barra de Objetivo + Selector OPSEC (Stealth vs Activo)"]
        SessionCache["Caché Local de Sesiones (localStorage v3 - 0ms Restore)"]
        Dossier["IntelDossier (Dossier Técnico, CVEs, Web/TLS/Uptime, Wappalyzer, Playbook CLI)"]
        Graph["GraphCanvas (Cytoscape.js: Fuerza / Radial Concéntrico / Árbol)"]
        NodeInspector["NodeDetails (Inspector Flotante de Nodos)"]
        ReportExporter["ForensicReportModal (PDF / HTML / Markdown / Traza RAW .log)"]
    end

    subgraph Proxy["Capa de Transporte & Anonimización"]
        ViteProxy["Proxy Vite (/api -> http://127.0.0.1:8000)"]
        WARP_Tunnel["Túnel Local Cloudflare WARP / Socks5 (127.0.0.1:40000)"]
    end

    subgraph Backend["Motor Backend (FastAPI v3.2 + Asyncio)"]
        AuthValidator["Validador de Sesión Operador (require_operator_auth)"]
        Orchestrator["Orquestador Principal (/api/scan) + Sanitizador IPv4/IPv6/URL"]
        NetworkStatus["Monitor de Red & Egress (/api/network-status)"]
        MemCache["Caché en Memoria (_SCAN_CACHE TTL 300s + ?refresh=true)"]
        RiskEngine["Motor de Cálculo de Riesgo (Score 0-100 & Grado A-F)"]
        TraceBuilder["Generador de Traza Forense RAW (execution_trace)"]
        GraphBuilder["Constructor de Topología de Grafo con Etiquetas Compactas"]
    end

    subgraph Services["Módulos de Reconocimiento (backend/services/)"]
        S_DNS["dns_scanner.py (A, AAAA, MX, NS, TXT, CAA, SPF, DMARC)"]
        S_CRT["crtsh_scanner.py (CT Logs crt.sh + Origin IP Subdomain Resolver)"]
        S_RDAP["rdap_scanner.py (RDAP Domain, IP, ASN & BGP Routing)"]
        S_HTTP["http_scanner.py (TLS X.509, CAA check, Uptime, Wappalyzer, WAF, CORS)"]
        S_SHODAN["shodan_scanner.py (Shodan Official API + InternetDB Fallback)"]
        S_CVEDB["cve_enricher.py (Shodan CVEDB: CVSS, EPSS, CISA KEV, Ransomware)"]
    end

    subgraph External["Fuentes de Inteligencia y Objetivo"]
        Ext_DNS["Servidores DNS"]
        Ext_CRT["crt.sh (Certificate Transparency)"]
        Ext_RDAP["rdap.org / ipinfo / bgp.he.net"]
        Ext_Shodan["api.shodan.io & internetdb.shodan.io"]
        Ext_CVEDB["cvedb.shodan.io (NIST NVD / FIRST EPSS / CISA KEV)"]
        Ext_Target["Servidor Objetivo (Handshake TLS, Uptime, Headers)"]
    end

    AuthGate --> UI_Header
    UI_Header --> WarpIndicator
    TargetInput --> ViteProxy
    WarpIndicator --> ViteProxy
    ViteProxy --> AuthValidator
    AuthValidator --> Orchestrator
    AuthValidator --> NetworkStatus
    NetworkStatus --> WARP_Tunnel
    Orchestrator --> MemCache
    Orchestrator --> Services
    Services --> WARP_Tunnel
    WARP_Tunnel --> External
    Services --> RiskEngine
    RiskEngine --> TraceBuilder
    TraceBuilder --> GraphBuilder
```

---

## 2. Flujo de Ejecución del Pipeline Concurrente

Cuando el usuario solicita un reconocimiento (`/api/scan?target=...&mode=passive|active`):

1. **Autenticación:** Se comprueba el token de sesión del operador mediante cabecera `X-Operator-Token` validada con HMAC-SHA256.
2. **Sanitización:** Se extrae el hostname/IP limpio, eliminando protocolos (`http://`, `https://`) y rutas.
3. **Resolución DNS & CAA (~80 ms):** `dns_scanner.py` obtiene registros A, AAAA, MX, NS, TXT, CAA, SPF y DMARC.
4. **Disparo en Paralelo (`asyncio.gather`):**
   - `shodan_scanner.py`: Consulta de puertos, banners y versiones pasivas.
   - `crtsh_scanner.py`: Extracción de subdominios y resolución de posibles *Origin IPs*.
   - `http_scanner.py`: Inspección de TLS (algoritmo, serial, fingerprint SHA-256, CA chain), verificación cruzada con registros CAA, uptime & server info, y motor Wappalyzer. En modo activo, sondea rutas de configuración expuestas (`/.env`, `/.git/HEAD`).
   - `rdap_scanner.py`: Consulta de asignación de IP, ASN y enlaces BGP.
5. **Enriquecimiento de Vulnerabilidades:** Cada CVE reportado por Shodan se consulta contra **Shodan CVEDB** para obtener CVSS v3/v2, probabilidad EPSS, pertenencia a CISA KEV y vínculos con Ransomware.
6. **Cálculo de Riesgo y Traza RAW:** El motor pondera todos los hallazgos y genera el JSON final junto con la topología para Cytoscape.js.

---

## 3. Modos OPSEC: Stealth (Pasivo) vs Activo

| Característica | Modo Stealth (Pasivo) | Modo Activo (Autorizado) |
| :--- | :--- | :--- |
| **Sondeo Web** | GET raíz estándar con User-Agent de navegador moderno | GET raíz + sondeo de `/.env`, `/.git/HEAD`, `/swagger.json` |
| **Puertos y Servicios** | 100% Pasivo (Shodan API / InternetDB / CT Logs) | Pasivo + Comandos listos en el Playbook Activo |
| **Alerta en IDS/WAF** | Nula / Mínima | Potencial (requiere autorización contractual) |
| **Rastro en Logs** | Huella de navegación común | Peticiones identificables a rutas sensibles |
