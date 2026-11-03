# SniperScope v3.2 // Referencia Técnica del Backend (FastAPI & Motores OSINT)

El backend de **SniperScope** está construido sobre **Python 3.11+**, **FastAPI** y programación asíncrona (`asyncio` + `httpx`), estructurado en micro-módulos especializados dentro de [`backend/services/`](file:///c:/Users/kiike/desarrolloweb/backend/services/).

---

## 1. Estructura de Módulos del Backend

```text
backend/
├── main.py                      # Orquestador FastAPI v3.2, Autenticación HMAC-SHA256, Risk Engine, Traza RAW
├── requirements.txt             # Dependencias Python (fastapi, uvicorn, shodan, dnspython, httpx, dotenv)
├── .env.example                 # Plantilla segura de variables de entorno
├── .env                         # Configuración privada (SHODAN_API_KEY, OUTBOUND_PROXY, credenciales operador)
└── services/
    ├── dns_scanner.py           # Resolución DNS multi-registro, registros CAA y auditoría SPF/DMARC
    ├── crtsh_scanner.py         # Enumeración Certificate Transparency (crt.sh) y Origin IP Resolver
    ├── rdap_scanner.py          # Consultas RDAP de dominio e infraestructura IP/ASN y BGP
    ├── http_scanner.py          # Inspección TLS X.509 (who.is style), Uptime & Server, Wappalyzer, WAF y cabeceras
    ├── shodan_scanner.py        # Integración con Shodan Official API + Fallback a Shodan InternetDB
    ├── cve_enricher.py          # Enriquecimiento paralelo contra Shodan CVEDB (CVSS, EPSS, KEV, Ransomware)
    └── graph_builder.py         # Topología Cytoscape anti-colisión con etiquetas compactas
```

---

## 2. Detalle Técnico de los Servicios (`backend/services/`)

### 2.1. [`dns_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/dns_scanner.py) — Resolución DNS, Anti-Spoofing y CAA
- Utiliza `dns.resolver.Resolver` (`dnspython`) con tiempos de espera estrictos (`lifetime = 3.0s`) ejecutado mediante `asyncio.to_thread`.
- Resuelve en paralelo registros **`A`**, **`AAAA`**, **`MX`**, **`NS`**, **`TXT`**, **`SOA`**, **`CNAME`** y **`CAA`**.
- **Comprobación CAA (Certificate Authority Authorization):**
  - Recupera las políticas CAA autorizadas (`issue`, `issuewild`, `iodef`).
  - Permite verificar si la CA que emitió el certificado SSL/TLS actual cuenta con autorización explícita para firmar certificados para el dominio.
- **Auditoría Anti-Spoofing (`email_security`):**
  - Analiza registros `TXT` buscando directivas **`v=spf1`**.
  - Consulta `_dmarc.<target>` para verificar la existencia y política (`p=none`, `p=quarantine`, `p=reject`) de **`v=DMARC1`**.

### 2.2. [`crtsh_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/crtsh_scanner.py) — Subdominios y Descubrimiento de Origin IPs
- Consulta el registro público de logs de **Certificate Transparency** (`https://crt.sh/?q=%.<target>&output=json`) con timeout controlado.
- Filtra certificados comodín (`*.`), normaliza nombres DNS y elimina duplicados.
- **Función `resolve_subdomains_map()`:** Resuelve concurrentemente los registros `A` de los primeros 15 subdominios descubiertos, detectando *Origin IPs* reales que no pasen por el CDN/WAF.

### 2.3. [`rdap_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/rdap_scanner.py) — RDAP / ASN y Enrutamiento BGP
- Consulta servidores RDAP autoritativos (`rdap.org`, LACNIC, RIPE, ARIN, APNIC) para dominios y bloques IP.
- Extrae el número de sistema autónomo (**ASN**), la entidad titular y genera hiperenlaces verificados hacia `ipinfo.io/AS...` y `bgp.he.net/AS...`.

### 2.4. [`shodan_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/shodan_scanner.py) — Inteligencia de Hosts, Servicios y Banners
- **Nivel 1 — API Oficial de Shodan (`api.shodan.io`):** Extrae organización, ISP, ASN, SO, geolocalización, CPEs y desglose completo de puertos (`port`, `transport`, `product`, `version`, `banner`, certificado SSL del servicio).
- **Nivel 2 — Fallback a Shodan InternetDB (`internetdb.shodan.io`):** Garantiza resiliencia inmediata ante restricciones o ausencia de clave Shodan.

### 2.5. [`cve_enricher.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/cve_enricher.py) — Enriquecimiento Profundo (Shodan CVEDB)
- Enriquece cada CVE en paralelo consultando `https://cvedb.shodan.io/cve/{cve_id}` con caché en memoria.
- Métricas incorporadas: **CVSS v3/v2**, **EPSS (%)**, **Percentil EPSS**, inclusión en catálogo **CISA KEV** y alertas de vinculación a campañas activas de **Ransomware**. Enlaces directos a NVD, Exploit-DB y GitHub PoCs.

### 2.6. [`http_scanner.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/http_scanner.py) — TLS X.509, Uptime, Wappalyzer, WAF y Rutas
- **Inspección TLS X.509 Estilo who.is (`inspect_tls_certificate`):**
  - Protocolo (`TLSv1.3`), algoritmo y tamaño de clave pública (ej. `EC 256-bit`, `RSA 2048-bit`), huella SHA-256 (`fingerprint`), número de serie en hexadecimal, cadena de certificación completa (`Chain: Root CA -> Intermediate CA`), SANs y validación cruzada con políticas CAA.
- **Diagnóstico Web y Uptime Estilo who.is:**
  - Estado del servidor (`Active`), latencia de respuesta en milisegundos (`latency_ms`), tipo de servidor (`Server`), título parseado (`<title>`), meta-descripción y meta-keywords.
- **Motor de Detección de Tecnologías Estilo Wappalyzer:**
  - Detección precisa basada en expresiones regulares estrictas (evitando falsos positivos en español) para: Astro, Tailwind CSS, Vue, Angular, React, WordPress, Elementor, jQuery, Bootstrap, Nginx, Apache, Cloudflare, etc., con versión detectada y categorías de stack.
- **WAF / CDN y Cabeceras:** Detección de WAFs (Cloudflare, AWS CloudFront, Akamai, etc.), validación de cabeceras de seguridad, cookies (`Secure`, `HttpOnly`, `SameSite`) y CORS.
- **Sondeo de Rutas Sensibles en Modo Activo:** Sondeo de `/.git/HEAD`, `/.env`, `/swagger.json`, etc.

### 2.7. [`graph_builder.py`](file:///c:/Users/kiike/desarrolloweb/backend/services/graph_builder.py) — Topología Cytoscape Anti-Colisión
- Construye la estructura de nodos (`target`, `ip`, `subdomain`, `port`, `cve`) y enlaces (`edges`).
- Aplica formateo compacto a las etiquetas (eliminando textos redundantes entre paréntesis en puertos y truncando subdominios largos) manteniendo los metadatos completos en el atributo `meta` de cada nodo.

---

## 3. Endpoints de la API REST

### `POST /api/login`
- **Descripción:** Autentica las credenciales de operador contra las variables de entorno utilizando HMAC-SHA256 en tiempo constante.
- **Body:** `{"username": "sniperadmin", "password": "..."}`
- **Respuesta:** `{"authenticated": true, "token": "<token_firmado>", "user": "sniperadmin"}`

### `GET /api/network-status`
- **Descripción:** Diagnostica en tiempo real la conectividad de salida y el estado del túnel anónimo (Cloudflare WARP / Proxy).
- **Respuesta:**
  ```json
  {
    "proxy_configured": true,
    "proxy_active": true,
    "proxy_url": "http://127.0.0.1:40000",
    "latency_ms": 45.2,
    "egress_ip": "104.28.x.x"
  }
  ```

### `GET /api/health`
- **Descripción:** Verifica la salud del servidor, versión del motor y estado de configuración de Shodan y proxy.

### `GET /api/scan`
- **Descripción:** Orquesta el pipeline de escaneo concurrentemente.
- **Cabecera requerida:** `X-Operator-Token: <token>`
- **Parámetros:**
  - `target` (obligatorio): Dominio, IP o URL a auditar.
  - `mode` (opcional, default `passive`): `passive` (Stealth / Cero ruido) o `active` (Auditoría profunda de rutas).
  - `refresh` (opcional, default `false`): Si es `true`, ignora la caché y re-ejecuta el escaneo.
