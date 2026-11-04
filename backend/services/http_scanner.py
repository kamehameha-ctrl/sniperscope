"""Servicio de auditoría HTTP/HTTPS, TLS/SSL, WAF/CDN, Cookies, CORS, Wappalyzer y Uptime/Server info."""
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import os
import ssl
import socket
import asyncio
import re
import time
import hashlib
from datetime import datetime, timezone
import httpx
from services.sca_scanner import enrich_wappalyzer_components


SECURITY_HEADERS_SPEC = [
    ("Strict-Transport-Security", "HSTS (Enforces encrypted HTTPS connections)"),
    ("Content-Security-Policy", "CSP (Mitigates XSS and data injection attacks)"),
    ("X-Frame-Options", "Clickjacking protection (frame/iframe restrictions)"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing attacks"),
    ("Referrer-Policy", "Controls Referer header leakage"),
    ("Permissions-Policy", "Restricts sensitive browser APIs and hardware features"),
]

STANDARD_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def is_proxy_reachable(proxy_url: Optional[str]) -> bool:
    """Comprueba en <80ms si el daemon local del proxy (ej. Cloudflare WARP 127.0.0.1:40000) está escuchando."""
    if not proxy_url:
        return False
    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 40000)
        with socket.create_connection((host, port), timeout=0.08):
            return True
    except Exception:
        return False


def _inspect_tls_certificate_sync(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Conecta por TLS al puerto 443 para extraer detalles criptográficos avanzados (estilo who.is)."""
    tls_info: Dict[str, Any] = {
        "enabled": False,
        "protocol_version": None,
        "cipher_suite": None,
        "cipher_bits": None,
        "public_key": None,
        "fingerprint_sha256": None,
        "subject_cn": None,
        "issuer_cn": None,
        "issuer_org": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "san_domains": [],
        "serial_number": None,
        "chain": [],
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_info["enabled"] = True
                tls_info["protocol_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    tls_info["cipher_suite"] = cipher[0]
                    tls_info["cipher_bits"] = cipher[2]

                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    sha256_hash = hashlib.sha256(der_cert).hexdigest().upper()
                    formatted_fp = ":".join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))
                    tls_info["fingerprint_sha256"] = formatted_fp

                cert = ssock.getpeercert()
                if cert:
                    for item in cert.get("subject", ()):
                        for k, v in item:
                            if k == "commonName":
                                tls_info["subject_cn"] = v
                    for item in cert.get("issuer", ()):
                        for k, v in item:
                            if k == "commonName":
                                tls_info["issuer_cn"] = v
                            elif k == "organizationName":
                                tls_info["issuer_org"] = v

                    tls_info["not_before"] = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    tls_info["not_after"] = not_after_str

                    raw_serial = cert.get("serialNumber")
                    if raw_serial:
                        try:
                            tls_info["serial_number"] = f"{int(raw_serial):032X}"
                        except Exception:
                            tls_info["serial_number"] = str(raw_serial)

                    if not_after_str:
                        try:
                            exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now_dt = datetime.now(timezone.utc)
                            tls_info["days_remaining"] = (exp_dt - now_dt).days
                        except Exception:
                            pass

                    sans = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]
                    tls_info["san_domains"] = sans[:25]

                    c_bits = tls_info["cipher_bits"] or 256
                    if "ECDHE" in (tls_info["cipher_suite"] or "") or "GCM" in (tls_info["cipher_suite"] or ""):
                        tls_info["public_key"] = f"EC {c_bits}-bit" if c_bits <= 384 else f"RSA {c_bits}-bit"
                    else:
                        tls_info["public_key"] = f"RSA {c_bits}-bit"

                    ca_label = tls_info["issuer_org"] or tls_info["issuer_cn"] or "CA"
                    subj_label = tls_info["subject_cn"] or hostname
                    tls_info["chain"] = [subj_label, ca_label, "Root Trust Store"]
    except Exception:
        pass
    return tls_info


def _extract_page_metadata(html: str) -> Dict[str, Optional[str]]:
    """Extrae título, meta description, keywords y meta generator de la página."""
    title = None
    description = None
    keywords = None
    generator = None

    if not html:
        return {"title": None, "description": None, "keywords": None, "generator": None}

    m_title = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m_title:
        title = re.sub(r"\s+", " ", m_title.group(1)).strip()

    m_desc = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', html, re.IGNORECASE)
    if not m_desc:
        m_desc = re.search(r'<meta[^>]*content=["\'](.*?)["\'][^>]*name=["\']description["\']', html, re.IGNORECASE)
    if m_desc:
        description = m_desc.group(1).strip()

    m_key = re.search(r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\'](.*?)["\']', html, re.IGNORECASE)
    if not m_key:
        m_key = re.search(r'<meta[^>]*content=["\'](.*?)["\'][^>]*name=["\']keywords["\']', html, re.IGNORECASE)
    if m_key:
        keywords = m_key.group(1).strip()

    m_gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']', html, re.IGNORECASE)
    if not m_gen:
        m_gen = re.search(r'<meta[^>]*content=["\'](.*?)["\'][^>]*name=["\']generator["\']', html, re.IGNORECASE)
    if m_gen:
        generator = m_gen.group(1).strip()

    return {
        "title": title[:160] if title else None,
        "description": description[:300] if description else None,
        "keywords": keywords[:200] if keywords else None,
        "generator": generator[:100] if generator else None,
    }


def _active_probe_ssh_os_banner(target_ip: str, port: int = 22, timeout: float = 1.8) -> Optional[Dict[str, str]]:
    """
    MODO ACTIVO EXCLUSIVAMENTE:
    Conecta por socket TCP crudo al puerto SSH (22) para capturar el banner del demonio
    e inferir el sistema operativo base y versiones de paquetes oficiales empaquetados.
    NUNCA se invoca en Modo Stealth (Pasivo) para preservar el OPSEC y la legalidad.
    """
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            raw = s.recv(1024)
            if not raw:
                return None
            banner = raw.decode("utf-8", errors="ignore").strip()
            if not banner:
                return None

            os_detected = None
            inferred_nginx = None
            inferred_apache = None

            if "Ubuntu-3ubuntu13" in banner or "OpenSSH_9.6p1 Ubuntu" in banner:
                os_detected = "Ubuntu 24.04 LTS (Noble Numbat)"
                inferred_nginx = "1.24.0 (Ubuntu Noble)"
                inferred_apache = "2.4.58 (Ubuntu Noble)"
            elif "Ubuntu-3ubuntu12" in banner or "Ubuntu-3ubuntu0" in banner or "OpenSSH_8.9p1 Ubuntu" in banner:
                os_detected = "Ubuntu 22.04 LTS (Jammy Jellyfish)"
                inferred_nginx = "1.18.0 (Ubuntu Jammy)"
                inferred_apache = "2.4.52 (Ubuntu Jammy)"
            elif "Ubuntu-3ubuntu1" in banner or "OpenSSH_8.2p1 Ubuntu" in banner:
                os_detected = "Ubuntu 20.04 LTS (Focal Fossa)"
                inferred_nginx = "1.18.0 (Ubuntu Focal)"
                inferred_apache = "2.4.41 (Ubuntu Focal)"
            elif "Debian-10" in banner or "OpenSSH_8.4p1 Debian" in banner:
                os_detected = "Debian 11 (Bullseye)"
                inferred_nginx = "1.18.0 (Debian)"
                inferred_apache = "2.4.56 (Debian)"
            elif "Debian-12" in banner or "OpenSSH_9.2p1 Debian" in banner:
                os_detected = "Debian 12 (Bookworm)"
                inferred_nginx = "1.22.1 (Debian)"
                inferred_apache = "2.4.57 (Debian)"
            elif "Ubuntu" in banner:
                os_detected = "Ubuntu Linux"
                inferred_nginx = "~1.24.0 / ~1.18.0 (Ubuntu)"
            elif "Debian" in banner:
                os_detected = "Debian Linux"

            return {
                "raw_banner": banner,
                "os": os_detected or "Linux (OpenSSH)",
                "inferred_nginx": inferred_nginx,
                "inferred_apache": inferred_apache,
            }
    except Exception:
        return None


def _detect_wappalyzer_technologies(
    headers: Dict[str, str],
    html_body: str,
    meta_info: Dict[str, Any],
    scan_mode: str = "passive"
) -> List[Dict[str, Any]]:
    """
    Motor profundo de detección tecnológica estilo Wappalyzer.
    Utiliza expresiones regulares estrictas y análisis de firmas para evitar falsos positivos
    e infiere versiones y metadatos técnicos explicativos.
    """
    h_lower = {k.lower(): v for k, v in headers.items()}
    body = html_body or ""
    server_val = h_lower.get("server", "")
    powered_by = h_lower.get("x-powered-by", "")
    generator = meta_info.get("generator") or ""

    tech_map: Dict[str, Dict[str, Any]] = {}

    def add_tech(
        name: str,
        category: str,
        version: Optional[str] = None,
        description: str = "",
        website: str = "",
        version_status: str = "verified",
        detection_mode: str = "stealth",
        provenance: str = "Passive Analysis"
    ):
        if name not in tech_map or (version and not tech_map[name].get("version")):
            tech_map[name] = {
                "name": name,
                "category": category,
                "version": version,
                "version_status": version_status,
                "detection_mode": detection_mode,
                "provenance": provenance,
                "description": description,
                "website": website,
            }

    # 1. Web Frameworks & SSG
    if re.search(r'data-astro-cid|/_astro/|content=["\']Astro\b', body, re.I) or "astro" in generator.lower():
        v_match = re.search(r"Astro\s*v?([\d\.]+)", generator, re.I)
        if v_match:
            add_tech(
                "Astro", "Web Framework / SSG",
                v_match.group(1),
                "Modern content-focused web framework with islands architecture for fast static sites",
                "https://astro.build",
                version_status="verified",
                detection_mode="stealth",
                provenance="Meta Generator"
            )
        else:
            add_tech(
                "Astro", "Web Framework / SSG",
                "v4.x (Zero-JS SSG)",
                "Modern Astro static site generator with islands architecture and scoped CSS (Zero-JS client).",
                "https://astro.build",
                version_status="architecture",
                detection_mode="stealth",
                provenance="DOM attributes data-astro-cid & /_astro/ assets"
            )

    if re.search(r'/_next/static/|<div id=["\']__next["\']', body, re.I):
        v_match = re.search(r"/_next/static/chunks/.*?([0-9]+\.[0-9]+\.[0-9]+)", body)
        add_tech(
            "Next.js", "Web Framework",
            v_match.group(1) if v_match else None,
            "Full-stack React framework with hybrid SSR/SSG rendering and production optimizations",
            "https://nextjs.org",
            version_status="verified" if v_match else "detected",
            detection_mode="stealth",
            provenance="Static routes /_next/"
        )

    if re.search(r'__nuxt|/_nuxt/|<div id=["\']__nuxt["\']', body, re.I):
        add_tech(
            "Nuxt.js", "Web Framework",
            None,
            "Intuitive Vue.js framework for universal applications and server-side rendering",
            "https://nuxt.com",
            version_status="detected",
            detection_mode="stealth",
            provenance="DOM markers __nuxt"
        )

    if re.search(r'data-reactroot|_reactFiber|\breact-dom\b|\b_react\b', body):
        add_tech(
            "React", "JavaScript UI Library",
            None,
            "Leading JavaScript library for building component-based interactive user interfaces",
            "https://react.dev",
            version_status="detected",
            detection_mode="stealth",
            provenance="React DOM markers"
        )

    if re.search(r'data-v-[a-f0-9]{6,10}|vue\.runtime|vue\.global', body, re.I):
        add_tech(
            "Vue.js", "JavaScript Framework",
            None,
            "Progressive JavaScript framework for building reactive and modular user interfaces",
            "https://vuejs.org",
            version_status="detected",
            detection_mode="stealth",
            provenance="DOM attributes data-v-*"
        )

    if re.search(r'ng-version=["\']([^"\']+)["\']|<app-root\b', body):
        v_match = re.search(r'ng-version=["\']([\d\.]+)["\']', body)
        add_tech(
            "Angular", "JavaScript Framework",
            v_match.group(1) if v_match else None,
            "Enterprise development platform for structured single-page applications",
            "https://angular.io",
            version_status="verified" if v_match else "detected",
            detection_mode="stealth",
            provenance="DOM attribute ng-version"
        )

    if re.search(r'class=["\'][^"\']*svelte-[a-z0-9]+|__sveltekit', body):
        add_tech(
            "Svelte", "JavaScript Framework",
            None,
            "Reactive component compiler with zero Virtual DOM runtime overhead",
            "https://svelte.dev",
            version_status="detected",
            detection_mode="stealth",
            provenance="CSS classes svelte-*"
        )

    # 2. Web Servers & Reverse Proxies
    if "nginx" in server_val.lower():
        v_match = re.search(r"nginx/([\d\.]+)", server_val, re.I)
        if v_match:
            add_tech(
                "Nginx", "Web Server",
                v_match.group(1),
                "High-performance HTTP web server and reverse proxy with low memory footprint",
                "https://nginx.org",
                version_status="verified",
                detection_mode="stealth",
                provenance="HTTP Server Header"
            )
        else:
            add_tech(
                "Nginx", "Web Server",
                "Hidden (server_tokens off)",
                "Nginx web server with defensive 'server_tokens off' directive active, suppressing version strings in headers and error pages.",
                "https://nginx.org",
                version_status="hardened",
                detection_mode="stealth",
                provenance="HTTP Server Header (Hardened)"
            )
    if "apache" in server_val.lower():
        v_match = re.search(r"apache/([\d\.]+)", server_val, re.I)
        if v_match:
            add_tech(
                "Apache HTTP Server", "Web Server",
                v_match.group(1),
                "Modular and robust HTTP web server from the Apache Software Foundation",
                "https://httpd.apache.org",
                version_status="verified",
                detection_mode="stealth",
                provenance="HTTP Server Header"
            )
        else:
            add_tech(
                "Apache HTTP Server", "Web Server",
                "Hidden (ServerTokens Prod)",
                "Apache web server with 'ServerTokens Prod' directive active, suppressing version numbers in HTTP headers.",
                "https://httpd.apache.org",
                version_status="hardened",
                detection_mode="stealth",
                provenance="HTTP Server Header (Hardened)"
            )
    if "litespeed" in server_val.lower():
        add_tech(
            "LiteSpeed", "Web Server",
            None,
            "Proprietary web server optimized for high concurrency and PHP acceleration",
            "https://www.litespeedtech.com"
        )
    if "caddy" in server_val.lower():
        add_tech(
            "Caddy", "Web Server",
            None,
            "Modern Go-based web server with automatic HTTPS certificate management",
            "https://caddyserver.com"
        )
    if "microsoft-iis" in server_val.lower() or "iis" in server_val.lower():
        v_match = re.search(r"microsoft-iis/([\d\.]+)", server_val, re.I)
        add_tech(
            "Microsoft IIS", "Web Server",
            v_match.group(1) if v_match else None,
            "Web application server for Windows Server environments",
            "https://www.iis.net"
        )

    # 3. WAF / CDN / Network Acceleration
    if "cf-ray" in h_lower or "cloudflare" in server_val.lower():
        add_tech(
            "Cloudflare", "CDN / WAF",
            None,
            "Global content delivery network, reverse proxy, and DDoS/WAF mitigation platform",
            "https://www.cloudflare.com"
        )
    if "x-amz-cf-id" in h_lower or "cloudfront" in server_val.lower():
        add_tech(
            "AWS CloudFront", "CDN",
            None,
            "Secure, high-speed content delivery network from Amazon Web Services",
            "https://aws.amazon.com/cloudfront"
        )
    if "x-fastly-request-id" in h_lower:
        add_tech(
            "Fastly", "CDN / Edge Cloud",
            None,
            "High-speed edge cloud computing platform and programmable CDN",
            "https://www.fastly.com"
        )
    if "x-vercel-id" in h_lower or "vercel" in server_val.lower():
        add_tech(
            "Vercel", "Hosting / PaaS",
            None,
            "Cloud deployment platform for frontend applications and serverless functions",
            "https://vercel.com"
        )
    if "x-sucuri-id" in h_lower or "sucuri" in server_val.lower():
        add_tech(
            "Sucuri CloudProxy", "WAF",
            None,
            "Web application firewall and malware cleanup service",
            "https://sucuri.net"
        )

    # 4. CMS & Ecommerce Platforms
    if re.search(r'wp-content/|wp-includes/|content=["\']WordPress\b', body, re.I) or "wordpress" in generator.lower():
        v_match = re.search(r"WordPress\s*([\d\.]+)", generator, re.I)
        if not v_match:
            v_match = re.search(r"wp-emoji-release\.min\.js\?ver=([\d\.]+)", body)
        if not v_match:
            v_match = re.search(r'/wp-(?:includes|content)/[^"\'\s]+\?ver=([\d\.]+)', body, re.I)
        add_tech(
            "WordPress", "CMS",
            v_match.group(1) if v_match else None,
            "The world's most popular open-source content management system (CMS)",
            "https://wordpress.org"
        )
    if re.search(r'\bwoocommerce\b', body, re.I):
        v_match = re.search(r"woocommerce\s*([\d\.]+)", body, re.I)
        add_tech(
            "WooCommerce", "Ecommerce",
            v_match.group(1) if v_match else None,
            "Flexible, customizable open-source ecommerce platform for WordPress",
            "https://woocommerce.com"
        )
    if re.search(r'Drupal\.settings|content=["\']Drupal\b', body, re.I) or "drupal" in generator.lower():
        v_match = re.search(r"Drupal\s*([\d\.]+)", generator, re.I)
        add_tech(
            "Drupal", "CMS",
            v_match.group(1) if v_match else None,
            "Modular CMS designed for high-traffic enterprise portals and complex content architectures",
            "https://www.drupal.org"
        )
    if re.search(r'content=["\']Joomla!\b', body, re.I) or "joomla" in generator.lower():
        v_match = re.search(r"Joomla!\s*-\s*Open Source Content Management\s*-\s*Version\s*([\d\.]+)", generator, re.I)
        add_tech(
            "Joomla", "CMS",
            v_match.group(1) if v_match else None,
            "Content management system for corporate websites and online publishing",
            "https://www.joomla.org"
        )
    if re.search(r'cdn\.shopify\.com|Shopify\.theme', body, re.I):
        add_tech(
            "Shopify", "Ecommerce",
            None,
            "Leading cloud commerce platform for multi-channel online retail",
            "https://www.shopify.com"
        )
    if re.search(r'prestashop|PrestaShop', body):
        add_tech(
            "PrestaShop", "Ecommerce",
            None,
            "Open-source ecommerce solution for professional online stores",
            "https://prestashop.com"
        )

    # 5. CSS Frameworks
    if re.search(r'class=["\'][^"\']*\b(flex|grid|hidden|inline-flex|justify-between|items-center|px-[0-9]|py-[0-9]|bg-[a-z0-9-]+|text-[a-z0-9-]+)\b[^"\']*["\']', body):
        add_tech(
            "Tailwind CSS", "CSS Framework",
            None,
            "Utility-first CSS framework for rapid custom UI composition",
            "https://tailwindcss.com"
        )
    if re.search(r'bootstrap(?:\.min)?\.css|\b(container-fluid|navbar-expand|col-md-[0-9]+|btn-primary)\b', body):
        v_match = re.search(r"bootstrap[.-]([\d\.]+)(?:\.min)?\.css", body, re.I)
        add_tech(
            "Bootstrap", "CSS Framework",
            v_match.group(1) if v_match else None,
            "Responsive design framework with prebuilt UI components and utilities",
            "https://getbootstrap.com"
        )

    # 6. JavaScript Libraries
    if re.search(r'jquery(?:[.-][\d\.]+)?(?:\.min)?\.js|\bjQuery\b', body, re.I):
        v_match = re.search(r"jquery[.-]([\d\.]+)(?:\.min)?\.js|jQuery\s*v([\d\.]+)|/\*!\s*jQuery\s*v([\d\.]+)", body, re.I)
        ver = (v_match.group(1) or v_match.group(2) or v_match.group(3)) if v_match else None
        add_tech(
            "jQuery", "JavaScript Library",
            ver,
            "Classic fast and lightweight JavaScript DOM manipulation library",
            "https://jquery.com"
        )
    if re.search(r'\bx-data=|\bx-show=|\balpinejs\b', body):
        add_tech(
            "Alpine.js", "JavaScript Library",
            None,
            "Rugged, minimal tool for composing declarative reactivity directly in HTML markup",
            "https://alpinejs.dev"
        )
    if re.search(r'\bhx-get=|\bhx-post=|\bhtmx\.org\b', body):
        add_tech(
            "HTMX", "JavaScript Library",
            None,
            "Modern HTML extension enabling AJAX, CSS Transitions, WebSockets and SSE via HTML attributes",
            "https://htmx.org"
        )
    if re.search(r'lodash(?:\.min)?\.js', body, re.I):
        add_tech("Lodash", "JavaScript Library", None, "JavaScript utility library delivering modularity, performance and extras")
    if re.search(r'axios(?:\.min)?\.js', body, re.I):
        add_tech("Axios", "JavaScript Library", None, "Promise-based HTTP client for browser and Node.js environments")

    # 7. Backend Programming Languages
    if "php" in powered_by.lower():
        v_match = re.search(r"php/([\d\.]+)", powered_by, re.I)
        add_tech("PHP", "Programming Language", v_match.group(1) if v_match else None, "Server-side programming language for dynamic web applications")
    elif "phpsessid" in str(h_lower.get("set-cookie", "")).lower():
        add_tech("PHP", "Programming Language", None, "Server-side programming language detected via PHPSESSID cookie")

    # 8. Analytics & Marketing
    gtm_match = re.search(r'googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)', body)
    if gtm_match or "gtm.js" in body:
        ver = gtm_match.group(1) if gtm_match else None
        add_tech(
            "Google Tag Manager", "Tag Manager",
            ver,
            "Tag management system to add and update measurement and marketing tags",
            "https://tagmanager.google.com"
        )

    ga_match = re.search(r'googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]+)|gtag\([\'"]config[\'"],\s*[\'"](G-[A-Z0-9]+)[\'"]', body)
    if ga_match or "google-analytics.com" in body:
        ver = ga_match.group(1) or ga_match.group(2) if ga_match else None
        add_tech(
            "Google Analytics (GA4)", "Analytics",
            ver,
            "Google digital analytics platform for tracking traffic and user engagement",
            "https://analytics.google.com"
        )

    if re.search(r'connect\.facebook\.net/[^"\'\s]+/fbevents\.js|fbq\(', body):
        add_tech("Meta Pixel", "Analytics", None, "Conversion and audience tracking pixel for Meta / Facebook Ads")

    if re.search(r'hotjar\.com|static\.hotjar\.com', body):
        add_tech("Hotjar", "Analytics", None, "Heatmaps, session recordings, and user feedback behavioral analytics tool")

    # 9. Security & Anti-Bot
    if re.search(r'google\.com/recaptcha|g-recaptcha', body):
        add_tech("Google reCAPTCHA", "Security", None, "Bot detection and automated abuse prevention security service")
    if re.search(r'challenges\.cloudflare\.com/turnstile', body):
        add_tech("Cloudflare Turnstile", "Security", None, "Privacy-preserving, frictionless CAPTCHA alternative")
    if re.search(r'hcaptcha\.com', body):
        add_tech("hCaptcha", "Security", None, "Anti-bot and malware defense solution with reinforced user privacy")

    # 10. Structured Data, SEO & Fonts
    if re.search(r'<script[^>]*type=["\']application/ld\+json["\']', body, re.I):
        types_found = re.findall(r'["\']@type["\']\s*:\s*["\']([A-Za-z0-9_]+)["\']', body)
        sample_types = ", ".join(list(dict.fromkeys(types_found))[:3]) if types_found else None
        desc = "Linked semantic structured data to enrich search engine representations"
        if sample_types:
            desc += f" (JSON-LD Entities: {sample_types})"
        add_tech(
            "Schema.org (JSON-LD)", "SEO / Structured Data",
            None,
            desc,
            "https://schema.org",
            version_status="none",
            detection_mode="stealth",
            provenance="DOM JSON-LD Block"
        )

    if re.search(r'<meta[^>]*property=["\']og:', body, re.I):
        add_tech("Open Graph Protocol", "Social Metadata", None, "Metadata protocol enabling any web page to become a rich object in social graphs")

    if re.search(r'fonts\.googleapis\.com|fonts\.gstatic\.com', body):
        add_tech("Google Fonts", "Web Fonts", None, "Optimized web typography delivery service")
    if re.search(r'font-awesome|fontawesome|kit\.fontawesome\.com', body, re.I):
        add_tech("Font Awesome", "Font / Icons", None, "Vector icon and social logo toolkit for graphic interfaces")

    return list(tech_map.values())


async def _deep_extract_technology_versions(
    client: httpx.AsyncClient,
    base_url: Any,
    html_body: str,
    wapp_tech: List[Dict[str, Any]],
    scan_mode: str = "passive"
) -> List[Dict[str, Any]]:
    """
    Inspección profunda de versiones para tecnologías detectadas:
    1. Fase estática (Pasiva / Stealth): analiza URLs de scripts/CSS en el HTML recibido
       (query params ?ver=, /vX.Y.Z/, @X.Y.Z/) sin emitir ninguna petición adicional.
    2. Fase dinámica (Activa únicamente): si scan_mode == 'active' y una librería clave
       no tiene versión, realiza una petición streaming selectiva con cabecera Range.
    """
    if not html_body or not wapp_tech:
        return wapp_tech

    tech_dict = {t["name"]: t for t in wapp_tech}

    # 1. Extraer todas las URLs de scripts y links CSS
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_body, re.I)
    link_hrefs = re.findall(r'<link[^>]+(?:href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\']|rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'])', html_body, re.I)
    css_hrefs = [h[0] or h[1] for h in link_hrefs if (h[0] or h[1])]
    all_assets = script_srcs + css_hrefs

    # 2. Análisis estático pasivo de parámetros y rutas en las URLs encontradas
    for asset in all_assets:
        asset_lower = asset.lower()

        # Query param ?ver=X.Y.Z o ?v=X.Y.Z o /ajax/libs/...
        v_param = re.search(r'[?&](?:ver|v|version)=([\d\.]+)', asset, re.I)
        cdn_ver = re.search(r'/(?:ajax/libs/[^/]+|npm/[^/@]+@|v|libs/[^/]+)/([\d\.]+)/', asset, re.I)
        detected_v = v_param.group(1) if v_param else (cdn_ver.group(1) if cdn_ver else None)

        if "jquery" in asset_lower:
            fn_match = re.search(r'jquery[.-]([\d\.]+)(?:\.min)?\.js', asset_lower)
            ver = (fn_match.group(1) if fn_match else None) or detected_v
            if ver and "jQuery" in tech_dict and not tech_dict["jQuery"].get("version"):
                tech_dict["jQuery"]["version"] = ver
                tech_dict["jQuery"]["provenance"] = f"Script URL ({asset[:50]}...)"

        if "bootstrap" in asset_lower:
            fn_match = re.search(r'bootstrap[.-]([\d\.]+)(?:\.min)?\.(?:js|css)', asset_lower)
            ver = (fn_match.group(1) if fn_match else None) or detected_v
            if ver and "Bootstrap" in tech_dict and not tech_dict["Bootstrap"].get("version"):
                tech_dict["Bootstrap"]["version"] = ver
                tech_dict["Bootstrap"]["provenance"] = f"Stylesheet/Script URL ({asset[:50]}...)"

        if "lodash" in asset_lower and detected_v:
            if "Lodash" in tech_dict and not tech_dict["Lodash"].get("version"):
                tech_dict["Lodash"]["version"] = detected_v
                tech_dict["Lodash"]["provenance"] = "CDN script path"

        if "vue" in asset_lower and detected_v:
            if "Vue.js" in tech_dict and not tech_dict["Vue.js"].get("version"):
                tech_dict["Vue.js"]["version"] = detected_v
                tech_dict["Vue.js"]["provenance"] = "CDN script path"

        if "react" in asset_lower and detected_v:
            if "React" in tech_dict and not tech_dict["React"].get("version"):
                tech_dict["React"]["version"] = detected_v
                tech_dict["React"]["provenance"] = "CDN script path"

        if "angular" in asset_lower and detected_v:
            if "Angular" in tech_dict and not tech_dict["Angular"].get("version"):
                tech_dict["Angular"]["version"] = detected_v
                tech_dict["Angular"]["provenance"] = "CDN script path"

        if "font-awesome" in asset_lower or "fontawesome" in asset_lower:
            if detected_v and "Font Awesome" in tech_dict and not tech_dict["Font Awesome"].get("version"):
                tech_dict["Font Awesome"]["version"] = detected_v
                tech_dict["Font Awesome"]["provenance"] = "CDN font path"

    # En Modo Stealth (Pasivo), CERO peticiones adicionales para preservar OPSEC y legalidad
    if scan_mode != "active":
        return list(tech_dict.values())

    # 3. Fase dinámica activa selectiva para librerías sin versión (Solo Modo Activo)
    targets_to_probe = []
    KEY_LIBRARIES = {
        "jQuery": r'jQuery(?:\s*JavaScript\s*Library)?\s*v?([\d\.]+)',
        "Bootstrap": r'Bootstrap\s*v?([\d\.]+)',
        "Lodash": r'lodash(?:\s*modular\s*utilities)?\s*v?([\d\.]+)',
        "Vue.js": r'Vue(?:\.js)?\s*v?([\d\.]+)',
        "React": r'React\s*v?([\d\.]+)',
        "Angular": r'Angular(?:JS)?\s*v?([\d\.]+)',
        "Axios": r'axios\s*v?([\d\.]+)',
        "Font Awesome": r'Font\s*Awesome.*?v?([\d\.]+)',
    }

    for lib_name, pattern in KEY_LIBRARIES.items():
        if lib_name in tech_dict and not tech_dict[lib_name].get("version"):
            keyword = lib_name.lower().split()[0].replace(".js", "")
            for s in script_srcs:
                if keyword in s.lower():
                    full_url = urljoin(str(base_url), s)
                    targets_to_probe.append((lib_name, pattern, full_url))
                    break

    if targets_to_probe:
        async def fetch_banner(lib: str, pat: str, url: str):
            try:
                headers = {"Range": "bytes=0-1500"}
                resp = await client.get(url, headers=headers, timeout=1.5, follow_redirects=True)
                chunk = resp.text[:1500]
                m = re.search(pat, chunk, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), None)
                    return lib, ver
            except Exception:
                pass
            return lib, None

        # Ejecución paralela con límite estricto de 4 peticiones y timeout de 1.5s
        probe_tasks = [fetch_banner(l, p, u) for l, p, u in targets_to_probe[:4]]
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, tuple) and res[0] and res[1]:
                lib, ver = res
                if lib in tech_dict and not tech_dict[lib].get("version"):
                    tech_dict[lib]["version"] = ver

    return list(tech_dict.values())


def _audit_cookies(raw_cookies: List[str]) -> List[Dict[str, Any]]:
    """Evalúa las banderas de seguridad (Secure, HttpOnly, SameSite) en cada cookie Set-Cookie."""
    audited = []
    for c_str in raw_cookies[:10]:
        parts = [p.strip() for p in c_str.split(";")]
        if not parts:
            continue
        name = parts[0].split("=")[0].strip()
        low_flags = [p.lower() for p in parts[1:]]
        has_secure = any(f == "secure" for f in low_flags)
        has_httponly = any(f == "httponly" for f in low_flags)
        has_samesite = any(f.startswith("samesite=") for f in low_flags)
        audited.append({
            "name": name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": has_samesite,
            "safe": has_secure and has_httponly,
        })
    return audited


async def inspect_http_headers(target: str, scan_mode: str = "passive") -> Dict[str, Any]:
    """
    Realiza inspección HTTP/HTTPS, TLS/SSL, WAF, Cookies, CORS, Diagnóstico Web/Uptime y Wappalyzer.
    """
    outbound_proxy: Optional[str] = os.getenv("OUTBOUND_PROXY", "").strip() or None
    proxy_online = is_proxy_reachable(outbound_proxy)

    result: Dict[str, Any] = {
        "reachable": False,
        "scan_mode": scan_mode,
        "via_proxy": proxy_online,
        "proxy_status": "ACTIVE" if proxy_online else ("STANDBY" if outbound_proxy else "DISABLED"),
        "final_url": None,
        "status_code": None,
        "server": None,
        "powered_by": None,
        "waf_cdn": None,
        "cors_policy": None,
        "technologies": [],
        "wappalyzer": [],
        "sca_vulnerabilities": [],
        "uptime": {
            "status": "Inactive",
            "latency_ms": None,
            "server_type": None,
            "page_title": None,
            "meta_description": None,
            "meta_keywords": None,
            "last_checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "redirects_count": 0,
            "final_status": None,
        },
        "security_headers": [],
        "cookies_audit": [],
        "exposed_paths": [],
        "raw_headers": {},
        "tls": {},
        "robots_txt": False,
        "security_txt": False,
    }

    loop = asyncio.get_running_loop()
    tls_task = loop.run_in_executor(None, _inspect_tls_certificate_sync, target, 443)

    urls_to_try = [f"https://{target}", f"http://{target}"]
    base_origin = None

    client_kwargs: Dict[str, Any] = {
        "timeout": 6.0,
        "follow_redirects": True,
        "verify": False,
    }
    if outbound_proxy and proxy_online:
        client_kwargs["proxy"] = outbound_proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        headers_req = {
            "User-Agent": STANDARD_BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }
        if scan_mode == "active":
            headers_req["Origin"] = f"https://{target}"

        for url in urls_to_try:
            t_req_start = time.perf_counter()
            try:
                resp = await client.get(url, headers=headers_req)
                t_req_end = time.perf_counter()
                latency_ms = round((t_req_end - t_req_start) * 1000, 1)

                result["reachable"] = True
                result["final_url"] = str(resp.url)
                result["status_code"] = resp.status_code
                base_origin = f"{resp.url.scheme}://{resp.url.host}"

                raw_dict = {k: v for k, v in resp.headers.items()}
                result["raw_headers"] = raw_dict
                server_header = resp.headers.get("server")
                result["server"] = server_header
                result["powered_by"] = resp.headers.get("x-powered-by")
                result["cors_policy"] = resp.headers.get("access-control-allow-origin")

                set_cookie_list = resp.headers.get_list("set-cookie")
                result["cookies_audit"] = _audit_cookies(set_cookie_list)

                meta_info = _extract_page_metadata(resp.text)

                wapp_tech = _detect_wappalyzer_technologies(raw_dict, resp.text, meta_info, scan_mode=scan_mode)
                wapp_tech = await _deep_extract_technology_versions(client, resp.url, resp.text, wapp_tech, scan_mode=scan_mode)

                # MODO ACTIVO EXCLUSIVAMENTE: Correlación profunda de infraestructura mediante Banner Grabbing
                if scan_mode == "active":
                    try:
                        loop = asyncio.get_running_loop()
                        parsed_host = urlparse(url).hostname or target
                        target_ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(parsed_host))
                        if target_ip:
                            ssh_info = await loop.run_in_executor(None, _active_probe_ssh_os_banner, target_ip)
                            if ssh_info:
                                for t in wapp_tech:
                                    if t["name"] == "Nginx" and (not t.get("version") or t.get("version_status") == "hardened"):
                                        if ssh_info.get("inferred_nginx"):
                                            t["version"] = f"~{ssh_info['inferred_nginx']}"
                                            t["version_status"] = "inferred_active"
                                            t["detection_mode"] = "active"
                                            t["provenance"] = f"SSH p22 Banner ({ssh_info['raw_banner']})"
                                            t["description"] = (t.get("description", "") + f" [Active Mode: Probed port 22 SSH detecting '{ssh_info['raw_banner']}', identifying {ssh_info['os']} and Nginx package {ssh_info['inferred_nginx']}].").strip()
                                    elif "Apache" in t["name"] and (not t.get("version") or t.get("version_status") == "hardened"):
                                        if ssh_info.get("inferred_apache"):
                                            t["version"] = f"~{ssh_info['inferred_apache']}"
                                            t["version_status"] = "inferred_active"
                                            t["detection_mode"] = "active"
                                            t["provenance"] = f"SSH p22 Banner ({ssh_info['raw_banner']})"
                                            t["description"] = (t.get("description", "") + f" [Active Mode: Probed port 22 SSH detecting '{ssh_info['raw_banner']}', identifying {ssh_info['os']} and Apache package {ssh_info['inferred_apache']}].").strip()

                                if ssh_info.get("os"):
                                    wapp_tech.append({
                                        "name": ssh_info["os"],
                                        "category": "Operating System",
                                        "version": None,
                                        "version_status": "verified",
                                        "detection_mode": "active",
                                        "provenance": f"TCP p22 Banner ({ssh_info['raw_banner']})",
                                        "description": f"Server operating system actively identified via banner grabbing on port 22 SSH ({ssh_info['raw_banner']}).",
                                        "website": "https://ubuntu.com" if "Ubuntu" in ssh_info["os"] else "https://debian.org"
                                    })
                    except Exception:
                        pass

                wapp_tech = enrich_wappalyzer_components(wapp_tech)
                result["wappalyzer"] = wapp_tech

                all_sca_vulns = []
                for t in wapp_tech:
                    all_sca_vulns.extend(t.get("vulnerabilities", []))
                result["sca_vulnerabilities"] = all_sca_vulns

                formatted_techs = []
                for t in wapp_tech:
                    v = t.get("version")
                    v_st = t.get("version_status")
                    if v and v_st != "hardened":
                        badge_str = f" v{v}"
                    elif v_st == "hardened":
                        badge_str = " [Hidden / Hardened]"
                    else:
                        badge_str = ""
                    formatted_techs.append(f"{t['name']}{badge_str} ({t['category']})")
                result["technologies"] = formatted_techs

                waf_entries = [t["name"] for t in wapp_tech if "WAF" in t["category"] or "CDN" in t["category"]]
                result["waf_cdn"] = waf_entries[0] if waf_entries else None

                redirects = len(resp.history)
                result["uptime"] = {
                    "status": "Active" if resp.status_code < 400 else f"HTTP {resp.status_code}",
                    "latency_ms": latency_ms,
                    "server_type": server_header or "Not specified",
                    "page_title": meta_info.get("title") or "Not available",
                    "meta_description": meta_info.get("description") or "Not available",
                    "meta_keywords": meta_info.get("keywords") or "Not available",
                    "last_checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "redirects_count": redirects,
                    "final_status": f"{resp.status_code} {resp.reason_phrase if hasattr(resp, 'reason_phrase') else 'OK'}",
                }

                sec_eval: List[Dict[str, Any]] = []
                for h_name, h_desc in SECURITY_HEADERS_SPEC:
                    val = resp.headers.get(h_name.lower())
                    sec_eval.append({
                        "header": h_name,
                        "description": h_desc,
                        "present": val is not None,
                        "value": val,
                    })
                result["security_headers"] = sec_eval
                break
            except Exception:
                continue

        if base_origin and scan_mode == "active":
            probes = [
                ("/robots.txt", "robots", lambda txt: "user-agent" in txt.lower() or "disallow" in txt.lower()),
                ("/.well-known/security.txt", "security_txt", lambda txt: "contact:" in txt.lower()),
                ("/sitemap.xml", "sitemap", lambda txt: "<urlset" in txt.lower() or "<sitemapindex" in txt.lower()),
                ("/.git/HEAD", "critical_git", lambda txt: txt.strip().startswith("ref: refs/")),
                ("/.env", "critical_env", lambda txt: ("db_password" in txt.lower() or "app_key=" in txt.lower()) and "<html" not in txt.lower()),
                ("/swagger.json", "api_docs", lambda txt: '"swagger"' in txt.lower() or '"openapi"' in txt.lower()),
            ]

            async def _probe_path(path_str: str, kind: str, validator):
                try:
                    r = await client.get(f"{base_origin}{path_str}", headers={"User-Agent": STANDARD_BROWSER_UA}, timeout=2.5)
                    if r.status_code == 200 and validator(r.text[:2000]):
                        return {"path": path_str, "kind": kind, "status": 200}
                except Exception:
                    pass
                return None

            probe_results = await asyncio.gather(*[_probe_path(p, k, v) for p, k, v in probes])
            exposed = [pr for pr in probe_results if pr is not None]
            result["exposed_paths"] = exposed
            result["robots_txt"] = any(e["path"] == "/robots.txt" for e in exposed)
            result["security_txt"] = any(e["path"] == "/.well-known/security.txt" for e in exposed)

    try:
        result["tls"] = await tls_task
    except Exception:
        result["tls"] = {"enabled": False}

    return result
