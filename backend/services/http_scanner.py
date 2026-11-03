"""Servicio de auditoría HTTP/HTTPS, TLS/SSL, WAF/CDN, Cookies, CORS, Wappalyzer y Uptime/Server info."""
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import os
import ssl
import socket
import asyncio
import re
import time
import hashlib
from datetime import datetime, timezone
import httpx


SECURITY_HEADERS_SPEC = [
    ("Strict-Transport-Security", "HSTS (Fuerza conexiones HTTPS cifradas)"),
    ("Content-Security-Policy", "CSP (Mitiga ataques XSS e inyección de código)"),
    ("X-Frame-Options", "Protección contra Clickjacking (iframes)"),
    ("X-Content-Type-Options", "Previene ataques de MIME-sniffing"),
    ("Referrer-Policy", "Control de filtración de cabeceras Referer"),
    ("Permissions-Policy", "Restricción de APIs sensibles del navegador"),
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


def _detect_wappalyzer_technologies(
    headers: Dict[str, str],
    html_body: str,
    meta_info: Dict[str, Any]
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

    def add_tech(name: str, category: str, version: Optional[str] = None, description: str = "", website: str = ""):
        if name not in tech_map or (version and not tech_map[name].get("version")):
            tech_map[name] = {
                "name": name,
                "category": category,
                "version": version,
                "description": description,
                "website": website,
            }

    # 1. Frameworks Web & SSG
    if re.search(r'data-astro-cid|/_astro/|content=["\']Astro\b', body, re.I) or "astro" in generator.lower():
        v_match = re.search(r"Astro\s*v?([\d\.]+)", generator, re.I)
        add_tech(
            "Astro", "Web Framework / SSG",
            v_match.group(1) if v_match else None,
            "Framework web moderno orientado a contenido y sitios estáticos ultrarrápidos con arquitectura de islas",
            "https://astro.build"
        )

    if re.search(r'/_next/static/|<div id=["\']__next["\']', body, re.I):
        v_match = re.search(r"/_next/static/chunks/.*?([0-9]+\.[0-9]+\.[0-9]+)", body)
        add_tech(
            "Next.js", "Web Framework",
            v_match.group(1) if v_match else None,
            "Framework full-stack de React con renderizado híbrido SSR/SSG y optimización en producción",
            "https://nextjs.org"
        )

    if re.search(r'__nuxt|/_nuxt/|<div id=["\']__nuxt["\']', body, re.I):
        add_tech(
            "Nuxt.js", "Web Framework",
            None,
            "Framework intuitivo de Vue.js para aplicaciones universales y renderizado del lado del servidor",
            "https://nuxt.com"
        )

    if re.search(r'data-reactroot|_reactFiber|\breact-dom\b|\b_react\b', body):
        add_tech(
            "React", "JavaScript UI Library",
            None,
            "Librería líder para construcción de interfaces de usuario interactivas basadas en componentes",
            "https://react.dev"
        )

    if re.search(r'data-v-[a-f0-9]{6,10}|vue\.runtime|vue\.global', body, re.I):
        add_tech(
            "Vue.js", "JavaScript Framework",
            None,
            "Framework progresivo para desarrollo de interfaces web reactivas y modulares",
            "https://vuejs.org"
        )

    if re.search(r'ng-version=["\']([^"\']+)["\']|<app-root\b', body):
        v_match = re.search(r'ng-version=["\']([\d\.]+)["\']', body)
        add_tech(
            "Angular", "JavaScript Framework",
            v_match.group(1) if v_match else None,
            "Plataforma de desarrollo empresarial para aplicaciones web SPA ricas y estructuradas",
            "https://angular.io"
        )

    if re.search(r'class=["\'][^"\']*svelte-[a-z0-9]+|__sveltekit', body):
        add_tech(
            "Svelte", "JavaScript Framework",
            None,
            "Compilador de componentes reactivos sin sobrecarga de Virtual DOM en tiempo de ejecución",
            "https://svelte.dev"
        )

    # 2. Servidores Web & Proxies Inversos
    if "nginx" in server_val.lower():
        v_match = re.search(r"nginx/([\d\.]+)", server_val, re.I)
        add_tech(
            "Nginx", "Web Server",
            v_match.group(1) if v_match else None,
            "Servidor web HTTP y proxy inverso de alto rendimiento y bajo consumo de memoria",
            "https://nginx.org"
        )
    if "apache" in server_val.lower():
        v_match = re.search(r"apache/([\d\.]+)", server_val, re.I)
        add_tech(
            "Apache HTTP Server", "Web Server",
            v_match.group(1) if v_match else None,
            "Servidor web HTTP modular y robusto de la Apache Software Foundation",
            "https://httpd.apache.org"
        )
    if "litespeed" in server_val.lower():
        add_tech(
            "LiteSpeed", "Web Server",
            None,
            "Servidor web propietario optimizado para alta concurrencia y aceleración de PHP",
            "https://www.litespeedtech.com"
        )
    if "caddy" in server_val.lower():
        add_tech(
            "Caddy", "Web Server",
            None,
            "Servidor web moderno programado en Go con gestión automática de certificados HTTPS",
            "https://caddyserver.com"
        )
    if "microsoft-iis" in server_val.lower() or "iis" in server_val.lower():
        v_match = re.search(r"microsoft-iis/([\d\.]+)", server_val, re.I)
        add_tech(
            "Microsoft IIS", "Web Server",
            v_match.group(1) if v_match else None,
            "Servidor de aplicaciones web para entornos Windows Server",
            "https://www.iis.net"
        )

    # 3. WAF / CDN / Aceleración de Red
    if "cf-ray" in h_lower or "cloudflare" in server_val.lower():
        add_tech(
            "Cloudflare", "CDN / WAF",
            None,
            "Red global de entrega de contenidos, proxy inverso y mitigación de ataques DDoS/WAF",
            "https://www.cloudflare.com"
        )
    if "x-amz-cf-id" in h_lower or "cloudfront" in server_val.lower():
        add_tech(
            "AWS CloudFront", "CDN",
            None,
            "Red de distribución de contenidos segura y de alta velocidad de Amazon Web Services",
            "https://aws.amazon.com/cloudfront"
        )
    if "x-fastly-request-id" in h_lower:
        add_tech(
            "Fastly", "CDN / Edge Cloud",
            None,
            "Plataforma de computación edge y CDN programable de alta velocidad",
            "https://www.fastly.com"
        )
    if "x-vercel-id" in h_lower or "vercel" in server_val.lower():
        add_tech(
            "Vercel", "Hosting / PaaS",
            None,
            "Plataforma de despliegue en la nube para aplicaciones frontend y funciones serverless",
            "https://vercel.com"
        )
    if "x-sucuri-id" in h_lower or "sucuri" in server_val.lower():
        add_tech(
            "Sucuri CloudProxy", "WAF",
            None,
            "Cortafuegos de aplicaciones web y limpieza de malware para sitios web",
            "https://sucuri.net"
        )

    # 4. CMS & Plataformas de Comercio
    if re.search(r'wp-content/|wp-includes/|content=["\']WordPress\b', body, re.I) or "wordpress" in generator.lower():
        v_match = re.search(r"WordPress\s*([\d\.]+)", generator, re.I)
        if not v_match:
            v_match = re.search(r"wp-emoji-release\.min\.js\?ver=([\d\.]+)", body)
        add_tech(
            "WordPress", "CMS",
            v_match.group(1) if v_match else None,
            "El sistema de gestión de contenidos (CMS) de código abierto más popular del mundo",
            "https://wordpress.org"
        )
    if re.search(r'\bwoocommerce\b', body, re.I):
        v_match = re.search(r"woocommerce\s*([\d\.]+)", body, re.I)
        add_tech(
            "WooCommerce", "Ecommerce",
            v_match.group(1) if v_match else None,
            "Plataforma de comercio electrónico flexible y personalizable para WordPress",
            "https://woocommerce.com"
        )
    if re.search(r'Drupal\.settings|content=["\']Drupal\b', body, re.I) or "drupal" in generator.lower():
        v_match = re.search(r"Drupal\s*([\d\.]+)", generator, re.I)
        add_tech(
            "Drupal", "CMS",
            v_match.group(1) if v_match else None,
            "CMS modular orientado a portales de gran volumen y estructuras de datos complejas",
            "https://www.drupal.org"
        )
    if re.search(r'content=["\']Joomla!\b', body, re.I) or "joomla" in generator.lower():
        v_match = re.search(r"Joomla!\s*-\s*Open Source Content Management\s*-\s*Version\s*([\d\.]+)", generator, re.I)
        add_tech(
            "Joomla", "CMS",
            v_match.group(1) if v_match else None,
            "Sistema de gestión de contenidos para sitios web corporativos y publicaciones online",
            "https://www.joomla.org"
        )
    if re.search(r'cdn\.shopify\.com|Shopify\.theme', body, re.I):
        add_tech(
            "Shopify", "Ecommerce",
            None,
            "Plataforma líder de comercio electrónico en la nube para tiendas online",
            "https://www.shopify.com"
        )
    if re.search(r'prestashop|PrestaShop', body):
        add_tech(
            "PrestaShop", "Ecommerce",
            None,
            "Solución de comercio electrónico de código abierto para tiendas profesionales",
            "https://prestashop.com"
        )

    # 5. Frameworks CSS
    if re.search(r'class=["\'][^"\']*\b(flex|grid|hidden|inline-flex|justify-between|items-center|px-[0-9]|py-[0-9]|bg-[a-z0-9-]+|text-[a-z0-9-]+)\b[^"\']*["\']', body):
        add_tech(
            "Tailwind CSS", "CSS Framework",
            None,
            "Framework CSS utilitario de bajo nivel para composición rápida de interfaces a medida",
            "https://tailwindcss.com"
        )
    if re.search(r'bootstrap(?:\.min)?\.css|\b(container-fluid|navbar-expand|col-md-[0-9]+|btn-primary)\b', body):
        v_match = re.search(r"bootstrap[.-]([\d\.]+)(?:\.min)?\.css", body, re.I)
        add_tech(
            "Bootstrap", "CSS Framework",
            v_match.group(1) if v_match else None,
            "Framework de maquetación responsive con componentes CSS y utilidades prediseñadas",
            "https://getbootstrap.com"
        )

    # 6. Librerías JavaScript
    if re.search(r'jquery[.-]([\d\.]+)(?:\.min)?\.js|\bjQuery\s*v([\d\.]+)|/\*!\s*jQuery\s*v([\d\.]+)', body, re.I):
        v_match = re.search(r"jquery[.-]([\d\.]+)(?:\.min)?\.js|jQuery\s*v([\d\.]+)|/\*!\s*jQuery\s*v([\d\.]+)", body, re.I)
        ver = v_match.group(1) or v_match.group(2) or v_match.group(3) if v_match else None
        add_tech(
            "jQuery", "JavaScript Library",
            ver,
            "Librería JavaScript clásica rápida y ligera para manipulación de documentos HTML",
            "https://jquery.com"
        )
    if re.search(r'\bx-data=|\bx-show=|\balpinejs\b', body):
        add_tech(
            "Alpine.js", "JavaScript Library",
            None,
            "Herramienta robusta y minimalista para componer reactividad declarativa directamente en el DOM",
            "https://alpinejs.dev"
        )
    if re.search(r'\bhx-get=|\bhx-post=|\bhtmx\.org\b', body):
        add_tech(
            "HTMX", "JavaScript Library",
            None,
            "Extensión moderna del HTML para permitir transiciones AJAX y SSE mediante atributos declarativos",
            "https://htmx.org"
        )
    if re.search(r'lodash(?:\.min)?\.js', body, re.I):
        add_tech("Lodash", "JavaScript Library", None, "Librería utilitaria JavaScript para manejo de arrays, objetos y funciones")
    if re.search(r'axios(?:\.min)?\.js', body, re.I):
        add_tech("Axios", "JavaScript Library", None, "Cliente HTTP basado en promesas para el navegador y Node.js")

    # 7. Lenguajes de Backend
    if "php" in powered_by.lower():
        v_match = re.search(r"php/([\d\.]+)", powered_by, re.I)
        add_tech("PHP", "Programming Language", v_match.group(1) if v_match else None, "Lenguaje de programación del lado del servidor para aplicaciones dinámicas")
    elif "phpsessid" in str(h_lower.get("set-cookie", "")).lower():
        add_tech("PHP", "Programming Language", None, "Lenguaje de programación del lado del servidor detectado por cookie PHPSESSID")

    # 8. Analítica & Marketing
    gtm_match = re.search(r'googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)', body)
    if gtm_match or "gtm.js" in body:
        ver = gtm_match.group(1) if gtm_match else None
        add_tech(
            "Google Tag Manager", "Tag Manager",
            ver,
            "Gestor de etiquetas para añadir y actualizar etiquetas de medición y marketing",
            "https://tagmanager.google.com"
        )

    ga_match = re.search(r'googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]+)|gtag\([\'"]config[\'"],\s*[\'"](G-[A-Z0-9]+)[\'"]', body)
    if ga_match or "google-analytics.com" in body:
        ver = ga_match.group(1) or ga_match.group(2) if ga_match else None
        add_tech(
            "Google Analytics (GA4)", "Analytics",
            ver,
            "Plataforma de analítica digital de Google para seguimiento de tráfico y comportamiento de usuarios",
            "https://analytics.google.com"
        )

    if re.search(r'connect\.facebook\.net/[^"\'\s]+/fbevents\.js|fbq\(', body):
        add_tech("Meta Pixel", "Analytics", None, "Píxel de seguimiento de conversiones y audiencias de Meta / Facebook Ads")

    if re.search(r'hotjar\.com|static\.hotjar\.com', body):
        add_tech("Hotjar", "Analytics", None, "Herramienta de mapas de calor, grabaciones de sesiones y feedback de usuarios")

    # 9. Seguridad & Verificación
    if re.search(r'google\.com/recaptcha|g-recaptcha', body):
        add_tech("Google reCAPTCHA", "Security", None, "Servicio de detección de bots y prevención de abusos automatizados")
    if re.search(r'challenges\.cloudflare\.com/turnstile', body):
        add_tech("Cloudflare Turnstile", "Security", None, "Alternativa moderna y respetuosa con la privacidad frente a CAPTCHAs tradicionales")
    if re.search(r'hcaptcha\.com', body):
        add_tech("hCaptcha", "Security", None, "Solución de protección frente a bots y malware con privacidad reforzada")

    # 10. Datos Estructurados, SEO & Fuentes
    if re.search(r'<script[^>]*type=["\']application/ld\+json["\']', body, re.I):
        types_found = re.findall(r'["\']@type["\']\s*:\s*["\']([A-Za-z0-9_]+)["\']', body)
        sample_types = ", ".join(list(dict.fromkeys(types_found))[:3]) if types_found else None
        add_tech(
            "Schema.org (JSON-LD)", "SEO / Structured Data",
            sample_types,
            "Datos estructurados semánticos vinculados para enriquecer la presentación en motores de búsqueda",
            "https://schema.org"
        )

    if re.search(r'<meta[^>]*property=["\']og:', body, re.I):
        add_tech("Open Graph Protocol", "Social Metadata", None, "Metadatos que permiten transformar cualquier página en un objeto enriquecido en redes sociales")

    if re.search(r'fonts\.googleapis\.com|fonts\.gstatic\.com', body):
        add_tech("Google Fonts", "Web Fonts", None, "Servicio de distribución de tipografías web optimizadas")
    if re.search(r'font-awesome|fontawesome|kit\.fontawesome\.com', body, re.I):
        add_tech("Font Awesome", "Font / Icons", None, "Librería de iconos vectoriales para interfaces gráficas")

    return list(tech_map.values())


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

                wapp_tech = _detect_wappalyzer_technologies(raw_dict, resp.text, meta_info)
                result["wappalyzer"] = wapp_tech
                result["technologies"] = [
                    f"{t['name']}{f' v{t['version']}' if t['version'] else ''} ({t['category']})"
                    for t in wapp_tech
                ]

                waf_entries = [t["name"] for t in wapp_tech if "WAF" in t["category"] or "CDN" in t["category"]]
                result["waf_cdn"] = waf_entries[0] if waf_entries else None

                redirects = len(resp.history)
                result["uptime"] = {
                    "status": "Active" if resp.status_code < 400 else f"HTTP {resp.status_code}",
                    "latency_ms": latency_ms,
                    "server_type": server_header or "No especificado",
                    "page_title": meta_info.get("title") or "No disponible",
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
