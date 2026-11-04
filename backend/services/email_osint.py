"""Servicio de inteligencia de correos electrónicos (Email OSINT estilo Epieos / Holehe).

Realiza validación sintáctica, detección de proveedores desechables/temporales,
auditoría de registros DNS (MX, SPF, DMARC), extracción de perfiles y avatares
en Gravatar, generación de enlaces a Epieos / HIBP y Google Hacking Dorks.
"""
from typing import Dict, Any, List, Optional
import re
import hashlib
import asyncio
from urllib.parse import quote
import httpx
try:
    import dns.resolver
except ImportError:
    dns = None

# Catálogo ampliado de dominios de correo temporal / desechable (Throwaway / Disposable)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "yopmail.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "sharklasers.com", "grr.la", "temp-mail.org", "tempmail.com", "tempmail.net", "10minutemail.com",
    "10minutemail.net", "throwawaymail.com", "trashmail.com", "dispostable.com", "getairmail.com",
    "fakeinbox.com", "maildrop.cc", "mohmal.com", "crazymailing.com", "mytemp.email", "nada.ltd",
    "getnada.com", "inboxkitten.com", "burnermail.io", "protonmail.ch", "mailpoof.com", "dropmail.me",
    "trashmail.net", "byom.de", "generator.email", "tempinbox.com", "spam4.me", "bccto.me",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")


async def analyze_email_address(raw_email: str) -> Dict[str, Any]:
    """Analiza una dirección de correo electrónico extrayendo inteligencia técnica y forense."""
    email = raw_email.strip().lower()
    match = EMAIL_REGEX.match(email)
    if not match:
        return {"error": "Formato de dirección de correo electrónico inválido"}

    domain = match.group(1).lower()
    username = email.split("@")[0]

    # 1. Comprobación de Correo Temporal / Desechable
    is_disposable = domain in DISPOSABLE_DOMAINS or any(domain.endswith(f".{d}") for d in DISPOSABLE_DOMAINS)

    # 2. Hash MD5 para consultas de Gravatar / Libravatar
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()

    # 3. Inspección DNS Asíncrona (MX, SPF, DMARC)
    def _resolve_dns():
        mx_hosts = []
        has_spf = False
        has_dmarc = False
        dmarc_policy = None

        if dns:
            try:
                answers = dns.resolver.resolve(domain, "MX", lifetime=2.5)
                for rdata in answers:
                    mx_hosts.append(str(rdata.exchange).rstrip("."))
            except Exception:
                pass

            try:
                txt_answers = dns.resolver.resolve(domain, "TXT", lifetime=2.0)
                for rdata in txt_answers:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                    if "v=spf1" in txt_str.lower():
                        has_spf = True
            except Exception:
                pass

            try:
                dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=2.0)
                for rdata in dmarc_answers:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                    if "v=dmarc1" in txt_str.lower():
                        has_dmarc = True
                        p_match = re.search(r"p=(none|quarantine|reject)", txt_str, re.I)
                        if p_match:
                            dmarc_policy = p_match.group(1).lower()
            except Exception:
                pass

        return mx_hosts, has_spf, has_dmarc, dmarc_policy

    mx_hosts, has_spf, has_dmarc, dmarc_policy = await asyncio.to_thread(_resolve_dns)
    mx_active = len(mx_hosts) > 0

    # 4. Sondeo Gravatar de Identidad
    gravatar_info: Dict[str, Any] = {
        "found": False,
        "avatar_url": None,
        "display_name": None,
        "profile_url": None,
        "location": None,
        "about": None,
    }

    try:
        async with httpx.AsyncClient(timeout=2.5, follow_redirects=True) as client:
            grav_resp = await client.get(f"https://en.gravatar.com/{email_hash}.json")
            if grav_resp.status_code == 200:
                data = grav_resp.json()
                entry = data.get("entry", [{}])[0]
                gravatar_info["found"] = True
                gravatar_info["avatar_url"] = entry.get("thumbnailUrl") or f"https://www.gravatar.com/avatar/{email_hash}?s=200"
                gravatar_info["display_name"] = entry.get("displayName") or entry.get("preferredUsername")
                gravatar_info["profile_url"] = entry.get("profileUrl")
                gravatar_info["location"] = entry.get("currentLocation")
                gravatar_info["about"] = entry.get("aboutMe")
            else:
                # Probar existencia del avatar directamente
                img_resp = await client.get(f"https://www.gravatar.com/avatar/{email_hash}?d=404")
                if img_resp.status_code == 200:
                    gravatar_info["found"] = True
                    gravatar_info["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
    except Exception:
        pass

    # 5. Enlaces de Pivotaje e Investigación Externa
    investigation_links = [
        {
            "name": "Epieos (Google & Social OSINT)",
            "url": f"https://epieos.com/?q={quote(email)}",
            "description": "Comprueba presencia de cuenta Google, Google ID, Calendar y reseñas públicas de Maps",
            "badge": "EPIEOS",
            "badge_color": "border-purple-500/40 text-purple-400 bg-purple-950/30"
        },
        {
            "name": "Have I Been Pwned (HIBP)",
            "url": f"https://haveibeenpwned.com/account/{quote(email)}",
            "description": "Audita si el correo electrónico ha sido comprometido en filtraciones masivas de datos conocidas",
            "badge": "BREACHES",
            "badge_color": "border-red-500/40 text-red-400 bg-red-950/30"
        },
        {
            "name": "Intelligence X (IntelX)",
            "url": f"https://intelx.io/?s={quote(email)}",
            "description": "Búsqueda en volcados de contraseñas de la Darknet, pastes públicos y archivos históricos",
            "badge": "DARKNET",
            "badge_color": "border-amber-500/40 text-amber-400 bg-amber-950/30"
        },
        {
            "name": "Hunter.io Verifier",
            "url": f"https://hunter.io/verify/{quote(email)}",
            "description": "Verificación de entregabilidad corporativa, servidor SMTP y formatos de empresa",
            "badge": "DELIVERY",
            "badge_color": "border-sky-500/40 text-sky-400 bg-sky-950/30"
        },
        {
            "name": "Google Calendar Direct Probe",
            "url": f"https://calendar.google.com/calendar/u/0/r?add={quote(email)}",
            "description": "Intenta vincular el correo a la agenda de Google Calendar para revelar nombre real del propietario",
            "badge": "GOOGLE",
            "badge_color": "border-emerald-500/40 text-emerald-400 bg-emerald-950/30"
        }
    ]

    # 6. Google Hacking Dorks para el correo
    email_dorks = [
        {
            "title": "Menciones Exactas & Huella Digital",
            "dork": f'"{email}"',
            "url": f"https://www.google.com/search?q={quote(f'\"{email}\"')}"
        },
        {
            "title": "Pastes Públicos & Leaks (Pastebin / Ghostbin)",
            "dork": f'site:pastebin.com OR site:ghostbin.com "{email}"',
            "url": f"https://www.google.com/search?q={quote(f'site:pastebin.com OR site:ghostbin.com \"{email}\"')}"
        },
        {
            "title": "Documentos Ofimáticos (PDF / XLSX / DOCX)",
            "dork": f'filetype:pdf OR filetype:xlsx OR filetype:docx "{email}"',
            "url": f"https://www.google.com/search?q={quote(f'filetype:pdf OR filetype:xlsx OR filetype:docx \"{email}\"')}"
        },
        {
            "title": "Boletines Oficiales y Administración Española (BOE / BOP)",
            "dork": f'site:boe.es OR site:dipucadiz.es OR site:madrid.org "{email}"',
            "url": f"https://www.google.com/search?q={quote(f'site:boe.es OR site:dipucadiz.es OR site:madrid.org \"{email}\"')}"
        },
        {
            "title": "Redes Profesionales y Repositorios",
            "dork": f'"{email}" site:linkedin.com OR site:github.com OR site:gitlab.com',
            "url": f"https://www.google.com/search?q={quote(f'\"{email}\" site:linkedin.com OR site:github.com OR site:gitlab.com')}"
        }
    ]

    return {
        "email": email,
        "username": username,
        "domain": domain,
        "is_disposable": is_disposable,
        "dns": {
            "mx_active": mx_active,
            "mx_hosts": mx_hosts[:5],
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "dmarc_policy": dmarc_policy,
        },
        "gravatar": gravatar_info,
        "investigation_links": investigation_links,
        "email_dorks": email_dorks,
    }
