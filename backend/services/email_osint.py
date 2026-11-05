"""Servicio de inteligencia de correos electrónicos (Email OSINT).

Realiza validación sintáctica, detección de proveedores desechables/temporales,
auditoría DNS (MX, SPF, DMARC), verificación pasiva de buzón (SMTP Handshake),
sondeo asíncrono de cuentas registradas en plataformas (GitHub, Duolingo, Gravatar, Archive.org)
y comprobación de brechas de seguridad masivas (Data Breaches vía XposedOrNot).
"""
from typing import Dict, Any, List, Optional
import re
import hashlib
import asyncio
import smtplib
import socket
from datetime import datetime, timezone
from urllib.parse import quote
import httpx

try:
    from services.rdap_scanner import fetch_rdap_domain
except ImportError:
    try:
        from backend.services.rdap_scanner import fetch_rdap_domain
    except ImportError:
        fetch_rdap_domain = None

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
    "disposablemail.com", "guerrillamailblock.com", "sharklasers.net", "tempail.com",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")


def _detect_provider_from_mx(mx_hosts: List[str]) -> str:
    """Clasifica el proveedor corporativo en base a sus servidores de correo MX."""
    joined = " ".join(mx_hosts).lower()
    if any(h in joined for h in ("google.com", "googlemail.com", "aspmx.l.google.com")):
        return "Google Workspace / Gmail"
    if any(h in joined for h in ("outlook.com", "protection.outlook.com", "hotmail.com")):
        return "Microsoft 365 / Exchange"
    if any(h in joined for h in ("proton.me", "protonmail.ch")):
        return "Proton Mail (Cifrado E2E)"
    if any(h in joined for h in ("zoho.com", "zoho.eu")):
        return "Zoho Mail"
    if any(h in joined for h in ("icloud.com", "apple.com")):
        return "Apple iCloud Mail"
    if any(h in joined for h in ("ovh.net", "ovh.com")):
        return "OVHcloud Mail"
    if any(h in joined for h in ("ionos.com", "1and1.com", "kundenserver.de")):
        return "IONOS / 1&1 Mail"
    if mx_hosts:
        return f"Servidor Corporativo / Dedicado ({mx_hosts[0]})"
    return "Servidor No Determinado"


def _verify_smtp_mailbox_sync(mx_host: str, email: str, domain: str) -> Dict[str, Any]:
    """Realiza un handshake SMTP pasivo (HELO -> MAIL FROM -> RCPT TO) para validar el buzón."""
    if not mx_host:
        return {
            "deliverable": False,
            "status": "NO_MX",
            "label": "Sin servidores MX configurados",
            "smtp_code": None,
        }

    try:
        # Pre-comprobación de conectividad TCP con timeout ultrarrápido (1.2s)
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(1.2)
        test_sock.connect((mx_host, 25))
        test_sock.close()

        smtp = smtplib.SMTP(host=mx_host, port=25, timeout=1.5)
        smtp.helo("sniperscope.local")
        smtp.mail("check@sniperscope.local")
        code, msg = smtp.rcpt(email)

        if code == 250:
            # Comprobación de Catch-All con un buzón aleatorio imposible
            probe_user = f"probe_check_{hash(email) % 100000}@{domain}"
            c_code, _ = smtp.rcpt(probe_user)
            smtp.quit()
            if c_code == 250:
                return {
                    "deliverable": True,
                    "status": "CATCH_ALL",
                    "label": "Dominio Catch-All (Acepta cualquier buzón)",
                    "smtp_code": 250,
                }
            return {
                "deliverable": True,
                "status": "DELIVERABLE",
                "label": "Buzón Activo (Confirmado en servidor MX)",
                "smtp_code": 250,
            }
        elif code in (550, 551, 552, 553, 554):
            smtp.quit()
            return {
                "deliverable": False,
                "status": "UNDELIVERABLE",
                "label": "Buzón Inexistente (Rechazado por MX)",
                "smtp_code": code,
            }
        else:
            smtp.quit()
            return {
                "deliverable": None,
                "status": "UNKNOWN",
                "label": f"Respuesta SMTP ({code})",
                "smtp_code": code,
            }
    except (socket.timeout, TimeoutError):
        return {
            "deliverable": None,
            "status": "FILTERED",
            "label": "No verificable directamente (Puerto 25 filtrado o protegido)",
            "smtp_code": None,
        }
    except Exception:
        return {
            "deliverable": None,
            "status": "FILTERED",
            "label": "No verificable directamente (Puerto 25 filtrado o protegido)",
            "smtp_code": None,
        }


async def _probe_github(client: httpx.AsyncClient, email: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el email tiene perfil público o commits en GitHub."""
    try:
        url = f"https://api.github.com/search/users?q={quote(email)}+in:email"
        r = await client.get(url, timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            if data.get("total_count", 0) > 0:
                item = data.get("items", [{}])[0]
                return {
                    "platform": "GitHub",
                    "found": True,
                    "username": item.get("login"),
                    "profile_url": item.get("html_url"),
                    "avatar_url": item.get("avatar_url"),
                    "category": "Desarrollo / Código",
                }
    except Exception:
        pass
    return None


async def _probe_duolingo(client: httpx.AsyncClient, email: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el correo está registrado en Duolingo."""
    try:
        url = f"https://www.duolingo.com/2017-06-30/users?email={quote(email)}"
        r = await client.get(url, timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            users = data.get("users", [])
            if users:
                u = users[0]
                pic = u.get("picture")
                if pic and not pic.startswith("http"):
                    pic = f"https:{pic}"
                return {
                    "platform": "Duolingo",
                    "found": True,
                    "username": u.get("username"),
                    "name": u.get("name"),
                    "profile_url": f"https://www.duolingo.com/profile/{u.get('username')}" if u.get("username") else None,
                    "avatar_url": pic,
                    "category": "Educación / Idiomas",
                }
    except Exception:
        pass
    return None


async def _probe_gravatar(client: httpx.AsyncClient, email_hash: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el correo tiene perfil en Gravatar / Red WordPress."""
    try:
        r = await client.get(f"https://en.gravatar.com/{email_hash}.json", timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            entry = data.get("entry", [{}])[0]
            return {
                "platform": "Gravatar / WordPress",
                "found": True,
                "username": entry.get("preferredUsername") or entry.get("displayName"),
                "name": entry.get("displayName"),
                "profile_url": entry.get("profileUrl"),
                "avatar_url": entry.get("thumbnailUrl") or f"https://www.gravatar.com/avatar/{email_hash}?s=200",
                "location": entry.get("currentLocation"),
                "about": entry.get("aboutMe"),
                "category": "Identidad Digital / Blogs",
            }
        else:
            img_r = await client.get(f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=2.0)
            if img_r.status_code == 200:
                return {
                    "platform": "Gravatar / WordPress",
                    "found": True,
                    "username": None,
                    "profile_url": f"https://en.gravatar.com/{email_hash}",
                    "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?s=200",
                    "category": "Identidad Digital",
                }
    except Exception:
        pass
    return None


def _evaluate_domain_age(rdap_data: Dict[str, Any]) -> Dict[str, Any]:
    """Evalúa la antigüedad del dominio y alerta de riesgo de suplantación o phishing."""
    created = rdap_data.get("created_date") if isinstance(rdap_data, dict) else None
    exp = rdap_data.get("expiration_date") if isinstance(rdap_data, dict) else None
    registrar = (rdap_data.get("registrar") if isinstance(rdap_data, dict) else None) or "Desconocido"

    age_days = None
    age_years = None
    age_label = "Antigüedad no determinada"
    risk_level = "LOW"
    phishing_warning = None

    if created:
        try:
            clean_dt_str = created.split("T")[0]
            dt = datetime.strptime(clean_dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = max(0, (now - dt).days)
            age_years = round(age_days / 365.25, 1)

            if age_days < 30:
                risk_level = "CRITICAL"
                age_label = f"Creado hace {age_days} día(s) ({clean_dt_str})"
                phishing_warning = "ALERTA CRÍTICA: Dominio registrado hace menos de 30 días. Muy alta probabilidad de dominio efímero de Phishing o Suplantación."
            elif age_days < 180:
                risk_level = "MEDIUM"
                age_label = f"Creado hace {round(age_days / 30)} meses ({clean_dt_str})"
                phishing_warning = "PRECAUCIÓN: Dominio reciente con menos de 6 meses de actividad."
            else:
                risk_level = "CLEAN"
                age_label = f"Registrado hace {age_years} año(s) ({clean_dt_str})"
                phishing_warning = None
        except Exception:
            pass

    return {
        "created_date": created,
        "expiration_date": exp,
        "registrar": registrar,
        "age_days": age_days,
        "age_years": age_years,
        "age_label": age_label,
        "risk_level": risk_level,
        "phishing_warning": phishing_warning,
    }


async def _probe_spotify(client: httpx.AsyncClient, email: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el correo está registrado en Spotify."""
    try:
        url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={quote(email)}"
        r = await client.get(url, timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == 20:
                return {
                    "platform": "Spotify",
                    "found": True,
                    "username": email.split("@")[0],
                    "profile_url": "https://open.spotify.com",
                    "avatar_url": None,
                    "details": "Cuenta activa en Spotify",
                    "category": "Streaming / Música",
                }
    except Exception:
        pass
    return None


async def _probe_chess_com(client: httpx.AsyncClient, username: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el usuario tiene perfil activo en Chess.com."""
    try:
        url = f"https://api.chess.com/pub/player/{quote(username)}"
        r = await client.get(url, timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            if data.get("url"):
                return {
                    "platform": "Chess.com",
                    "found": True,
                    "username": data.get("username") or username,
                    "name": data.get("name"),
                    "profile_url": data.get("url"),
                    "avatar_url": data.get("avatar"),
                    "details": f"Jugador en Chess.com ({data.get('status', 'activo')})",
                    "category": "Gaming / Ajedrez",
                }
    except Exception:
        pass
    return None


async def _probe_archive_org(client: httpx.AsyncClient, email: str) -> Optional[Dict[str, Any]]:
    """Comprueba si el correo ha subido contenido público a Internet Archive."""
    try:
        url = f"https://archive.org/advancedsearch.php?q=creator%3A%22{quote(email)}%22&fl%5B%5D=identifier&rows=1&output=json"
        r = await client.get(url, timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            num = data.get("response", {}).get("numFound", 0)
            if num > 0:
                return {
                    "platform": "Internet Archive",
                    "found": True,
                    "username": email,
                    "profile_url": f"https://archive.org/search?query=creator%3A%22{quote(email)}%22",
                    "avatar_url": None,
                    "details": f"{num} publicación(es) asociada(s)",
                    "category": "Repositorio Público",
                }
    except Exception:
        pass
    return None


async def _check_data_breaches(client: httpx.AsyncClient, email: str) -> Dict[str, Any]:
    """Comprueba filtraciones públicas de datos asociadas al correo en XposedOrNot."""
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{quote(email)}"
        r = await client.get(url, timeout=3.0)
        if r.status_code == 200:
            data = r.json()
            raw_breaches = data.get("breaches")
            if raw_breaches and isinstance(raw_breaches, list):
                breach_items = raw_breaches[0] if (len(raw_breaches) > 0 and isinstance(raw_breaches[0], list)) else raw_breaches
                count = len(breach_items)
                return {
                    "exposed": True,
                    "count": count,
                    "breaches": breach_items[:20],
                    "risk_level": "CRITICAL" if count >= 5 else "HIGH",
                    "status_label": f"EXPUESTO EN {count} FILTRACIONES MASIVAS",
                }
    except Exception:
        pass

    return {
        "exposed": False,
        "count": 0,
        "breaches": [],
        "risk_level": "CLEAN",
        "status_label": "SIN FILTRACIONES REGISTRADAS",
    }


async def analyze_email_address(raw_email: str) -> Dict[str, Any]:
    """Analiza una dirección de correo extrayendo inteligencia profunda, buzón y brechas."""
    email = raw_email.strip().lower()
    match = EMAIL_REGEX.match(email)
    if not match:
        return {"error": "Formato de dirección de correo electrónico inválido"}

    domain = match.group(1).lower()
    username = email.split("@")[0]

    # 1. Comprobación de Correo Temporal / Desechable
    is_disposable = domain in DISPOSABLE_DOMAINS or any(domain.endswith(f".{d}") for d in DISPOSABLE_DOMAINS)

    # 2. Hash MD5
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()

    # 3. Inspección DNS Asíncrona (MX, SPF, DMARC) con resolvers de alta velocidad
    def _resolve_dns():
        mx_hosts = []
        has_spf = False
        has_dmarc = False
        dmarc_policy = None

        if dns:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.lifetime = 3.0

            try:
                answers = resolver.resolve(domain, "MX")
                for rdata in answers:
                    mx_hosts.append(str(rdata.exchange).rstrip("."))
            except Exception:
                pass

            try:
                txt_answers = resolver.resolve(domain, "TXT")
                for rdata in txt_answers:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                    if "v=spf1" in txt_str.lower():
                        has_spf = True
            except Exception:
                pass

            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
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
    provider_name = _detect_provider_from_mx(mx_hosts)
    primary_mx = mx_hosts[0] if mx_hosts else None

    # 4. Lanzar en paralelo: Handshake SMTP + RDAP Antigüedad + Plataformas (GitHub, Spotify, Duolingo, Chess.com, Gravatar, Archive) + Brechas
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(headers=headers, timeout=3.5, follow_redirects=True) as client:
        smtp_task = asyncio.to_thread(_verify_smtp_mailbox_sync, primary_mx, email, domain) if primary_mx else asyncio.sleep(0, result={
            "deliverable": False, "status": "NO_MX", "label": "Sin registros MX", "smtp_code": None
        })
        rdap_task = fetch_rdap_domain(domain) if fetch_rdap_domain else asyncio.sleep(0, result={})
        github_task = _probe_github(client, email)
        spotify_task = _probe_spotify(client, email)
        duolingo_task = _probe_duolingo(client, email)
        chess_task = _probe_chess_com(client, username)
        gravatar_task = _probe_gravatar(client, email_hash)
        archive_task = _probe_archive_org(client, email)
        breaches_task = _check_data_breaches(client, email)

        smtp_res, rdap_res, gh_res, spot_res, duo_res, chess_res, grav_res, arch_res, breach_res = await asyncio.gather(
            smtp_task, rdap_task, github_task, spotify_task, duolingo_task, chess_task, gravatar_task, archive_task, breaches_task,
            return_exceptions=True
        )

    # Filtrar resultados válidos de plataformas
    registered_platforms: List[Dict[str, Any]] = []
    for r in (gh_res, spot_res, duo_res, chess_res, grav_res, arch_res):
        if isinstance(r, dict) and r.get("found"):
            registered_platforms.append(r)

    if isinstance(smtp_res, Exception) or not isinstance(smtp_res, dict):
        smtp_res = {
            "deliverable": None,
            "status": "FILTERED",
            "label": "No verificable directamente (Puerto 25 filtrado)",
            "smtp_code": None
        }

    domain_age = _evaluate_domain_age(rdap_res) if (isinstance(rdap_res, dict) and rdap_res) else {
        "created_date": None,
        "expiration_date": None,
        "registrar": "Desconocido",
        "age_days": None,
        "age_years": None,
        "age_label": "Antigüedad no disponible",
        "risk_level": "LOW",
        "phishing_warning": None,
    }

    if isinstance(breach_res, Exception) or not isinstance(breach_res, dict):
        breach_res = {
            "exposed": False,
            "count": 0,
            "breaches": [],
            "risk_level": "CLEAN",
            "status_label": "SIN DATOS DE BRECHAS DISPONIBLES"
        }

    # 5. Enlaces directos esenciales (Sin saturación de la interfaz)
    quick_links = [
        {
            "name": "Have I Been Pwned",
            "url": f"https://haveibeenpwned.com/account/{quote(email)}",
            "label": "Auditoría HIBP",
        },
        {
            "name": "Google Calendar Direct Probe",
            "url": f"https://calendar.google.com/calendar/u/0/r?add={quote(email)}",
            "label": "Sondear Calendar",
        },
        {
            "name": "Google Identity Lookup",
            "url": f"https://www.google.com/search?q={quote(f'\"{email}\"')}",
            "label": "Rastrear Huella en Google",
        },
    ]

    return {
        "email": email,
        "username": username,
        "domain": domain,
        "provider": provider_name,
        "domain_age": domain_age,
        "is_disposable": is_disposable,
        "mailbox": smtp_res,
        "dns": {
            "mx_active": len(mx_hosts) > 0,
            "mx_hosts": mx_hosts[:4],
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "dmarc_policy": dmarc_policy,
        },
        "registered_platforms": registered_platforms,
        "breaches": breach_res,
        "quick_links": quick_links,
    }
