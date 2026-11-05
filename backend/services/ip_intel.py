"""Servicio de inteligencia de red: geolocalización, clasificación de infraestructura y correlación perimetral."""
from typing import Dict, Any, List, Optional
import ipaddress
import re
import httpx


KNOWN_CDNS = {
    "cloudflare": ("Cloudflare", "CDN / WAF"),
    "akamai": ("Akamai", "CDN / Edge Platform"),
    "fastly": ("Fastly", "CDN / Edge Cloud"),
    "cloudfront": ("AWS CloudFront", "CDN"),
    "imperva": ("Imperva / Incapsula", "CDN / WAF"),
    "incapsula": ("Imperva / Incapsula", "CDN / WAF"),
    "sucuri": ("Sucuri CloudProxy", "WAF / Proxy"),
}

KNOWN_CLOUDS = {
    "amazon": ("Amazon Web Services (AWS)", "Cloud Infrastructure"),
    "aws": ("Amazon Web Services (AWS)", "Cloud Infrastructure"),
    "google": ("Google Cloud Platform (GCP)", "Cloud Infrastructure"),
    "microsoft": ("Microsoft Azure", "Cloud Infrastructure"),
    "azure": ("Microsoft Azure", "Cloud Infrastructure"),
    "digitalocean": ("DigitalOcean", "Cloud VPS"),
    "oracle": ("Oracle Cloud (OCI)", "Cloud Infrastructure"),
    "linode": ("Linode / Akamai", "Cloud VPS"),
    "vultr": ("Vultr", "Cloud VPS"),
    "alibaba": ("Alibaba Cloud", "Cloud Infrastructure"),
}

KNOWN_HOSTING = {
    "hetzner": ("Hetzner Online", "Dedicated / Cloud Hosting"),
    "ovh": ("OVHcloud", "Dedicated / Cloud Hosting"),
    "leaseweb": ("Leaseweb", "Dedicated Hosting"),
    "ionos": ("IONOS / 1&1", "Web Hosting & Cloud"),
    "contabo": ("Contabo", "VPS & Dedicated Hosting"),
    "scaleway": ("Scaleway", "Cloud & Dedicated"),
    "hostinger": ("Hostinger", "Shared & Cloud Hosting"),
    "godaddy": ("GoDaddy", "Hosting Infrastructure"),
}


def _country_code_to_flag(country_code: Optional[str]) -> str:
    """Convierte un código ISO de 2 letras en emoji de bandera (ej. 'ES' -> 🇪🇸)."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c.upper())) for c in country_code)
    except Exception:
        return "🌐"


def _is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip.strip("[]"))
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False


def _classify_provider(org_str: str, isp_str: str, as_str: str) -> Dict[str, str]:
    """Determina el tipo y nombre del proveedor a partir de cadenas de ASN/ISP/Organización."""
    combined = f"{org_str} {isp_str} {as_str}".lower()

    for pattern, (name, category) in KNOWN_CDNS.items():
        if pattern in combined:
            return {"provider": name, "category": category, "is_cdn": True}

    for pattern, (name, category) in KNOWN_CLOUDS.items():
        if pattern in combined:
            return {"provider": name, "category": category, "is_cdn": False}

    for pattern, (name, category) in KNOWN_HOSTING.items():
        if pattern in combined:
            return {"provider": name, "category": category, "is_cdn": False}

    # Detección genérica
    if any(k in combined for k in ("telecom", "telefonica", "vodafone", "orange", "comcast", "verizon", "broadband")):
        return {"provider": isp_str or org_str or "ISP Network", "category": "ISP / Residential / Commercial", "is_cdn": False}

    return {"provider": org_str or isp_str or "Autonomous System", "category": "Datacenter / Network Host", "is_cdn": False}


async def classify_and_geolocate_ip(ip: str) -> Dict[str, Any]:
    """
    Obtiene geolocalización precisa y clasificación de infraestructura para una dirección IP.
    Utiliza endpoint JSON estándar de ip-api con fallback de baja latencia.
    """
    clean_ip = ip.strip("[]")
    if not clean_ip or _is_private_ip(clean_ip):
        return {
            "ip": clean_ip,
            "country": "Local / Private Network",
            "country_code": "LOC",
            "flag": "🔒",
            "city": "Private RFC 1918",
            "region": "Local",
            "coordinates": {"lat": 0.0, "lon": 0.0},
            "isp": "Local Loopback / Intranet",
            "asn": "Private",
            "asn_name": "Private Network",
            "infra_provider": "Private Network",
            "infra_category": "Internal / Non-Routable",
            "is_cdn": False,
            "is_hosting": False,
            "is_anycast": False,
        }

    default_result: Dict[str, Any] = {
        "ip": clean_ip,
        "country": "Desconocido",
        "country_code": "UN",
        "flag": "🌐",
        "city": "Desconocido",
        "region": "Desconocido",
        "coordinates": {"lat": 0.0, "lon": 0.0},
        "isp": "Desconocido",
        "asn": "Desconocido",
        "asn_name": "Desconocido",
        "infra_provider": "Desconocido",
        "infra_category": "Host de Red",
        "is_cdn": False,
        "is_hosting": True,
        "is_anycast": False,
    }

    url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,hosting"
    try:
        async with httpx.AsyncClient(timeout=2.2, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    c_code = d.get("countryCode", "UN")
                    asn_raw = d.get("as", "")
                    asn_num = asn_raw.split()[0] if asn_raw else "Desconocido"
                    org_str = d.get("org", "")
                    isp_str = d.get("isp", "")
                    
                    classification = _classify_provider(org_str, isp_str, asn_raw)
                    is_cdn = classification["is_cdn"]

                    return {
                        "ip": clean_ip,
                        "country": d.get("country") or "Desconocido",
                        "country_code": c_code,
                        "flag": _country_code_to_flag(c_code),
                        "city": d.get("city") or "Desconocido",
                        "region": d.get("regionName") or "Desconocido",
                        "coordinates": {
                            "lat": float(d.get("lat", 0.0) or 0.0),
                            "lon": float(d.get("lon", 0.0) or 0.0)
                        },
                        "isp": isp_str or "Desconocido",
                        "asn": asn_num,
                        "asn_name": org_str or isp_str or asn_raw or "Desconocido",
                        "infra_provider": classification["provider"],
                        "infra_category": classification["category"],
                        "is_cdn": is_cdn,
                        "is_hosting": bool(d.get("hosting", True)),
                        "is_anycast": is_cdn or ("anycast" in f"{org_str} {isp_str}".lower()),
                    }
    except Exception:
        pass

    # Fallback rápido mediante RDAP si ip-api no responde
    try:
        async with httpx.AsyncClient(timeout=2.0, follow_redirects=True) as client:
            rdap_resp = await client.get(f"https://rdap.org/ip/{clean_ip}")
            if rdap_resp.status_code == 200:
                rp = rdap_resp.json()
                c_code = rp.get("country", "UN")
                name = rp.get("name", "Desconocido")
                classification = _classify_provider(name, name, name)
                default_result.update({
                    "country": c_code,
                    "country_code": c_code,
                    "flag": _country_code_to_flag(c_code),
                    "asn_name": name,
                    "infra_provider": classification["provider"],
                    "infra_category": classification["category"],
                    "is_cdn": classification["is_cdn"],
                })
    except Exception:
        pass

    return default_result


def analyze_unproxied_hosts(
    primary_geo: Dict[str, Any],
    dns_res: Dict[str, Any],
    subdomain_ips: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compara la infraestructura de la IP principal con los hosts descubiertos (MX, subdominios).
    Si el objetivo principal está tras Cloudflare/CDN, lista objetivamente qué hosts
    asociados resuelven fuera de la red del CDN (información útil de perímetro).
    """
    is_behind_cdn = bool(primary_geo.get("is_cdn", False))
    cdn_name = primary_geo.get("infra_provider") or "CDN / Proxy"

    if not is_behind_cdn:
        return {
            "is_behind_cdn": False,
            "cdn_provider": None,
            "unproxied_hosts": [],
            "has_unproxied_hosts": False,
        }

    # Recoger IPs asociadas conocidas
    discovered_entries: List[Dict[str, str]] = []

    # 1. Servidores de correo (MX)
    records = dns_res.get("records", {})
    mx_records = records.get("MX", [])
    for mx in mx_records:
        host_str = mx.get("host") if isinstance(mx, dict) else str(mx)
        if host_str:
            # Comprobar si hay IPs resueltas
            for sub in subdomain_ips:
                if sub.get("subdomain") == host_str.rstrip("."):
                    for ip in sub.get("ips", []):
                        discovered_entries.append({
                            "ip": ip,
                            "source": f"Mail Exchange ({host_str.rstrip('.')})",
                            "hostname": host_str.rstrip(".")
                        })

    # 2. Subdominios de Certificate Transparency
    for sub in subdomain_ips:
        sub_name = sub.get("subdomain", "")
        for ip in sub.get("ips", []):
            if not _is_private_ip(ip):
                discovered_entries.append({
                    "ip": ip,
                    "source": f"Subdomain ({sub_name})",
                    "hostname": sub_name
                })

    # Filtrar IPs que NO pertenecen a Cloudflare/CDN
    seen_ips = set()
    unproxied_list: List[Dict[str, Any]] = []

    for entry in discovered_entries:
        candidate_ip = entry["ip"]
        if candidate_ip in seen_ips or candidate_ip == primary_geo.get("ip"):
            continue
        seen_ips.add(candidate_ip)

        # Clasificación rápida
        unproxied_list.append({
            "ip": candidate_ip,
            "source": entry["source"],
            "hostname": entry["hostname"],
        })

    return {
        "is_behind_cdn": True,
        "cdn_provider": cdn_name,
        "unproxied_hosts": unproxied_list[:12],
        "has_unproxied_hosts": len(unproxied_list) > 0,
    }
