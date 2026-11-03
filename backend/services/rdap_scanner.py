"""Servicio de consulta WHOIS / RDAP (Registration Data Access Protocol)."""
from typing import Dict, Any, Optional
import httpx


async def fetch_rdap_domain(domain: str) -> Dict[str, Any]:
    """Obtiene datos de registro de dominio mediante RDAP estándar."""
    url = f"https://rdap.org/domain/{domain}"
    data: Dict[str, Any] = {
        "domain": domain,
        "registrar": "Desconocido",
        "created_date": None,
        "expiration_date": None,
        "status": [],
        "nameservers": [],
    }

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                payload = resp.json()
                data["status"] = payload.get("status", [])
                
                # Nombres de servidores
                ns_list = payload.get("nameservers", [])
                data["nameservers"] = [ns.get("ldhName", "") for ns in ns_list if "ldhName" in ns]

                # Eventos (fechas de registro y vencimiento)
                events = payload.get("events", [])
                for ev in events:
                    action = ev.get("eventAction")
                    date = ev.get("eventDate")
                    if action == "registration":
                        data["created_date"] = date
                    elif action == "expiration":
                        data["expiration_date"] = date

                # Entidades (Registrador)
                entities = payload.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) > 3 and item[0] == "fn":
                                    data["registrar"] = item[3]
                                    break
    except Exception:
        pass

    return data


async def fetch_rdap_ip(ip: str) -> Dict[str, Any]:
    """Obtiene información de red, ASN e ISP para una dirección IP."""
    url = f"https://rdap.org/ip/{ip}"
    result = {
        "ip": ip,
        "network_name": "Desconocido",
        "country": "Desconocido",
        "org": "Desconocido",
        "cidr": None,
        "asn": None,
        "asn_url": None,
    }
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                payload = resp.json()
                result["network_name"] = payload.get("name", "Desconocido")
                result["country"] = payload.get("country", "Desconocido")
                if payload.get("startAddress") and payload.get("endAddress"):
                    result["cidr"] = f"{payload.get('startAddress')} - {payload.get('endAddress')}"
    except Exception:
        pass

    return result
