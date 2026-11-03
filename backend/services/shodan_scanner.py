"""Servicio de inteligencia de infraestructura, servicios y vulnerabilidades vía Shodan API."""
import os
from typing import Dict, List, Any, Optional
import asyncio
import httpx
from shodan import Shodan
from shodan.exception import APIError

COMMON_PORT_SERVICES = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet Remote Login"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    123: ("NTP", "Network Time Protocol"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    445: ("SMB", "Server Message Block"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    3306: ("MySQL", "MySQL Database Service"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    6379: ("Redis", "Redis Key-Value Store"),
    8080: ("HTTP-Proxy", "HTTP Alternate / Proxy"),
    8443: ("HTTPS-Alt", "HTTPS Alternate"),
    9200: ("Elasticsearch", "Elasticsearch REST API"),
    27017: ("MongoDB", "MongoDB Database"),
}


def _get_shodan_client() -> Optional[Shodan]:
    api_key = os.getenv("SHODAN_API_KEY")
    if api_key and api_key != "tu_api_key_aqui":
        return Shodan(api_key)
    return None


def _parse_cpe_human(cpe_str: str) -> Dict[str, str]:
    """Convierte un string CPE (cpe:/a:vendor:product:version o cpe:2.3:...) en metadatos legibles."""
    parts = cpe_str.replace("cpe:2.3:", "").replace("cpe:/", "").split(":")
    vendor = parts[1] if len(parts) > 1 else ""
    product = parts[2] if len(parts) > 2 else ""
    version = parts[3] if len(parts) > 3 else ""
    return {
        "raw": cpe_str,
        "vendor": vendor.replace("_", " ").title(),
        "product": product.replace("_", " "),
        "version": version,
    }


def _infer_product_from_cpes(port: int, cpes: List[str]) -> Optional[Dict[str, str]]:
    """Infiere el producto y versión de un puerto cruzando los CPEs conocidos del host."""
    port_keywords = {
        22: ["openssh", "ssh", "dropbear", "libssh"],
        80: ["http_server", "apache", "nginx", "iis", "lighttpd", "caddy"],
        443: ["http_server", "apache", "nginx", "iis", "openssl", "caddy"],
        8080: ["http_server", "apache", "tomcat", "jetty", "nginx"],
        123: ["ntp", "chrony", "openntpd"],
        21: ["vsftpd", "proftpd", "pure-ftpd", "filezilla"],
        25: ["postfix", "exim", "sendmail"],
        53: ["bind", "dnsmasq", "unbound", "powerdns"],
        3306: ["mysql", "mariadb"],
        5432: ["postgresql"],
    }
    keywords = port_keywords.get(port, [])
    for cpe in cpes:
        low_cpe = cpe.lower()
        for kw in keywords:
            if kw in low_cpe:
                parsed = _parse_cpe_human(cpe)
                prod_name = parsed["product"].title()
                if "openssh" in low_cpe:
                    prod_name = "OpenSSH"
                elif "http_server" in low_cpe and "apache" in low_cpe:
                    prod_name = "Apache httpd"
                elif "ntp" in low_cpe:
                    prod_name = "ntpd"
                return {"product": prod_name, "version": parsed["version"], "cpe": cpe}
    return None


def _calculate_severity_label(cvss: Optional[float], cve_id: str) -> str:
    if cvss is not None:
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        return "LOW"
    if any(yr in cve_id for yr in ["2024", "2025", "2026"]):
        return "HIGH"
    return "MEDIUM"


async def _fetch_internetdb(ip: str) -> Dict[str, Any]:
    """Consulta Shodan InternetDB para complementar CPEs, puertos y tags."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}


async def query_shodan_ip(ip: str) -> Dict[str, Any]:
    """Consulta una IP en Shodan API oficial + InternetDB y extrae servicios y CVEs preliminares."""
    shodan_client = _get_shodan_client()
    idb_data = await _fetch_internetdb(ip)
    host_cpes: List[str] = idb_data.get("cpes", [])

    data: Dict[str, Any] = {
        "ip": ip,
        "ports": [],
        "vulns": [],
        "vuln_details": {},
        "cpes": host_cpes,
        "tags": idb_data.get("tags", []),
        "hostnames": idb_data.get("hostnames", []),
        "domains": [],
        "services": [],
        "source": "none",
        "asn": None,
        "org": None,
        "isp": None,
        "os": None,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "last_update": None,
    }

    # 1. Intentar con Shodan API Oficial
    if shodan_client:
        loop = asyncio.get_running_loop()
        try:
            def _shodan_host():
                return shodan_client.host(ip)

            host_info = await loop.run_in_executor(None, _shodan_host)
            data["source"] = "Shodan Official API"
            data["ports"] = sorted(list(set(host_info.get("ports", []))))
            data["vulns"] = list(set(host_info.get("vulns", []) + idb_data.get("vulns", [])))
            data["tags"] = list(set(data["tags"] + host_info.get("tags", [])))
            data["hostnames"] = list(set(data["hostnames"] + host_info.get("hostnames", [])))
            data["domains"] = host_info.get("domains", [])
            data["asn"] = host_info.get("asn")
            data["org"] = host_info.get("org")
            data["isp"] = host_info.get("isp")
            data["os"] = host_info.get("os")
            data["country"] = host_info.get("country_name")
            data["city"] = host_info.get("city")
            data["latitude"] = host_info.get("latitude")
            data["longitude"] = host_info.get("longitude")
            data["last_update"] = host_info.get("last_update")

            # Recolectar todos los CPEs de todos los servicios del host para inferencia cruzada
            all_service_cpes = list(host_cpes)
            for item in host_info.get("data", []):
                for c in (item.get("cpe23", []) or item.get("cpe", [])):
                    if c not in all_service_cpes:
                        all_service_cpes.append(c)
            data["cpes"] = all_service_cpes

            if not data["os"]:
                for cpe in all_service_cpes:
                    if "ubuntu" in cpe.lower():
                        data["os"] = "Ubuntu Linux"
                    elif "debian" in cpe.lower():
                        data["os"] = "Debian Linux"
                    elif "windows" in cpe.lower():
                        data["os"] = "Microsoft Windows"

            for item in host_info.get("data", []):
                port = item.get("port")
                transport = item.get("transport", "tcp")
                shodan_mod = item.get("_shodan", {}).get("module", "")
                std_proto, std_desc = COMMON_PORT_SERVICES.get(port, (shodan_mod.upper() or "SERVICE", "Network Service"))

                product = item.get("product") or ""
                version = str(item.get("version") or "")
                extra_info = item.get("info") or ""
                item_cpes = list(item.get("cpe23", []) or item.get("cpe", []))

                # Inferir desde CPEs si el puerto no trajo product explícito (ej. puerto 22 con OpenSSH en host_cpes)
                if not product:
                    inferred = _infer_product_from_cpes(port, all_service_cpes)
                    if inferred:
                        product = inferred["product"]
                        if not version:
                            version = inferred["version"]
                        if inferred["cpe"] not in item_cpes:
                            item_cpes.append(inferred["cpe"])
                        if not extra_info:
                            extra_info = f"({std_proto})"

                if not product:
                    product = f"{std_proto} ({std_desc})"

                http_meta = None
                if "http" in item and isinstance(item["http"], dict):
                    h = item["http"]
                    http_meta = {
                        "title": h.get("title"),
                        "server": h.get("server"),
                        "robots": h.get("robots"),
                        "securitytxt": h.get("securitytxt"),
                    }

                ssl_meta = None
                if "ssl" in item and isinstance(item["ssl"], dict):
                    s_obj = item["ssl"]
                    cert = s_obj.get("cert", {})
                    ssl_meta = {
                        "issuer": cert.get("issuer", {}).get("CN") or cert.get("issuer", {}).get("O"),
                        "subject": cert.get("subject", {}).get("CN"),
                        "expires": cert.get("expired"),
                        "versions": s_obj.get("versions", []),
                        "cipher": s_obj.get("cipher", {}).get("name"),
                    }

                cloud_meta = item.get("cloud")

                port_vulns_dict = item.get("vulns", {})
                port_cve_list = list(port_vulns_dict.keys()) if isinstance(port_vulns_dict, dict) else []

                for cve_id, cve_obj in (port_vulns_dict.items() if isinstance(port_vulns_dict, dict) else []):
                    cvss_val = cve_obj.get("cvss")
                    try:
                        cvss_float = float(cvss_val) if cvss_val is not None else None
                    except (ValueError, TypeError):
                        cvss_float = None

                    epss_val = cve_obj.get("epss")
                    try:
                        epss_float = float(epss_val) if epss_val is not None else None
                    except (ValueError, TypeError):
                        epss_float = None

                    existing = data["vuln_details"].get(cve_id, {})
                    affected_ports = existing.get("ports", [])
                    if port not in affected_ports:
                        affected_ports.append(port)

                    data["vuln_details"][cve_id] = {
                        "cve": cve_id,
                        "cvss": cvss_float,
                        "epss": epss_float,
                        "severity": _calculate_severity_label(cvss_float, cve_id),
                        "summary": cve_obj.get("summary") or "",
                        "verified": bool(cve_obj.get("verified", False)),
                        "ports": affected_ports,
                        "service": f"{product} {version}".strip(),
                        "ip": ip,
                        "references": (cve_obj.get("references") or [])[:5],
                    }

                raw_banner = (item.get("data") or "").strip()
                if not raw_banner:
                    if http_meta and http_meta.get("title"):
                        raw_banner = f"HTTP Title: {http_meta['title']}"
                    else:
                        raw_banner = f"Servicio detectado en puerto {port}/{transport.upper()}: {product} {version} {extra_info}".strip()

                data["services"].append({
                    "port": port,
                    "transport": transport,
                    "protocol": std_proto,
                    "module": shodan_mod or std_proto.lower(),
                    "product": product,
                    "version": version,
                    "info": extra_info,
                    "banner": raw_banner[:1000],
                    "cpe": item_cpes,
                    "http": http_meta,
                    "ssl": ssl_meta,
                    "cloud": cloud_meta,
                    "timestamp": item.get("timestamp"),
                    "vulns_count": len(port_cve_list),
                    "vulns": port_cve_list[:25],
                })

            # Asegurar que cualquier CVE en data["vulns"] esté registrada en vuln_details
            for cve_id in data["vulns"]:
                if cve_id not in data["vuln_details"]:
                    data["vuln_details"][cve_id] = {
                        "cve": cve_id,
                        "cvss": None,
                        "epss": None,
                        "severity": _calculate_severity_label(None, cve_id),
                        "summary": "",
                        "verified": False,
                        "ports": data["ports"],
                        "service": "",
                        "ip": ip,
                        "references": [],
                    }

            data["services"].sort(key=lambda x: x.get("port") or 0)
            return data
        except APIError:
            pass
        except Exception:
            pass

    # 2. Fallback a Shodan InternetDB si la API principal no devolvió resultados (ej. en ciertas IPv6)
    if idb_data:
        data["source"] = "Shodan InternetDB"
        data["ports"] = sorted(idb_data.get("ports", []))
        data["vulns"] = idb_data.get("vulns", [])
        data["cpes"] = host_cpes
        data["tags"] = idb_data.get("tags", [])
        data["hostnames"] = idb_data.get("hostnames", [])

        for cpe in host_cpes:
            if "ubuntu" in cpe.lower():
                data["os"] = "Ubuntu Linux"
            elif "debian" in cpe.lower():
                data["os"] = "Debian Linux"

        for port in data["ports"]:
            std_proto, std_desc = COMMON_PORT_SERVICES.get(port, ("TCP", "Servicio de Red"))
            inferred = _infer_product_from_cpes(port, host_cpes)
            prod = inferred["product"] if inferred else f"{std_proto} ({std_desc})"
            ver = inferred["version"] if inferred else ""
            cpe_list = [inferred["cpe"]] if inferred else []

            data["services"].append({
                "port": port,
                "transport": "tcp",
                "protocol": std_proto,
                "module": std_proto.lower(),
                "product": prod,
                "version": ver,
                "info": f"({std_proto})" if inferred else std_desc,
                "banner": f"Puerto {port}/{std_proto} activo | Servicio identificado: {prod} {ver}".strip(),
                "cpe": cpe_list,
                "http": None,
                "ssl": None,
                "cloud": None,
                "timestamp": None,
                "vulns_count": 0,
                "vulns": [],
            })

        for cve_id in data["vulns"]:
            data["vuln_details"][cve_id] = {
                "cve": cve_id,
                "cvss": None,
                "epss": None,
                "severity": _calculate_severity_label(None, cve_id),
                "summary": "",
                "verified": False,
                "ports": data["ports"],
                "service": "",
                "ip": ip,
                "references": [],
            }

    return data
