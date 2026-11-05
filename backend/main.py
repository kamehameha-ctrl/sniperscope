"""Punto de entrada de la API FastAPI para SniperScope."""
import os
import sys
import re
import time
import json
import hmac
import hashlib
import asyncio
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

# Asegurar que el directorio de backend esté en sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
from pydantic import BaseModel
from fastapi import FastAPI, Query, HTTPException, Header, Depends
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from shodan import Shodan

# Cargar variables de entorno desde backend/.env
env_path = backend_dir / ".env"
load_dotenv(dotenv_path=env_path)

from services.dns_scanner import resolve_dns_records
from services.crtsh_scanner import fetch_subdomains, resolve_subdomains_map
from services.rdap_scanner import fetch_rdap_domain, fetch_rdap_ip
from services.http_scanner import inspect_http_headers, is_proxy_reachable
from services.shodan_scanner import query_shodan_ip
from services.cve_enricher import enrich_cve_dictionary
from services.graph_builder import build_attack_surface_graph
from services.sherlock_data import SITES_DATABASE, CATEGORIES
from services.sherlock_engine import stream_sherlock_scan, validate_username
from services.phone_osint import analyze_phone_number
from services.email_osint import analyze_email_address
from services.ip_intel import classify_and_geolocate_ip, analyze_unproxied_hosts

app = FastAPI(
    title="SniperScope EASM & Forensic API",
    description="Motor de alto rendimiento para análisis de superficie de ataque, Shodan CVEDB y reconocimiento OSINT",
    version="3.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Caché en memoria con TTL de 300 segundos para rendimiento instantáneo
_SCAN_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 300.0


class LoginRequest(BaseModel):
    username: str
    password: str


def _get_auth_secret() -> bytes:
    """Deriva la clave de firma HMAC a partir de las variables de entorno en backend/.env."""
    user = os.getenv("SNIPERSCOPE_USER", "")
    pwd = os.getenv("SNIPERSCOPE_PASS", "")
    shodan_k = os.getenv("SHODAN_API_KEY", "")
    return f"sniperscope-v3-hmac::{user}::{pwd}::{shodan_k}".encode("utf-8")


def _create_session_token(username: str) -> str:
    """Genera un token firmado HMAC-SHA256 para la sesión autenticada."""
    sig = hmac.new(_get_auth_secret(), username.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{username}:{sig}"


def _verify_session_token(token: Optional[str]) -> str:
    """Verifica el token HMAC-SHA256 sin almacenar estado en base de datos."""
    expected_user = os.getenv("SNIPERSCOPE_USER", "")
    if not expected_user:
        return "operator"
    if not token or ":" not in token:
        raise HTTPException(status_code=401, detail="Unauthenticated session. Please log in to SniperScope.")
    user_part, sig_part = token.split(":", 1)
    expected_sig = hmac.new(_get_auth_secret(), user_part.encode("utf-8"), hashlib.sha256).hexdigest()
    if not (
        hmac.compare_digest(user_part.encode("utf-8"), expected_user.encode("utf-8"))
        and hmac.compare_digest(sig_part.encode("utf-8"), expected_sig.encode("utf-8"))
    ):
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    return user_part


async def require_operator_auth(
    x_sniperscope_token: Optional[str] = Header(default=None, alias="X-SniperScope-Token")
) -> str:
    return _verify_session_token(x_sniperscope_token)


def _clean_target(raw_target: str) -> str:
    """Sanitiza cualquier entrada (URL completa, IPv4, IPv6 o dominio) de forma segura."""
    t = (raw_target or "").strip().lower()
    if not t:
        return ""
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or parsed.netloc
        return (host or "").strip("[]")
    # Si no tiene esquema pero tiene barra de ruta o parámetros
    t = t.split("/")[0].split("?")[0].split("#")[0]
    # Comprobar si es IPv6 antes de cortar por ':'
    try:
        ipaddress.ip_address(t.strip("[]"))
        return t.strip("[]")
    except ValueError:
        pass
    # Si es dominio:puerto o ipv4:puerto
    if ":" in t:
        t = t.split(":")[0]
    return t.strip()


def _is_ip(target: str) -> bool:
    """Verifica con precisión matemática si el objetivo es una dirección IPv4 o IPv6."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _now_utc_ms() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def _evaluate_risk_and_findings(
    cve_list: List[Dict[str, Any]],
    shodan_hosts: List[Dict[str, Any]],
    dns_res: Dict[str, Any],
    http_res: Dict[str, Any],
) -> Dict[str, Any]:
    """Calcula la puntuación de riesgo (0-100) y genera hallazgos accionables para el auditor."""
    score = 0
    findings: List[Dict[str, str]] = []

    kev_vulns = [v for v in cve_list if v.get("kev")]
    ransom_vulns = [v for v in cve_list if v.get("ransomware_campaign")]
    crit_vulns = [v for v in cve_list if v.get("severity") == "CRITICAL"]
    high_vulns = [v for v in cve_list if v.get("severity") == "HIGH"]

    # 1. Exposiciones críticas directas de archivos confidenciales (/.git, /.env)
    exposed_paths = http_res.get("exposed_paths", [])
    crit_paths = [p["path"] for p in exposed_paths if p.get("kind") in ("critical_git", "critical_env")]
    if crit_paths:
        score += 20
        findings.append({
            "severity": "CRITICAL",
            "title": f"Critical Exposure of Sensitive Repositories / Files ({', '.join(crit_paths)})",
            "detail": "Public access detected to repository metadata or configuration secrets on the web server."
        })

    # 2. Vulnerabilidades en el catálogo CISA KEV (Explotación activa documentada)
    if kev_vulns:
        score += 20
        findings.append({
            "severity": "CRITICAL",
            "title": f"{len(kev_vulns)} Vulnerability(ies) in CISA KEV Catalog (Active Exploitation)",
            "detail": f"Actively exploited in-the-wild CVEs detected: {', '.join(v['cve'] for v in kev_vulns[:5])}."
        })

    # 3. Vectores asociados a campañas de Ransomware
    if ransom_vulns:
        score += 10
        findings.append({
            "severity": "HIGH",
            "title": "Exposure to Documented Ransomware Vectors",
            "detail": f"At least {len(ransom_vulns)} CVE(s) are associated with known ransomware exploitation."
        })

    # 4. CVEs Críticas y Altas
    if crit_vulns:
        score += min(20, len(crit_vulns) * 6)
        findings.append({
            "severity": "CRITICAL",
            "title": f"{len(crit_vulns)} CRITICAL Severity Vulnerability(ies) (CVSS >= 9.0)",
            "detail": f"Max detected CVSS: {max((v.get('cvss') or 9.0) for v in crit_vulns)} in {crit_vulns[0].get('service', 'exposed services')}."
        })

    if high_vulns:
        score += min(12, len(high_vulns) * 3)

    # 5. Puertos importantes expuestos a Internet (Bases de datos y protocolos de administración)
    crit_ports = {
        23: "Telnet (Plaintext)", 445: "SMB", 1433: "MSSQL",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"
    }
    admin_ports = {21: "FTP", 22: "SSH"}

    exposed_crit = []
    exposed_admin = []
    for h in shodan_hosts:
        for p in h.get("ports", []):
            if p in crit_ports:
                exposed_crit.append(f"{p}/{crit_ports[p]}")
            elif p in admin_ports:
                exposed_admin.append(f"{p}/{admin_ports[p]}")

    if exposed_crit:
        score += min(15, len(exposed_crit) * 8)
        findings.append({
            "severity": "HIGH",
            "title": "Publicly Accessible Database / Sensitive Service Ports",
            "detail": f"Database or plaintext services exposed to the Internet: {', '.join(exposed_crit[:5])}."
        })

    if exposed_admin:
        score += min(5, len(exposed_admin) * 3)
        findings.append({
            "severity": "MEDIUM",
            "title": "Direct Remote Administration Services Exposed",
            "detail": f"Remote management services listening on public interface: {', '.join(exposed_admin[:4])}."
        })

    # 6. Observación de versiones en cabeceras HTTP
    if http_res.get("server") and any(ch.isdigit() for ch in http_res["server"]):
        score += 2
        findings.append({
            "severity": "LOW",
            "title": f"Web Server Version Disclosure ({http_res['server']})",
            "detail": "The web server discloses its software version in response headers."
        })

    # 7. Políticas CORS permisivas y cookies
    if http_res.get("cors_policy") == "*":
        score += 3
        findings.append({
            "severity": "LOW",
            "title": "Permissive Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
            "detail": "The server allows cross-origin requests from any origin."
        })

    insecure_cookies = [c["name"] for c in http_res.get("cookies_audit", []) if not c.get("safe")]
    if insecure_cookies:
        score += 2
        findings.append({
            "severity": "LOW",
            "title": f"Cookies Lacking HttpOnly or Secure Flags ({', '.join(insecure_cookies[:3])})",
            "detail": "Some issued cookies do not set standard HttpOnly / Secure flags."
        })

    # 8. Cabeceras de seguridad web ausentes (Higiene)
    missing_headers = [h["header"] for h in http_res.get("security_headers", []) if not h.get("present")]
    if missing_headers and http_res.get("reachable"):
        score += min(3, len(missing_headers))
        findings.append({
            "severity": "LOW",
            "title": f"Missing Web Security Headers ({len(missing_headers)})",
            "detail": f"Recommended headers missing: {', '.join(missing_headers[:3])}."
        })

    # 9. Seguridad de correo SPF / DMARC
    email_sec = dns_res.get("email_security", {})
    if not email_sec.get("has_spf") and not email_sec.get("has_dmarc"):
        score += 3
        findings.append({
            "severity": "LOW",
            "title": "Missing Email Anti-Spoofing Configuration (SPF / DMARC)",
            "detail": "The domain lacks SPF and DMARC policies against email spoofing."
        })
    elif email_sec.get("dmarc_policy") == "none":
        score += 2
        findings.append({
            "severity": "LOW",
            "title": "Permissive DMARC Policy (p=none)",
            "detail": "DMARC is set to p=none without quarantine or reject enforcement."
        })

    # 10. Vulnerabilidades en Componentes Web / JavaScript (SCA)
    sca_findings = [v for v in cve_list if v.get("source") == "SCA Web Technology Audit"]
    if sca_findings:
        score += min(8, len(sca_findings) * 2)
        findings.append({
            "severity": "MEDIUM",
            "title": f"Web Component Flaws Identified (SCA: {len(sca_findings)})",
            "detail": f"Known vulnerabilities in client libraries: {', '.join(set(v.get('service', '') for v in sca_findings[:3]))}."
        })

    final_score = min(100, score)
    if final_score >= 75:
        grade, level = "F", "CRITICAL"
    elif final_score >= 56:
        grade, level = "D", "HIGH"
    elif final_score >= 36:
        grade, level = "C", "MODERATE"
    elif final_score >= 16:
        grade, level = "B", "GOOD"
    else:
        grade, level = "A", "OPTIMAL"

    return {
        "score": final_score,
        "grade": grade,
        "level": level,
        "findings": findings,
    }


def _build_execution_trace(
    clean_host: str,
    is_direct_ip: bool,
    scan_mode: str,
    t_init: str,
    t_dns: str,
    t_discovery: str,
    t_shodan: str,
    t_cvedb: str,
    dns_res: Dict[str, Any],
    subdomains: List[str],
    subdomain_ips: List[Dict[str, Any]],
    rdap_res: Dict[str, Any],
    http_res: Dict[str, Any],
    clean_shodan: List[Dict[str, Any]],
    cve_list: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build step-by-step trace (command-by-command / request-by-request) for the RAW trace."""
    trace: List[Dict[str, Any]] = []
    step_idx = 1

    trace.append({
        "step": f"{step_idx:02d}",
        "timestamp": t_init,
        "phase": "TARGET_INITIALIZATION",
        "title": "Target Sanitization, OPSEC Profile & Classification",
        "command": f"sniperscope --init --target {clean_host} --mode {scan_mode}",
        "request": f"Internal Parser -> Input='{clean_host}' | Mode='{scan_mode.upper()}' | Type={'IP_HOST' if is_direct_ip else 'DOMAIN_NAME'}",
        "reasoning": "Target is normalized by stripping URI schemes and paths, configuring the OPSEC profile (Passive Stealth vs Authorized Active).",
        "raw_output": json.dumps({
            "normalized_target": clean_host,
            "scan_mode": scan_mode,
            "via_proxy": http_res.get("via_proxy", False),
            "target_type": "IP" if is_direct_ip else "Domain",
            "session_start_utc": t_init
        }, indent=2, ensure_ascii=False)
    })
    step_idx += 1

    if not is_direct_ip:
        trace.append({
            "step": f"{step_idx:02d}",
            "timestamp": t_dns,
            "phase": "DNS_ZONE_RECON",
            "title": "DNS Zone Resolution & Email Anti-Spoofing Audit (SPF/DMARC)",
            "command": f"dig +nocmd {clean_host} A AAAA MX NS TXT SOA CNAME +noall +answer && dig +short TXT _dmarc.{clean_host}",
            "request": f"DNS Standard Queries (UDP/53) -> qname={clean_host}, qtypes=[A, AAAA, MX, NS, TXT, SOA, CNAME] & qname=_dmarc.{clean_host}",
            "reasoning": "Queries DNS recursive/authoritative servers to uncover IPv4/IPv6 addresses for Shodan recon and audit email security policies.",
            "raw_output": json.dumps(dns_res, indent=2, ensure_ascii=False)
        })
        step_idx += 1

        trace.append({
            "step": f"{step_idx:02d}",
            "timestamp": t_discovery,
            "phase": "CT_LOGS_SUBDOMAINS",
            "title": "Passive Subdomain Enumeration (crt.sh) & Origin IP Resolution",
            "command": f"curl -s 'https://crt.sh/?q=%.{clean_host}&output=json' | jq -r '.[].name_value' | sort -u",
            "request": f"HTTP GET https://crt.sh/?q=%25.{clean_host}&output=json + Async DNS A Resolution",
            "reasoning": "Queries SSL/TLS Certificate Transparency logs to discover perimeter subdomains and resolves their IPs to uncover origin servers behind WAFs.",
            "raw_output": json.dumps({
                "subdomains_discovered_count": len(subdomains),
                "subdomains_resolved": subdomain_ips,
                "all_subdomains": subdomains
            }, indent=2, ensure_ascii=False)
        })
        step_idx += 1

    rdap_url = f"https://rdap.org/{'ip' if is_direct_ip else 'domain'}/{clean_host}"
    trace.append({
        "step": f"{step_idx:02d}",
        "timestamp": t_discovery,
        "phase": "RDAP_WHOIS_LOOKUP",
        "title": "Official WHOIS / RDAP Registry Query",
        "command": f"curl -s -L '{rdap_url}'",
        "request": f"HTTP GET {rdap_url}",
        "reasoning": "Queries the Registration Data Access Protocol (RDAP) to extract registrar entity, registration/expiration timestamps, and authoritative nameservers.",
        "raw_output": json.dumps(rdap_res, indent=2, ensure_ascii=False)
    })
    step_idx += 1

    tls_data = http_res.get("tls", {})
    trace.append({
        "step": f"{step_idx:02d}",
        "timestamp": t_discovery,
        "phase": "TLS_CRYPTO_HANDSHAKE",
        "title": "TLS/SSL Handshake & X.509 Certificate Inspection (Port 443)",
        "command": f"openssl s_client -connect {clean_host}:443 -servername {clean_host} -showcerts </dev/null",
        "request": f"TCP/TLS Handshake -> {clean_host}:443 (SNI={clean_host})",
        "reasoning": "Negotiates direct TLS handshake on port 443 to inspect protocol version, cipher suite, Certificate Authority (CA), validity window, and Subject Alternative Names (SANs).",
        "raw_output": json.dumps(tls_data, indent=2, ensure_ascii=False)
    })
    step_idx += 1

    http_cmd = (
        f"curl -k -i -L 'https://{clean_host}/' && curl -k -s -I 'https://{clean_host}/.git/HEAD' 'https://{clean_host}/.env'"
        if scan_mode == "active"
        else f"curl -k -i -L -A 'Mozilla/5.0 Chrome/131.0' 'https://{clean_host}/'"
    )
    http_req_desc = (
        f"HTTP GET https://{clean_host}/ | Active Probes: [/robots.txt, /.well-known/security.txt, /sitemap.xml, /.git/HEAD, /.env, /swagger.json]"
        if scan_mode == "active"
        else f"HTTP GET https://{clean_host}/ (Stealth Mode: Zero path probing, standard browser User-Agent)"
    )

    trace.append({
        "step": f"{step_idx:02d}",
        "timestamp": t_discovery,
        "phase": f"HTTP_SECURITY_AUDIT ({scan_mode.upper()})",
        "title": "HTTP/HTTPS Inspection, Security Headers, Cookies, CORS & WAF",
        "command": http_cmd,
        "request": http_req_desc,
        "reasoning": "Audits raw HTTP headers, cookie security flags (Secure, HttpOnly, SameSite), CORS policy, and WAF/CDN presence adhering strictly to the OPSEC mode.",
        "raw_output": json.dumps({
            "scan_mode": scan_mode,
            "via_proxy": http_res.get("via_proxy", False),
            "reachable": http_res.get("reachable"),
            "final_url": http_res.get("final_url"),
            "status_code": http_res.get("status_code"),
            "server": http_res.get("server"),
            "waf_cdn": http_res.get("waf_cdn"),
            "cors_policy": http_res.get("cors_policy"),
            "cookies_audit": http_res.get("cookies_audit"),
            "exposed_paths": http_res.get("exposed_paths"),
            "technologies": http_res.get("technologies"),
            "raw_response_headers": http_res.get("raw_headers", {}),
        }, indent=2, ensure_ascii=False)
    })
    step_idx += 1

    for h in clean_shodan:
        ip_addr = h.get("ip")
        trace.append({
            "step": f"{step_idx:02d}",
            "timestamp": t_shodan,
            "phase": f"SHODAN_HOST_RECON ({ip_addr})",
            "title": f"Infrastructure, Open Ports & Banner Recon on Shodan for IP {ip_addr}",
            "command": f"shodan host {ip_addr} && curl -s 'https://internetdb.shodan.io/{ip_addr}'",
            "request": f"HTTP GET https://api.shodan.io/shodan/host/{ip_addr}?key=[REDACTED] & GET https://internetdb.shodan.io/{ip_addr}",
            "reasoning": f"For IP {ip_addr}, queries Shodan API and InternetDB (100% passive, sending zero packets to target) to discover open ports, software versions, CPEs, and banners.",
            "raw_output": json.dumps({
                "ip": ip_addr,
                "source": h.get("source"),
                "asn": h.get("asn"),
                "org": h.get("org"),
                "isp": h.get("isp"),
                "os": h.get("os"),
                "location": {"city": h.get("city"), "country": h.get("country"), "lat": h.get("latitude"), "lon": h.get("longitude")},
                "open_ports": h.get("ports"),
                "cpes": h.get("cpes"),
                "hostnames": h.get("hostnames"),
                "services_and_banners": h.get("services"),
            }, indent=2, ensure_ascii=False)
        })
        step_idx += 1

    if cve_list:
        sample_cve = cve_list[0]["cve"]
        trace.append({
            "step": f"{step_idx:02d}",
            "timestamp": t_cvedb,
            "phase": "SHODAN_CVEDB_ENRICHMENT",
            "title": f"Enrichment of {len(cve_list)} Vulnerabilities via Shodan CVEDB (CVSS, EPSS & CISA KEV)",
            "command": f"for cve in {' '.join(v['cve'] for v in cve_list[:6])} ...; do curl -s \"https://cvedb.shodan.io/cve/$cve\"; done",
            "request": f"Async HTTP GET https://cvedb.shodan.io/cve/{{CVE_ID}} ({len(cve_list)} concurrent requests, e.g. /cve/{sample_cve})",
            "reasoning": "Cross-references all discovered CVE identifiers against Shodan CVEDB to extract technical descriptions, CVSS vectors, EPSS exploitation probability, and CISA KEV status.",
            "raw_output": json.dumps(cve_list, indent=2, ensure_ascii=False)
        })

    return trace


@app.post("/api/auth/login")
async def login_operator(payload: LoginRequest):
    """Autentica al operador verificando credenciales contra variables de entorno."""
    load_dotenv(dotenv_path=env_path, override=True)
    expected_user = os.getenv("SNIPERSCOPE_USER", "")
    expected_pass = os.getenv("SNIPERSCOPE_PASS", "")
    if not expected_user or not expected_pass:
        raise HTTPException(status_code=500, detail="Operator credentials not configured in backend/.env")

    user_ok = hmac.compare_digest(
        payload.username.strip().encode("utf-8"),
        expected_user.encode("utf-8"),
    )
    pass_ok = hmac.compare_digest(
        payload.password.encode("utf-8"),
        expected_pass.encode("utf-8"),
    )
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid operator credentials")

    token = _create_session_token(expected_user)
    proxy_val = os.getenv("OUTBOUND_PROXY", "").strip()
    return {
        "authenticated": True,
        "username": expected_user,
        "token": token,
        "proxy_configured": bool(proxy_val),
        "proxy_active": is_proxy_reachable(proxy_val),
    }


@app.get("/api/auth/verify")
async def verify_operator(operator: str = Depends(require_operator_auth)):
    """Verifica si el token almacenado en el cliente sigue siendo válido."""
    proxy_val = os.getenv("OUTBOUND_PROXY", "").strip()
    return {
        "authenticated": True,
        "username": operator,
        "proxy_configured": bool(proxy_val),
        "proxy_active": is_proxy_reachable(proxy_val),
    }


@app.get("/api/health")
async def health_check():
    api_key = os.getenv("SHODAN_API_KEY")
    proxy_val = os.getenv("OUTBOUND_PROXY", "").strip()
    return {
        "status": "healthy",
        "engine": "SniperScope v3.1",
        "shodan_configured": bool(api_key and api_key != "tu_api_key_aqui"),
        "proxy_configured": bool(proxy_val),
        "proxy_active": is_proxy_reachable(proxy_val),
    }


@app.get("/api/shodan-status")
async def shodan_status(_operator: str = Depends(require_operator_auth)):
    """Comprueba la conectividad y créditos de la API key de Shodan."""
    api_key = os.getenv("SHODAN_API_KEY")
    proxy_val = os.getenv("OUTBOUND_PROXY", "").strip()
    proxy_online = is_proxy_reachable(proxy_val)
    if not api_key or api_key == "tu_api_key_aqui":
        return {
            "configured": False,
            "proxy_configured": bool(proxy_val),
            "proxy_active": proxy_online,
            "message": "Shodan API key not configured",
        }
    try:
        loop = asyncio.get_running_loop()
        client = Shodan(api_key)
        info = await loop.run_in_executor(None, client.info)
        return {
            "configured": True,
            "plan": info.get("plan"),
            "query_credits": info.get("query_credits"),
            "scan_credits": info.get("scan_credits"),
            "proxy_configured": bool(proxy_val),
            "proxy_active": proxy_online,
        }
    except Exception as e:
        return {
            "configured": True,
            "plan": "active",
            "proxy_configured": bool(proxy_val),
            "proxy_active": proxy_online,
            "error": str(e),
        }


async def _run_shodan_pipeline(ips: List[str]) -> List[Dict[str, Any]]:
    """Ejecuta las consultas Shodan para las IPs descubiertas respetando el rate-limit."""
    results = []
    for idx, ip in enumerate(ips[:3]):
        if idx > 0:
            await asyncio.sleep(1.02)
        try:
            s_res = await query_shodan_ip(ip)
            if isinstance(s_res, dict):
                results.append(s_res)
        except Exception:
            pass
    return results


@app.get("/api/scan")
async def scan_target(
    target: str = Query(..., description="Dominio, URL o dirección IP objetivo"),
    refresh: bool = Query(False, description="Forzar re-escaneo ignorando caché"),
    mode: str = Query("passive", description="Modo OPSEC: 'passive' (Stealth) o 'active' (Auditoría profunda)"),
    _operator: str = Depends(require_operator_auth),
):
    """Realiza un reconocimiento profundo de alta velocidad contra el objetivo."""
    t_start_perf = time.perf_counter()
    t_init = _now_utc_ms()
    clean_host = _clean_target(target)
    if not clean_host:
        raise HTTPException(status_code=400, detail="Invalid or empty target")

    scan_mode = "active" if mode.lower() == "active" else "passive"
    cache_key = f"{clean_host}::{scan_mode}"

    # Comprobar caché en memoria si no se pide refresh forzado
    now_epoch = time.time()
    if not refresh and cache_key in _SCAN_CACHE:
        cached_time, cached_payload = _SCAN_CACHE[cache_key]
        if (now_epoch - cached_time) < CACHE_TTL_SECONDS:
            return cached_payload

    is_direct_ip = _is_ip(clean_host)
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # PIPELINE PARALELO DE BAJA LATENCIA:
    http_task = asyncio.create_task(inspect_http_headers(clean_host, scan_mode=scan_mode))
    rdap_task = asyncio.create_task(
        fetch_rdap_ip(clean_host) if is_direct_ip else fetch_rdap_domain(clean_host)
    )
    subdomain_task = asyncio.create_task(
        asyncio.sleep(0, result=[]) if is_direct_ip else fetch_subdomains(clean_host)
    )

    if is_direct_ip:
        dns_res = {"records": {}, "primary_ips": [clean_host], "email_security": {}}
        ips_to_query = [clean_host]
    else:
        try:
            dns_res = await resolve_dns_records(clean_host)
        except Exception:
            dns_res = {"records": {}, "primary_ips": [], "email_security": {}}
        ips_to_query = dns_res.get("primary_ips", [])

    t_dns = _now_utc_ms()
    primary_ip_str = clean_host if is_direct_ip else (ips_to_query[0] if ips_to_query else clean_host)

    # Lanzar Shodan y Geolocalización inmediatamente en paralelo con el resto de tareas de descubrimiento
    shodan_task = asyncio.create_task(_run_shodan_pipeline(ips_to_query))
    geo_task = asyncio.create_task(classify_and_geolocate_ip(primary_ip_str))

    subdomains, rdap_res, http_res, clean_shodan, geo_res = await asyncio.gather(
        subdomain_task, rdap_task, http_task, shodan_task, geo_task, return_exceptions=True
    )
    t_discovery = _now_utc_ms()
    t_shodan = t_discovery

    if isinstance(subdomains, Exception):
        subdomains = []
    if isinstance(rdap_res, Exception):
        rdap_res = {}
    if isinstance(http_res, Exception):
        http_res = {"reachable": False, "scan_mode": scan_mode, "security_headers": [], "raw_headers": {}, "tls": {}, "exposed_paths": [], "cookies_audit": []}
    if isinstance(clean_shodan, Exception):
        clean_shodan = []
    if isinstance(geo_res, Exception) or not isinstance(geo_res, dict):
        geo_res = {
            "ip": primary_ip_str,
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

    # Resolver IPs de los primeros subdominios y enriquecer CVEs en paralelo
    raw_vulns_map: Dict[str, Dict[str, Any]] = {}
    for s_entry in clean_shodan:
        host_ip = s_entry.get("ip")
        v_details = s_entry.get("vuln_details", {})
        for cve_id, cve_obj in v_details.items():
            if cve_id not in raw_vulns_map:
                raw_vulns_map[cve_id] = {
                    **cve_obj,
                    "ips": [host_ip] if host_ip else [],
                }
            else:
                existing = raw_vulns_map[cve_id]
                if host_ip and host_ip not in existing.get("ips", []):
                    existing.setdefault("ips", []).append(host_ip)
                if not existing.get("summary") and cve_obj.get("summary"):
                    existing["summary"] = cve_obj["summary"]
                if existing.get("cvss") is None and cve_obj.get("cvss") is not None:
                    existing["cvss"] = cve_obj["cvss"]
                if existing.get("epss") is None and cve_obj.get("epss") is not None:
                    existing["epss"] = cve_obj["epss"]
                if not existing.get("service") and cve_obj.get("service"):
                    existing["service"] = cve_obj["service"]
                for p in cve_obj.get("ports", []):
                    if p not in existing.get("ports", []):
                        existing.setdefault("ports", []).append(p)

    # 2. Incorporar vulnerabilidades detectadas por el motor SCA en componentes web (Wappalyzer)
    sca_vulns = http_res.get("sca_vulnerabilities", []) if isinstance(http_res, dict) else []
    primary_ip_str = clean_shodan[0].get("ip") if clean_shodan else (dns_res.get("primary_ips", [None])[0] if isinstance(dns_res, dict) and dns_res.get("primary_ips") else None)
    for sca_item in sca_vulns:
        cve_id = sca_item.get("cve")
        if not cve_id:
            continue
        if cve_id not in raw_vulns_map:
            raw_vulns_map[cve_id] = {
                "cve": cve_id,
                "summary": sca_item.get("summary", ""),
                "cvss": sca_item.get("cvss", 6.1),
                "severity": sca_item.get("severity", "MEDIUM"),
                "service": sca_item.get("service") or f"{sca_item.get('product', 'Web Component')} {sca_item.get('version', '')}".strip(),
                "product": sca_item.get("product", ""),
                "version": sca_item.get("version", ""),
                "ports": [80, 443],
                "ips": [primary_ip_str] if primary_ip_str else [],
                "poc_url": sca_item.get("poc_url"),
                "exploitdb_url": sca_item.get("exploitdb_url"),
                "nvd_url": sca_item.get("nvd_url"),
                "vector": sca_item.get("vector", ""),
                "remediation": sca_item.get("remediation", ""),
                "source": "SCA Web Technology Audit"
            }
        else:
            existing = raw_vulns_map[cve_id]
            for p in (80, 443):
                if p not in existing.setdefault("ports", []):
                    existing["ports"].append(p)

    cve_list, subdomain_ips = await asyncio.gather(
        enrich_cve_dictionary(raw_vulns_map, max_enrich=75),
        resolve_subdomains_map(subdomains, limit=15),
        return_exceptions=True,
    )
    if isinstance(cve_list, Exception):
        cve_list = []
    if isinstance(subdomain_ips, Exception):
        subdomain_ips = []

    t_cvedb = _now_utc_ms()
    enriched_by_id = {item["cve"]: item for item in cve_list}

    for s_entry in clean_shodan:
        updated_map = {}
        for cve_id in s_entry.get("vuln_details", {}).keys():
            if cve_id in enriched_by_id:
                updated_map[cve_id] = enriched_by_id[cve_id]
        s_entry["vuln_details"] = updated_map

    crit_count = sum(1 for v in cve_list if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in cve_list if v.get("severity") == "HIGH")
    med_count = sum(1 for v in cve_list if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in cve_list if v.get("severity") == "LOW")
    kev_count = sum(1 for v in cve_list if v.get("kev"))

    risk_assessment = _evaluate_risk_and_findings(cve_list, clean_shodan, dns_res, http_res)
    perimeter_analysis = analyze_unproxied_hosts(geo_res, dns_res, subdomain_ips)

    execution_trace = _build_execution_trace(
        clean_host=clean_host,
        is_direct_ip=is_direct_ip,
        scan_mode=scan_mode,
        t_init=t_init,
        t_dns=t_dns,
        t_discovery=t_discovery,
        t_shodan=t_shodan,
        t_cvedb=t_cvedb,
        dns_res=dns_res,
        subdomains=subdomains,
        subdomain_ips=subdomain_ips,
        rdap_res=rdap_res,
        http_res=http_res,
        clean_shodan=clean_shodan,
        cve_list=cve_list,
    )

    elapsed_sec = round(time.perf_counter() - t_start_perf, 2)

    result = {
        "target": clean_host,
        "scan_mode": scan_mode,
        "scan_timestamp": scan_timestamp,
        "scan_duration_sec": elapsed_sec,
        "is_ip": is_direct_ip,
        "risk": risk_assessment,
        "dns": dns_res,
        "subdomains": subdomains,
        "subdomain_ips": subdomain_ips,
        "rdap_domain": rdap_res if not is_direct_ip else {},
        "rdap_ip": rdap_res if is_direct_ip else {},
        "http_audit": http_res,
        "shodan": clean_shodan,
        "geo": geo_res,
        "perimeter_hosts": perimeter_analysis,
        "summary": {
            "subdomains_count": len(subdomains),
            "ips_count": len(ips_to_query),
            "open_ports_count": sum(len(s.get("ports", [])) for s in clean_shodan),
            "vulnerabilities_count": len(cve_list),
            "critical_vulns": crit_count,
            "high_vulns": high_count,
            "medium_vulns": med_count,
            "low_vulns": low_count,
            "kev_vulns": kev_count,
        },
        "vulnerabilities": cve_list,
        "execution_trace": execution_trace,
    }

    result["graph"] = build_attack_surface_graph(result)

    # Guardar en caché
    _SCAN_CACHE[cache_key] = (time.time(), result)

    return result


@app.get("/sherlock")
async def sherlock_entrypoint():
    """Redirige directamente a la estación de trabajo Sherlock en el frontend."""
    return RedirectResponse(url="http://localhost:5173/sherlock", status_code=307)


@app.get("/api/sherlock/sites")
async def get_sherlock_sites(
    _operator: str = Depends(require_operator_auth),
):
    """Devuelve las categorías disponibles y el catálogo de plataformas soportadas."""
    return {
        "total": len(SITES_DATABASE),
        "categories": CATEGORIES,
        "sites": [
            {
                "name": s["name"],
                "category": s.get("category", "General"),
                "icon": s.get("icon", "globe")
            }
            for s in SITES_DATABASE
        ]
    }


@app.get("/api/sherlock/stream/{username}")
async def sherlock_stream(
    username: str,
    category: Optional[str] = Query(None, description="Filtrar por categoría (ej. 'Coding & Dev')"),
    token: Optional[str] = Query(None, description="Token de sesión opcional para EventSource"),
    x_sniperscope_token: Optional[str] = Header(default=None, alias="X-SniperScope-Token"),
):
    """Transmite resultados SOCMINT en tiempo real mediante Server-Sent Events (SSE)."""
    auth_token = x_sniperscope_token or token
    _verify_session_token(auth_token)

    outbound_proxy = os.getenv("OUTBOUND_PROXY_URL")

    async def event_generator():
        async for evt in stream_sherlock_scan(username=username, category=category, outbound_proxy=outbound_proxy):
            yield f"data: {json.dumps(evt, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@app.get("/api/osint/phone/{phone_number}")
async def get_phone_osint(
    phone_number: str,
    _operator: str = Depends(require_operator_auth),
):
    """Analiza un número de teléfono con inteligencia libphonenumber internacional y reputación en vivo."""
    result = await analyze_phone_number(phone_number)
    return result


@app.get("/api/osint/email/{email_address}")
async def get_email_osint(
    email_address: str,
    _operator: str = Depends(require_operator_auth),
):
    """Analiza una dirección de correo con inteligencia de dominios, MX/SPF, buzón SMTP, plataformas y brechas."""
    result = await analyze_email_address(email_address)
    return result

