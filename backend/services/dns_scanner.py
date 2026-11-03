"""Servicio de resolución y reconocimiento pasivo de registros DNS."""
from typing import Dict, List, Any
import asyncio
import dns.resolver
import dns.exception


async def resolve_dns_records(domain: str) -> Dict[str, Any]:
    """Resuelve registros DNS comunes, CAA y políticas de correo para un dominio."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
    results: Dict[str, List[Dict[str, Any]]] = {rtype: [] for rtype in record_types}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    def _query(rtype: str):
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                val = rdata.to_text().strip('"')
                results[rtype].append({"value": val, "ttl": answers.rrset.ttl if answers.rrset else 0})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception:
            pass

    loop = asyncio.get_running_loop()
    await asyncio.gather(*[loop.run_in_executor(None, _query, rtype) for rtype in record_types])

    # Priorizar siempre IPv4 (A) antes que IPv6 (AAAA)
    ipv4_list = [r["value"] for r in results["A"]]
    ipv6_list = [r["value"] for r in results["AAAA"]]
    ordered_ips = list(dict.fromkeys(ipv4_list + ipv6_list))

    # Verificar DMARC específicamente
    dmarc_record = None
    try:
        def _check_dmarc():
            try:
                answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in answers:
                    return rdata.to_text().strip('"')
            except Exception:
                return None
        dmarc_record = await loop.run_in_executor(None, _check_dmarc)
    except Exception:
        pass

    # Detección y análisis profundo de SPF dentro de registros TXT
    spf_record = next(
        (rec["value"] for rec in results["TXT"] if rec["value"].startswith("v=spf1")),
        None
    )
    spf_policy = "missing"
    spf_warning = None
    if spf_record:
        if "+all" in spf_record or "?all" in spf_record:
            spf_policy = "permissive"
            spf_warning = "Directiva permisiva (+all o ?all) detectada: cualquier IP puede enviar correos autorizados."
        elif "-all" in spf_record:
            spf_policy = "hard_fail"
        elif "~all" in spf_record:
            spf_policy = "soft_fail"
        else:
            spf_policy = "neutral"

    # Análisis de directivas DMARC y riesgo de Spoofing / Phishing
    dmarc_policy = "missing"
    dmarc_status = "CRITICAL_MISSING"
    is_spoofing_vulnerable = True
    dmarc_detail = "Sin registro DMARC configurado. El dominio es altamente vulnerable a suplantación directa (email spoofing)."

    if dmarc_record:
        dmarc_lower = dmarc_record.lower()
        if "p=reject" in dmarc_lower:
            dmarc_policy = "reject"
            dmarc_status = "STRICT_PROTECTION"
            is_spoofing_vulnerable = False
            dmarc_detail = "Política DMARC estricta (p=reject): los servidores receptores descartan de inmediato correos suplantados."
        elif "p=quarantine" in dmarc_lower:
            dmarc_policy = "quarantine"
            dmarc_status = "PROTECTED"
            is_spoofing_vulnerable = False
            dmarc_detail = "Política DMARC activa (p=quarantine): los correos sospechosos se envían a la carpeta de spam/cuarentena."
        elif "p=none" in dmarc_lower:
            dmarc_policy = "none"
            dmarc_status = "WEAK_MONITOR"
            is_spoofing_vulnerable = True
            dmarc_detail = "Política DMARC en modo monitor (p=none): no bloquea ni aísla correos falsificados, permitiendo suplantación activa."
        else:
            dmarc_policy = "unknown"
            dmarc_status = "UNKNOWN"
            is_spoofing_vulnerable = True
            dmarc_detail = "Registro DMARC presente pero sin directiva p= reconocida."

    return {
        "records": results,
        "primary_ips": ordered_ips,
        "email_security": {
            "has_spf": spf_record is not None,
            "spf_raw": spf_record,
            "spf_policy": spf_policy,
            "spf_warning": spf_warning,
            "has_dmarc": dmarc_record is not None,
            "dmarc_raw": dmarc_record,
            "dmarc_policy": dmarc_policy,
            "dmarc_status": dmarc_status,
            "is_spoofing_vulnerable": is_spoofing_vulnerable,
            "spoofing_detail": dmarc_detail,
        }
    }
