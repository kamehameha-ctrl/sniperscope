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

    # Detección de SPF dentro de registros TXT
    spf_record = next(
        (rec["value"] for rec in results["TXT"] if rec["value"].startswith("v=spf1")),
        None
    )

    return {
        "records": results,
        "primary_ips": ordered_ips,
        "email_security": {
            "has_spf": spf_record is not None,
            "spf_raw": spf_record,
            "has_dmarc": dmarc_record is not None,
            "dmarc_raw": dmarc_record,
        }
    }
