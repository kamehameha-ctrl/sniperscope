"""Servicio de enriquecimiento profundo de vulnerabilidades mediante Shodan CVEDB."""
from typing import Dict, Any, List, Optional
import asyncio
import httpx

# Caché en memoria para acelerar consultas repetidas de CVEs comunes
_CVE_CACHE: Dict[str, Dict[str, Any]] = {}


def _classify_severity(cvss: Optional[float], cve_id: str, is_kev: bool = False) -> str:
    if is_kev:
        return "CRITICAL"
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


def _extract_vendor_product_from_cpes(cpes: List[str]) -> Dict[str, Optional[str]]:
    if not cpes:
        return {"vendor": None, "product": None}
    first = cpes[0].replace("cpe:2.3:", "").replace("cpe:/", "")
    parts = first.split(":")
    vendor = parts[1].replace("_", " ").title() if len(parts) > 1 else None
    product = parts[2].replace("_", " ").title() if len(parts) > 2 else None
    return {"vendor": vendor, "product": product}


async def _fetch_single_cve(client: httpx.AsyncClient, sem: asyncio.Semaphore, cve_id: str) -> Optional[Dict[str, Any]]:
    if cve_id in _CVE_CACHE:
        return _CVE_CACHE[cve_id]

    async with sem:
        try:
            resp = await client.get(f"https://cvedb.shodan.io/cve/{cve_id}")
            if resp.status_code == 200:
                data = resp.json()
                _CVE_CACHE[cve_id] = data
                return data
        except Exception:
            pass
    return None


async def enrich_cve_dictionary(raw_vulns_map: Dict[str, Dict[str, Any]], max_enrich: int = 60) -> List[Dict[str, Any]]:
    """
    Recibe un diccionario {cve_id: info_preliminar} y consulta Shodan CVEDB
    para completar descripciones ausentes, CVSS, EPSS, KEV, Ransomware y referencias.
    """
    cve_ids = list(raw_vulns_map.keys())[:max_enrich]
    sem = asyncio.Semaphore(12)

    async with httpx.AsyncClient(timeout=6.0) as client:
        tasks = [_fetch_single_cve(client, sem, cve_id) for cve_id in cve_ids]
        cvedb_results = await asyncio.gather(*tasks, return_exceptions=True)

    enriched_list: List[Dict[str, Any]] = []

    for cve_id, cvedb in zip(cve_ids, cvedb_results):
        base = raw_vulns_map.get(cve_id, {})
        cvedb_dict = cvedb if isinstance(cvedb, dict) else {}

        # CVSS: priorizar CVEDB (cvss_v3 -> cvss -> cvss_v2) o el valor previo de Shodan host
        cvss_raw = (
            cvedb_dict.get("cvss_v3")
            or cvedb_dict.get("cvss")
            or cvedb_dict.get("cvss_v2")
            or base.get("cvss")
        )
        try:
            cvss_val = float(cvss_raw) if cvss_raw is not None else None
        except (ValueError, TypeError):
            cvss_val = None

        # EPSS y Ranking EPSS
        epss_raw = cvedb_dict.get("epss") if cvedb_dict.get("epss") is not None else base.get("epss")
        try:
            epss_val = float(epss_raw) if epss_raw is not None else None
        except (ValueError, TypeError):
            epss_val = None

        rank_raw = cvedb_dict.get("ranking_epss")
        try:
            ranking_epss = float(rank_raw) if rank_raw is not None else None
        except (ValueError, TypeError):
            ranking_epss = None

        is_kev = bool(cvedb_dict.get("kev", False))
        ransomware = cvedb_dict.get("ransomware_campaign")
        propose_action = cvedb_dict.get("propose_action")
        published_time = cvedb_dict.get("published_time")

        # Summary real: preferir el de CVEDB o el de Shodan Host, evitando textos genéricos
        base_summary = base.get("summary") or ""
        if "InternetDB" in base_summary or "Vulnerabilidad reportada" in base_summary:
            base_summary = ""

        summary = (
            cvedb_dict.get("summary")
            or (cvedb_dict.get("euvd") or {}).get("description")
            or base_summary
            or "Sin descripción técnica detallada en base de datos pública."
        )

        # Vendor y Producto afectado
        euvd_info = cvedb_dict.get("euvd") or {}
        vendors = euvd_info.get("vendors") or []
        products = euvd_info.get("products") or []
        cpe_vp = _extract_vendor_product_from_cpes(cvedb_dict.get("cpes") or [])

        vendor_name = vendors[0] if vendors else cpe_vp.get("vendor")
        product_name = products[0] if products else cpe_vp.get("product")

        refs = cvedb_dict.get("references") or base.get("references") or []
        clean_num = cve_id.upper().replace("CVE-", "")

        enriched_list.append({
            "cve": cve_id,
            "cvss": cvss_val,
            "cvss_version": cvedb_dict.get("cvss_version") or (3.0 if cvss_val else None),
            "epss": epss_val,
            "ranking_epss": ranking_epss,
            "kev": is_kev,
            "ransomware_campaign": ransomware,
            "propose_action": propose_action,
            "published_time": published_time[:10] if isinstance(published_time, str) else None,
            "vendor": vendor_name,
            "product": product_name,
            "severity": _classify_severity(cvss_val, cve_id, is_kev),
            "summary": summary,
            "verified": bool(base.get("verified", False) or is_kev),
            "ports": sorted(list(set(base.get("ports", [])))),
            "service": base.get("service") or product_name or "Host Service",
            "ips": sorted(list(set(base.get("ips", [base.get("ip")] if base.get("ip") else [])))),
            "references": list(dict.fromkeys(refs))[:6],
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "mitre_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "exploitdb_url": f"https://www.exploit-db.com/search?cve={clean_num}",
            "github_poc_url": f"https://github.com/search?q={cve_id}+poc+OR+exploit&type=repositories",
        })

    # Ordenar primero por KEV activo, luego por CVSS descendente, luego por EPSS descendente
    enriched_list.sort(
        key=lambda x: (
            1 if x.get("kev") else 0,
            x.get("cvss") or 0.0,
            x.get("epss") or 0.0,
        ),
        reverse=True,
    )

    return enriched_list
