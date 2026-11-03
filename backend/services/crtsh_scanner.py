"""Servicio de enumeración pasiva de subdominios vía Certificate Transparency logs y resolución de IPs."""
from typing import List, Set, Dict, Any
import asyncio
import httpx
import dns.resolver


async def _resolve_subdomain_ip(resolver: dns.resolver.Resolver, sub: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()

    def _query():
        try:
            ans = resolver.resolve(sub, "A")
            return [r.to_text() for r in ans]
        except Exception:
            return []

    ips = await loop.run_in_executor(None, _query)
    return {"subdomain": sub, "ips": ips}


async def fetch_subdomains(domain: str, max_results: int = 40) -> List[str]:
    """Consulta crt.sh con timeout controlado para obtener subdominios de certificados SSL públicos."""
    subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        async with httpx.AsyncClient(timeout=6.5, follow_redirects=True) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SniperScope-Audit/3.0"
            }
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                entries = resp.json()
                if isinstance(entries, list):
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for raw_name in name_value.split("\n"):
                            clean_name = raw_name.strip().lower()
                            if clean_name.startswith("*."):
                                clean_name = clean_name[2:]
                            if (
                                clean_name.endswith(f".{domain}")
                                and clean_name != domain
                                and " " not in clean_name
                            ):
                                subdomains.add(clean_name)
                                if len(subdomains) >= max_results:
                                    break
                        if len(subdomains) >= max_results:
                            break
    except Exception:
        pass

    return sorted(list(subdomains))


async def resolve_subdomains_map(subdomains: List[str], limit: int = 15) -> List[Dict[str, Any]]:
    """Resuelve rápidamente las IPs de los primeros subdominios para detectar Origin IP leaks."""
    if not subdomains:
        return []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 2.0

    tasks = [_resolve_subdomain_ip(resolver, sub) for sub in subdomains[:limit]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
