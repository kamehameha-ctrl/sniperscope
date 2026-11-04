"""Motor asíncrono no-bloqueante para SOCMINT Sherlock Hunter.

Ejecuta comprobaciones ultra-rápidas mediante httpx asíncrono, semáforos de concurrencia,
validación de falsos positivos y streaming de eventos en tiempo real (SSE).
"""
import asyncio
import time
import re
from typing import Dict, Any, List, Optional, AsyncGenerator
import httpx

from services.sherlock_data import SITES_DATABASE, CATEGORIES
from services.http_scanner import is_proxy_reachable, STANDARD_BROWSER_UA

DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 30


def validate_username(username: str) -> bool:
    """Valida sintaxis común de un username/handle para evitar peticiones anómalas."""
    if not username or len(username) > 60:
        return False
    # Permitir alfanuméricos, guiones bajos, guiones y puntos
    return bool(re.match(r"^[a-zA-Z0-9_\-\.]+$", username.strip()))


async def _probe_single_site(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    site: Dict[str, Any],
    username: str
) -> Dict[str, Any]:
    """Sondea una plataforma específica con control de concurrencia y detección de falsos positivos."""
    site_name = site["name"]
    category = site.get("category", "General")
    probe_url = site["url_probe"].format(username)
    profile_url = site["url_profile"].format(username)
    check_type = site.get("check_type", "status_code")
    valid_code = site.get("valid_code", 200)
    error_text = site.get("error_text", "")
    icon = site.get("icon", "globe")

    start_time = time.perf_counter()

    async with semaphore:
        try:
            # Petición GET con seguimiento de redirección pero con cabeceras reales
            response = await client.get(
                probe_url,
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                headers={
                    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "User-Agent": STANDARD_BROWSER_UA
                }
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            status_code = response.status_code

            found = False
            # Detección según el tipo de regla
            if check_type == "status_code":
                if status_code == valid_code:
                    # Si tiene error_text definido, comprobar que NO esté presente (anti-falso positivo)
                    if error_text:
                        found = error_text.lower() not in response.text.lower()
                    else:
                        found = True
                else:
                    found = False
            elif check_type == "text_absence":
                if status_code == 200:
                    found = error_text.lower() not in response.text.lower()
                else:
                    found = False

            return {
                "site": site_name,
                "category": category,
                "url": profile_url,
                "found": found,
                "status_code": status_code,
                "elapsed_ms": elapsed_ms,
                "icon": icon,
                "error": None
            }
        except httpx.TimeoutException:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "site": site_name,
                "category": category,
                "url": profile_url,
                "found": False,
                "status_code": None,
                "elapsed_ms": elapsed_ms,
                "icon": icon,
                "error": "Timeout"
            }
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "site": site_name,
                "category": category,
                "url": profile_url,
                "found": False,
                "status_code": None,
                "elapsed_ms": elapsed_ms,
                "icon": icon,
                "error": str(exc.__class__.__name__)
            }


async def stream_sherlock_scan(
    username: str,
    category: Optional[str] = None,
    outbound_proxy: Optional[str] = None
) -> AsyncGenerator[Dict[str, Any], None]:
    """Generador asíncrono para Server-Sent Events (SSE). Emite resultados a medida que se completan."""
    clean_user = username.strip()
    if not validate_username(clean_user):
        yield {
            "event": "error",
            "message": "Formato de nombre de usuario inválido. Usa caracteres alfanuméricos, '.', '_' o '-'."
        }
        return

    # Filtrar catálogo por categoría si se especificó
    if category and category != "Todos":
        sites = [s for s in SITES_DATABASE if s.get("category") == category]
    else:
        sites = list(SITES_DATABASE)

    total_sites = len(sites)

    # Evento de inicio
    yield {
        "event": "init",
        "username": clean_user,
        "total": total_sites,
        "category": category or "Todos"
    }

    # Configurar proxy de salida si está disponible y activo
    proxy_to_use = None
    if outbound_proxy and is_proxy_reachable(outbound_proxy):
        proxy_to_use = outbound_proxy

    transport = None
    if proxy_to_use:
        mounts = {
            "all://": httpx.AsyncHTTPTransport(proxy=proxy_to_use)
        }
    else:
        mounts = None

    semaphore = asyncio.Semaphore(DEFAULT_CONCURRENCY)
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)

    start_scan = time.perf_counter()
    found_count = 0
    checked_count = 0

    async with httpx.AsyncClient(mounts=mounts, limits=limits, verify=False) as client:
        # Lanzar todas las corutinas concurrentes
        tasks = [
            asyncio.create_task(_probe_single_site(client, semaphore, site, clean_user))
            for site in sites
        ]

        # Consumir las tareas conforme terminan con asyncio.as_completed
        for completed_task in asyncio.as_completed(tasks):
            result = await completed_task
            checked_count += 1
            if result["found"]:
                found_count += 1

            yield {
                "event": "progress",
                "site": result["site"],
                "category": result["category"],
                "url": result["url"],
                "found": result["found"],
                "status_code": result["status_code"],
                "elapsed_ms": result["elapsed_ms"],
                "icon": result["icon"],
                "checked_count": checked_count,
                "found_count": found_count,
                "total": total_sites
            }

    duration_s = round(time.perf_counter() - start_scan, 2)

    # Evento de finalización
    yield {
        "event": "complete",
        "username": clean_user,
        "total_checked": checked_count,
        "total_found": found_count,
        "duration_s": duration_s
    }
