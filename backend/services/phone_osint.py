"""Servicio de inteligencia de números de teléfono (OSINT Telefónico estilo PhoneInfoga).

Realiza normalización E.164, detección de país y prefijo, análisis forense de
numeración española (Móvil vs Fijo vs Tarificación Especial), detección de rangos
de operadores CNMC, enlaces de mensajería (WhatsApp/Telegram), reputación/spam
(Listaspam/Tellows) y generación de PhoneInfoga Google Dorks.
"""
from typing import Dict, Any, List, Optional
import re
from urllib.parse import quote

# Prefijos telefónicos internacionales comunes
COUNTRY_PREFIXES = [
    ("34", "España", "ES", "+34"),
    ("1", "Estados Unidos / Canadá", "US/CA", "+1"),
    ("44", "Reino Unido", "GB", "+44"),
    ("33", "Francia", "FR", "+33"),
    ("49", "Alemania", "DE", "+49"),
    ("39", "Italia", "IT", "+39"),
    ("351", "Portugal", "PT", "+351"),
    ("52", "México", "MX", "+52"),
    ("54", "Argentina", "AR", "+54"),
    ("57", "Colombia", "CO", "+57"),
    ("56", "Chile", "CL", "+56"),
    ("51", "Perú", "PE", "+51"),
    ("58", "Venezuela", "VE", "+58"),
    ("593", "Ecuador", "EC", "+593"),
    ("41", "Suiza", "CH", "+41"),
    ("31", "Países Bajos", "NL", "+31"),
    ("32", "Bélgica", "BE", "+32"),
]

# Prefijos provinciales en España para líneas fijas
SPANISH_PROVINCE_PREFIXES = {
    "91": "Madrid", "81": "Madrid / A Coruña",
    "93": "Barcelona", "83": "Barcelona / Girona",
    "96": "Valencia / Alicante / Castellón", "86": "Valencia / Murcia",
    "95": "Sevilla / Málaga / Granada / Córdoba / Cádiz", "85": "Andalucía",
    "94": "Bizkaia / Gipuzkoa / Álava / Navarra / Cantabria", "84": "País Vasco / Navarra",
    "98": "A Coruña / Lugo / Ourense / Pontevedra / Asturias / León", "88": "Galicia / Asturias",
    "92": "Badajoz / Cáceres / Toledo / Ciudad Real / Albacete / Cuenca / Guadalajara",
    "97": "Baleares / Zaragoza / Huesca / Teruel / Lleida / Tarragona", "87": "Aragón / Baleares",
}


def analyze_phone_number(raw_phone: str) -> Dict[str, Any]:
    """Analiza un número de teléfono extrayendo inteligencia forense y enlaces OSINT."""
    cleaned = re.sub(r"[^\d+]", "", raw_phone.strip())
    if not cleaned:
        return {"error": "Número de teléfono no proporcionado o inválido"}

    has_leading_plus = cleaned.startswith("+")
    digits_only = re.sub(r"\D", "", cleaned)

    country_name = "Desconocido / Internacional"
    country_code = "INTL"
    dial_code = "+?"
    national_number = digits_only
    is_spain = False

    # Detección de prefijo internacional
    if has_leading_plus or digits_only.startswith("00"):
        digits_for_match = digits_only[2:] if digits_only.startswith("00") else digits_only
        for pfx, name, code, d_code in COUNTRY_PREFIXES:
            if digits_for_match.startswith(pfx):
                country_name = name
                country_code = code
                dial_code = d_code
                national_number = digits_for_match[len(pfx):]
                if pfx == "34":
                    is_spain = True
                break
    elif len(digits_only) == 9 and digits_only[0] in "6789":
        # Formato español estándar de 9 dígitos sin prefijo
        country_name = "España"
        country_code = "ES"
        dial_code = "+34"
        national_number = digits_only
        is_spain = True
    else:
        # Intentar coincidencia con prefijos
        for pfx, name, code, d_code in COUNTRY_PREFIXES:
            if digits_only.startswith(pfx) and len(digits_only) > len(pfx) + 6:
                country_name = name
                country_code = code
                dial_code = d_code
                national_number = digits_only[len(pfx):]
                if pfx == "34":
                    is_spain = True
                break

    e164_format = f"{dial_code}{national_number}" if dial_code.startswith("+") else f"+{digits_only}"
    e164_clean = e164_format.replace("+", "")

    # Inteligencia específica para España (+34)
    line_type = "Telefonía General"
    operator_assigned = "Operador no determinado"
    location = "Nacional"
    tariff_info = "Tarifa estándar nacional"
    is_valid_length = len(national_number) == 9 if is_spain else (7 <= len(national_number) <= 12)

    if is_spain and len(national_number) == 9:
        first_digit = national_number[0]
        first_two = national_number[:2]
        first_three = national_number[:3]

        if first_digit in ("6", "7"):
            line_type = "Móvil / Celular"
            tariff_info = "Línea móvil personal o corporativa"
            location = "España (Cobertura Nacional)"

            # Asignación histórica de rangos iniciales CNMC en España
            if first_two in ("60", "61", "62", "63", "64", "65", "66"):
                if first_three in ("600", "606", "607", "608", "609"):
                    operator_assigned = "Movistar / Telefónica Móviles (Rango Histórico)"
                elif first_three in ("610", "616", "617", "618", "619", "660", "669"):
                    operator_assigned = "Vodafone España (Airtel / Rango Histórico)"
                elif first_three in ("620", "622", "626", "629", "650", "659"):
                    operator_assigned = "Orange España (Amena / Rango Histórico)"
                elif first_three in ("633", "634"):
                    operator_assigned = "Yoigo / MásMóvil (Rango Histórico)"
                else:
                    operator_assigned = "Operador Móvil Asignado (Movistar / Vodafone / Orange / MásMóvil)"
            elif first_digit == "7":
                operator_assigned = "Rango Móvil Moderno / Operadores Móviles Virtuales (OMV)"
        elif first_digit in ("8", "9"):
            if first_three in ("900", "800"):
                line_type = "Tarificación Especial (Cobro Revertido)"
                tariff_info = "Número gratuito para el llamante (Llamadas de atención comercial)"
                location = "España (Nacional)"
                operator_assigned = "Servicio Corporativo / Número 900"
            elif first_three in ("901",):
                line_type = "Tarificación Especial Compartida"
                tariff_info = "Coste compartido entre emisor y receptor (Frecuente en Administraciones Públicas)"
                location = "España (Nacional)"
            elif first_three in ("902",):
                line_type = "Tarificación Especial (Pago Íntegro)"
                tariff_info = "Número de pago (Servicios de atención al cliente de empresas)"
                location = "España (Nacional)"
            elif first_three in ("905", "803", "806", "807"):
                line_type = "Tarificación Adicional de Alto Coste"
                tariff_info = "Servicios de tarificación adicional (Entretenimiento, concursos, líneas profesionales)"
                location = "España (Nacional)"
            else:
                line_type = "Línea Fija Geográfica"
                tariff_info = "Línea terrestre convencional o VoIP corporativa"
                matched_prov = SPANISH_PROVINCE_PREFIXES.get(first_two)
                if matched_prov:
                    location = f"Provincia: {matched_prov}"
                else:
                    location = "Línea Fija (España)"
                operator_assigned = "Telefónica de España / Red Fija Local"

    # Enlaces directos a plataformas de mensajería y reputación
    direct_messaging = {
        "whatsapp_url": f"https://wa.me/{e164_clean}",
        "whatsapp_label": "Abrir Chat WhatsApp Web (Directo sin agregar contacto)",
        "telegram_url": f"https://t.me/+{e164_clean}",
        "telegram_label": "Abrir Perfil Telegram",
    }

    reputation_checks = [
        {
            "name": "ListaSpam España",
            "url": f"https://www.listaspam.com/busca.php?Telefono={national_number}",
            "description": "Comprobar denuncias de spam telefónico, cobradores de deudas y telemarketing en España"
        },
        {
            "name": "Tellows España",
            "url": f"https://www.tellows.es/num/{national_number}",
            "description": "Puntuación de riesgo, geolocalización y comentarios de la comunidad"
        },
        {
            "name": "Responderono",
            "url": f"https://www.responderono.es/{national_number}",
            "description": "Base de datos española de llamadas sospechosas y empresas asociadas"
        },
        {
            "name": "Sync.me",
            "url": f"https://sync.me/search/?number={e164_format}",
            "description": "Identificador global de llamadas y sincronización de perfiles sociales"
        },
        {
            "name": "Truecaller Web",
            "url": f"https://www.truecaller.com/search/es/{national_number if is_spain else e164_clean}",
            "description": "Directorio mundial de nombres asociados a números de teléfono"
        }
    ]

    # PhoneInfoga Google Dorks
    formatted_dorks = [
        {
            "title": "Menciones Generales & Huella Digital",
            "dork": f'"{national_number}" OR "{e164_format}"',
            "url": f"https://www.google.com/search?q={quote(f'\"{national_number}\" OR \"{e164_format}\"')}"
        },
        {
            "title": "Portales de Clasificados (Milanuncios / Wallapop)",
            "dork": f'site:milanuncios.com OR site:wallapop.com "{national_number}"',
            "url": f"https://www.google.com/search?q={quote(f'site:milanuncios.com OR site:wallapop.com \"{national_number}\"')}"
        },
        {
            "title": "Boletines Oficiales (BOE / BOP / Ayuntamientos)",
            "dork": f'site:boe.es OR "bop" "{national_number}"',
            "url": f"https://www.google.com/search?q={quote(f'site:boe.es OR \"bop\" \"{national_number}\"')}"
        },
        {
            "title": "Documentos Expuestos (PDF / DOCX / XLS)",
            "dork": f'filetype:pdf OR filetype:xlsx OR filetype:docx "{national_number}"',
            "url": f"https://www.google.com/search?q={quote(f'filetype:pdf OR filetype:xlsx OR filetype:docx \"{national_number}\"')}"
        },
        {
            "title": "Directorios y Guías Telefónicas",
            "dork": f'site:paginasamarillas.es OR site:infobel.com "{national_number}"',
            "url": f"https://www.google.com/search?q={quote(f'site:paginasamarillas.es OR site:infobel.com \"{national_number}\"')}"
        }
    ]

    return {
        "raw_query": raw_phone,
        "clean_digits": digits_only,
        "e164_format": e164_format,
        "national_format": national_number,
        "country": country_name,
        "country_code": country_code,
        "dial_code": dial_code,
        "line_type": line_type,
        "location": location,
        "operator_assigned": operator_assigned,
        "tariff_info": tariff_info,
        "is_valid_length": is_valid_length,
        "direct_messaging": direct_messaging,
        "reputation_checks": reputation_checks,
        "phoneinfoga_dorks": formatted_dorks,
    }
