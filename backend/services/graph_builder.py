"""Constructor del grafo de relaciones para visualización en Cytoscape.js."""
from typing import Dict, List, Any


def build_attack_surface_graph(scan_result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Genera la estructura de elementos {nodes, edges} con metadatos técnicos profundos."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    existing_nodes = set()

    target = scan_result.get("target", "Target")

    # 1. Nodo Raíz (Target)
    root_id = f"target_{target}"
    nodes.append({
        "data": {
            "id": root_id,
            "label": target,
            "type": "target",
            "meta": {
                "target": target,
                "dns_records": scan_result.get("dns", {}).get("records", {}),
                "email_security": scan_result.get("dns", {}).get("email_security", {}),
                "rdap": scan_result.get("rdap_domain", {}),
                "http_audit": scan_result.get("http_audit", {}),
            }
        }
    })
    existing_nodes.add(root_id)

    # 2. Subdominios descubiertos
    subdomains = scan_result.get("subdomains", [])
    for sub in subdomains[:20]:
        sub_id = f"sub_{sub}"
        # Truncar visualmente si es excesivamente largo para el grafo
        sub_label = (sub[:22] + "..") if len(sub) > 24 else sub
        if sub_id not in existing_nodes:
            nodes.append({
                "data": {
                    "id": sub_id,
                    "label": sub_label,
                    "type": "subdomain",
                    "meta": {"subdomain": sub}
                }
            })
            existing_nodes.add(sub_id)
            edges.append({
                "data": {
                    "id": f"edge_{root_id}_{sub_id}",
                    "source": root_id,
                    "target": sub_id,
                    "label": "subdomain"
                }
            })

    # 3. Direcciones IP resueltas
    shodan_data = scan_result.get("shodan", [])
    for ip_entry in shodan_data:
        ip = ip_entry.get("ip")
        if not ip:
            continue
        ip_id = f"ip_{ip}"
        if ip_id not in existing_nodes:
            nodes.append({
                "data": {
                    "id": ip_id,
                    "label": ip,
                    "type": "ip",
                    "meta": {
                        "ip": ip,
                        "asn": ip_entry.get("asn"),
                        "org": ip_entry.get("org"),
                        "isp": ip_entry.get("isp"),
                        "os": ip_entry.get("os"),
                        "country": ip_entry.get("country"),
                        "city": ip_entry.get("city"),
                        "cpes": ip_entry.get("cpes", []),
                        "tags": ip_entry.get("tags", []),
                        "ports_count": len(ip_entry.get("ports", [])),
                        "vulns_count": len(ip_entry.get("vulns", [])),
                        "source": ip_entry.get("source"),
                    }
                }
            })
            existing_nodes.add(ip_id)
            edges.append({
                "data": {
                    "id": f"edge_{root_id}_{ip_id}",
                    "source": root_id,
                    "target": ip_id,
                    "label": "resolves_to"
                }
            })

        # 4. Puertos y Servicios expuestos en esta IP
        services = ip_entry.get("services", [])
        for srv in services:
            port = srv.get("port")
            port_id = f"port_{ip}_{port}"
            prod = srv.get("product", "")
            ver = srv.get("version", "")
            transport = srv.get("transport", "tcp")
            
            # Limpiar descripciones largas entre paréntesis para la etiqueta visual del grafo
            short_prod = prod.split("(")[0].strip() if "(" in prod else prod
            if len(short_prod) > 16:
                short_prod = short_prod[:14] + ".."
            
            port_label = f":{port}/{transport} {short_prod}".strip()
            if port_id not in existing_nodes:
                nodes.append({
                    "data": {
                        "id": port_id,
                        "label": port_label,
                        "type": "port",
                        "meta": {**srv, "ip": ip}
                    }
                })
                existing_nodes.add(port_id)
                edges.append({
                    "data": {
                        "id": f"edge_{ip_id}_{port_id}",
                        "source": ip_id,
                        "target": port_id,
                        "label": "open_port"
                    }
                })

        # 5. Vulnerabilidades (CVEs) priorizando las de mayor CVSS
        vuln_details = ip_entry.get("vuln_details", {})
        sorted_cves = sorted(
            vuln_details.values(),
            key=lambda v: (v.get("cvss") or 0.0, v.get("cve", "")),
            reverse=True
        )
        for v_info in sorted_cves[:18]:
            cve = v_info.get("cve")
            cve_id = f"cve_{cve}"
            if cve_id not in existing_nodes:
                nodes.append({
                    "data": {
                        "id": cve_id,
                        "label": f"{cve}" + (f" ({v_info['cvss']})" if v_info.get("cvss") else ""),
                        "type": "cve",
                        "severity": (v_info.get("severity") or "HIGH").lower(),
                        "meta": v_info,
                    }
                })
                existing_nodes.add(cve_id)

            # Conectar CVE con el puerto afectado si se conoce, o con la IP
            affected_ports = v_info.get("ports", [])
            linked_to_port = False
            for p_num in affected_ports:
                target_port_id = f"port_{ip}_{p_num}"
                if target_port_id in existing_nodes:
                    edge_id = f"edge_{target_port_id}_{cve_id}"
                    edges.append({
                        "data": {
                            "id": edge_id,
                            "source": target_port_id,
                            "target": cve_id,
                            "label": "vulnerable_to"
                        }
                    })
                    linked_to_port = True
            if not linked_to_port:
                edges.append({
                    "data": {
                        "id": f"edge_{ip_id}_{cve_id}",
                        "source": ip_id,
                        "target": cve_id,
                        "label": "vulnerability"
                    }
                })

    # 6. Añadir vulnerabilidades web globales (ej: SCA Web / Wappalyzer CVEs)
    all_vulns = scan_result.get("vulnerabilities", [])
    for v_info in all_vulns[:25]:
        cve = v_info.get("cve")
        if not cve:
            continue
        cve_id = f"cve_{cve}"
        if cve_id not in existing_nodes:
            nodes.append({
                "data": {
                    "id": cve_id,
                    "label": f"{cve}" + (f" ({v_info['cvss']})" if v_info.get("cvss") else ""),
                    "type": "cve",
                    "severity": (v_info.get("severity") or "HIGH").lower(),
                    "meta": v_info,
                }
            })
            existing_nodes.add(cve_id)

            linked = False
            for host_ip in v_info.get("ips", []):
                for p_num in v_info.get("ports", []):
                    port_node_id = f"port_{host_ip}_{p_num}"
                    if port_node_id in existing_nodes:
                        edges.append({
                            "data": {
                                "id": f"edge_{port_node_id}_{cve_id}",
                                "source": port_node_id,
                                "target": cve_id,
                                "label": "vulnerable_to"
                            }
                        })
                        linked = True
                        break
                if linked:
                    break
                ip_node_id = f"ip_{host_ip}"
                if ip_node_id in existing_nodes:
                    edges.append({
                        "data": {
                            "id": f"edge_{ip_node_id}_{cve_id}",
                            "source": ip_node_id,
                            "target": cve_id,
                            "label": "vulnerability"
                        }
                    })
                    linked = True
                    break

            if not linked:
                edges.append({
                    "data": {
                        "id": f"edge_{root_id}_{cve_id}",
                        "source": root_id,
                        "target": cve_id,
                        "label": "web_vulnerability"
                    }
                })

    return {"nodes": nodes, "edges": edges}
