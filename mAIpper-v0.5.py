#!/usr/bin/env python3

"""
mAIpper - Pentest Tool Analysis & Obsidian Export Tool

Features:
- Parses Nmap XML output
- Generates structured host and scan notes
- Optionally performs AI-assisted analysis via Ollama
- Builds/updates an Obsidian Canvas visualization

Designed for offensive security workflow documentation.

Author: Zachary Levine
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import re
import uuid
from pathlib import Path
import xml.etree.ElementTree as ET

import requests


# ============================================================
# Helpers
# ============================================================

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def safe_filename(s: str) -> str:
    bad = '<>:"/\\|?*\n\r\t'
    for ch in bad:
        s = s.replace(ch, "_")
    return s.strip().strip(".")


def new_canvas_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def is_ipv4(value: str) -> bool:
    return bool(value and IPV4_RE.match(value.strip()))


def is_probable_fqdn(value: str) -> bool:
    v = (value or "").strip().rstrip(".")
    return bool(v and "." in v and not is_ipv4(v))


def ensure_md_suffix(name: str) -> str:
    return name if name.lower().endswith(".md") else f"{name}.md"


def get_port_hints(
    port: int,
    service_name: str,
    product: str = "",
    extrainfo: str = "",
) -> list[str]:
    svc = (service_name or "").lower()
    prod = (product or "").lower()
    extra = (extrainfo or "").lower()

    hints: list[str] = []

    if port in (80, 81, 443, 8000, 8080, 8443) or svc in ("http", "https", "http-proxy"):
        hints.append("Web service detected; consider whatweb, nikto, gobuster/feroxbuster/ffuf, curl, and manual browsing.")
        hints.append("Check for default credentials, admin panels, exposed APIs, virtual hosts, and interesting headers.")

    if port == 445 or svc in ("microsoft-ds", "smb", "netbios-ssn"):
        hints.append("SMB detected; consider netexec smb, smbclient, smbmap, and enum4linux-ng.")
        hints.append("Check share access, null sessions, SMB signing, local admin reuse, and domain membership clues.")

    if port in (88, 464) or "kerberos" in svc or "kerberos" in prod:
        hints.append("Kerberos-related service detected; consider kerbrute, netexec, GetUserSPNs, and AS-REP roast checks.")
        hints.append("Look for domain naming clues, valid usernames, SPNs, and clock skew issues.")

    if port in (389, 636, 3268, 3269) or svc in ("ldap", "ldaps", "globalcatldap", "globalcatldapssl"):
        hints.append("LDAP detected; consider ldapsearch, netexec ldap, and directory enumeration.")
        hints.append("Look for anonymous bind, naming contexts, domain structure, users, groups, and password policy info.")

    if port == 135 or svc == "msrpc":
        hints.append("MSRPC detected; consider rpcclient, netexec, and enumerate Windows service exposure and domain clues.")

    if port == 139 or svc == "netbios-ssn":
        hints.append("NetBIOS detected; enumerate shares, names, and Windows host information.")

    if port in (5985, 5986) or "winrm" in svc:
        hints.append("WinRM detected; consider netexec winrm and evil-winrm if credentials are obtained.")

    if port in (1433, 1434) or "mssql" in svc or "sql server" in prod:
        hints.append("MSSQL detected; consider impacket-mssqlclient, netexec mssql, and SQL login enumeration.")

    if port == 3306 or "mysql" in svc:
        hints.append("MySQL detected; test authentication paths and enumerate version-specific exposure carefully.")

    if port == 5432 or "postgres" in svc:
        hints.append("PostgreSQL detected; test for weak/default credentials and accessible databases.")

    if port == 27017 or "mongodb" in svc:
        hints.append("MongoDB detected; verify whether authentication is required and whether remote access is overly exposed.")

    if port == 22 or svc == "ssh":
        hints.append("SSH detected; consider ssh-audit, banner review, key-based auth checks, and cautious credential testing.")

    if port == 21 or svc == "ftp":
        hints.append("FTP detected; check for anonymous access, writable locations, and plaintext credential exposure.")

    if port in (25, 465, 587) or svc in ("smtp", "smtps", "submission"):
        hints.append("SMTP detected; consider smtp-user-enum or swaks and look for open relay or user enumeration behavior.")

    if port == 53 or svc == "domain":
        hints.append("DNS detected; consider dig, nslookup, dnsrecon, and zone transfer testing where appropriate.")

    if port == 69 or svc == "tftp":
        hints.append("TFTP detected; check for unauthenticated file retrieval or upload opportunities.")

    if port == 111 or svc == "rpcbind":
        hints.append("RPCbind detected; consider rpcinfo and follow-on enumeration for NFS and related services.")

    if port == 2049 or svc == "nfs":
        hints.append("NFS detected; use showmount and test for accessible exports and weak export permissions.")

    if port in (161, 162) or svc == "snmp":
        hints.append("SNMP detected; try snmpwalk/onesixtyone and test common community strings carefully.")

    if port == 3389 or svc == "ms-wbt-server":
        hints.append("RDP detected; consider netexec rdp, xfreerdp, and review NLA / domain clues.")

    if port in (5900, 5901, 5902) or svc == "vnc":
        hints.append("VNC detected; verify authentication requirements and assess screenshot or password attack viability.")

    if port == 6379 or "redis" in svc:
        hints.append("Redis detected; verify bind/auth configuration and whether dangerous commands are exposed remotely.")

    if port == 11211 or "memcached" in svc:
        hints.append("Memcached detected; check whether it is exposed beyond localhost and assess information disclosure risk.")

    if port in (9200, 9300) or "elasticsearch" in svc:
        hints.append("Elasticsearch detected; check for unauthenticated cluster or index access.")

    if port in (2375, 2376) or "docker" in svc:
        hints.append("Docker API exposure may be high risk; verify remote daemon access and authentication/TLS posture.")

    if port == 6443 or "kubernetes" in svc:
        hints.append("Kubernetes-related service detected; look for exposed API endpoints and auth configuration issues.")

    if "ssl" in extra or "tls" in extra:
        hints.append("TLS-related context detected; review certificate details, protocol support, and any weak crypto indicators.")

    return hints


# ============================================================
# Nmap XML Parsing
# ============================================================

def parse_nmap_xml(xml_path: Path) -> dict:
    logging.info(f"Parsing XML: {xml_path}")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    scan_info = {
        "source_file": str(xml_path),
        "parsed_at": dt.datetime.now().isoformat(timespec="seconds"),
        "nmap_args": root.get("args", ""),
        "nmap_version": root.get("version", ""),
        "hosts": [],
    }

    for host in root.findall("host"):
        state_el = host.find("status")
        state = state_el.get("state") if state_el is not None else "unknown"

        addresses = [
            {"addr": a.get("addr", ""), "addrtype": a.get("addrtype", "")}
            for a in host.findall("address")
        ]

        hostnames = []
        hn_parent = host.find("hostnames")
        if hn_parent is not None:
            for hn in hn_parent.findall("hostname"):
                hostnames.append({
                    "name": hn.get("name", ""),
                    "type": hn.get("type", "")
                })

        ports = []
        ports_parent = host.find("ports")
        if ports_parent is not None:
            for port in ports_parent.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port.find("service")
                service = {}
                if service_el is not None:
                    service = {
                        "name": service_el.get("name", ""),
                        "product": service_el.get("product", ""),
                        "version": service_el.get("version", ""),
                        "extrainfo": service_el.get("extrainfo", ""),
                        "tunnel": service_el.get("tunnel", ""),
                    }

                scripts = []
                for s in port.findall("script"):
                    scripts.append({
                        "id": s.get("id", ""),
                        "output": s.get("output", ""),
                    })

                ports.append({
                    "protocol": port.get("protocol", ""),
                    "port": int(port.get("portid", "0")),
                    "service": service,
                    "scripts": scripts,
                })

        host_record = {
            "state": state,
            "addresses": addresses,
            "hostnames": hostnames,
            "open_ports": sorted(ports, key=lambda p: (p["protocol"], p["port"])),
        }
        scan_info["hosts"].append(host_record)

        logging.debug(
            f"Parsed host: display={choose_host_display_name(host_record)} "
            f"state={state} open_ports={len(host_record['open_ports'])}"
        )

    logging.info(
        f"Finished parsing XML: {xml_path.name} | hosts={len(scan_info['hosts'])}"
    )
    logging.debug(f"Nmap args: {scan_info['nmap_args']}")
    return scan_info


# ============================================================
# Host Naming / Host Summaries
# ============================================================

def choose_host_display_name(host: dict) -> str:
    hostnames = [h["name"].strip() for h in host.get("hostnames", []) if h.get("name")]

    for hn in hostnames:
        if is_probable_fqdn(hn):
            return hn.rstrip(".")

    for hn in hostnames:
        if hn:
            return hn.rstrip(".")

    for addr in host.get("addresses", []):
        if addr.get("addrtype") == "ipv4" and addr.get("addr"):
            return addr["addr"]

    for addr in host.get("addresses", []):
        if addr.get("addr"):
            return addr["addr"]

    return "unknown-host"


def get_primary_ipv4(host: dict) -> str | None:
    for addr in host.get("addresses", []):
        if addr.get("addrtype") == "ipv4" and addr.get("addr"):
            return addr["addr"]
    return None


def render_service_string(port_info: dict) -> str:
    svc = port_info.get("service", {})
    parts = [svc.get("name", "")]
    if svc.get("product"):
        parts.append(svc["product"])
    if svc.get("version"):
        parts.append(svc["version"])
    if svc.get("extrainfo"):
        parts.append(f"({svc['extrainfo']})")
    if svc.get("tunnel"):
        parts.append(f"[tunnel: {svc['tunnel']}]")
    return " ".join([p for p in parts if p]).strip() or "—"


def summarize_open_ports(host: dict, max_ports: int = 8) -> list[str]:
    summary_lines = []
    for p in host.get("open_ports", [])[:max_ports]:
        summary_lines.append(f"- **{p['protocol']}/{p['port']}** — {render_service_string(p)}")
    return summary_lines


# ============================================================
# Ollama
# ============================================================

def build_ollama_prompt(scan_data: dict) -> str:
    hosts = scan_data.get("hosts", [])

    instructions = """
You are an experienced penetration tester analyzing Nmap scan results.

Your job is to produce practical, concise, operator-focused analysis.

Priorities:
- Identify notable exposed services and likely attack surface
- Suggest useful follow-up enumeration tools for discovered services
- Suggest practical next-step commands or techniques where appropriate
- Highlight likely misconfigurations, risky exposures, or common weaknesses
- Infer likely technology stacks when reasonable, but clearly separate facts from assumptions
- Prefer real-world offensive security workflow recommendations over generic security advice

When suggesting tools, favor practical enumeration tools such as:
- SMB: netexec, smbclient, smbmap, enum4linux-ng
- LDAP: ldapsearch, netexec, bloodyAD
- Kerberos: kerbrute, impacket tools, netexec
- MSSQL: impacket-mssqlclient, netexec
- WinRM: evil-winrm, netexec
- RDP: netexec, xfreerdp
- SSH: ssh-audit, hydra
- Web: whatweb, nikto, gobuster, feroxbuster, ffuf, curl
- SNMP: snmpwalk, onesixtyone
- DNS: dig, nslookup, dnsrecon
- NFS: showmount, mount
- SMTP: swaks, smtp-user-enum
- FTP: ftp, Nmap NSE scripts
- RPC: rpcclient, netexec
- VNC: vncsnapshot, hydra

Be specific when the evidence supports it.
Do not invent vulnerabilities that are not supported by the scan.
If service detection is weak or uncertain, say so.
""".strip()

    lines = [
        f"Nmap args: {scan_data.get('nmap_args', '')}",
        f"Nmap version: {scan_data.get('nmap_version', '')}",
        f"Hosts count: {len(hosts)}",
        "",
        "Host details:",
    ]

    for host in hosts:
        name = choose_host_display_name(host)
        state = host.get("state", "unknown")
        ip = get_primary_ipv4(host) or "unknown"

        lines.append(f"- Host: {name}")
        lines.append(f"  State: {state}")
        lines.append(f"  IP: {ip}")

        open_ports = host.get("open_ports", [])
        if not open_ports:
            lines.append("  Open ports: none")
            lines.append("")
            continue

        lines.append("  Open ports:")

        for p in open_ports:
            proto = p.get("protocol", "")
            port = p.get("port", "")
            svc = p.get("service", {})
            svc_name = svc.get("name", "") or "unknown"
            product = svc.get("product", "")
            version = svc.get("version", "")
            extrainfo = svc.get("extrainfo", "")
            tunnel = svc.get("tunnel", "")

            service_parts = [svc_name]
            if product:
                service_parts.append(product)
            if version:
                service_parts.append(version)
            if extrainfo:
                service_parts.append(f"({extrainfo})")
            if tunnel:
                service_parts.append(f"[tunnel: {tunnel}]")

            service_str = " ".join(service_parts).strip()
            lines.append(f"    - {proto}/{port}: {service_str}")

            scripts = p.get("scripts", [])
            for script in scripts[:3]:
                sid = script.get("id", "").strip()
                out = (script.get("output", "") or "").strip()
                if out:
                    out = " ".join(out.split())
                    if len(out) > 220:
                        out = out[:217] + "..."
                    lines.append(f"      script:{sid} -> {out}")

            hints = get_port_hints(port, svc_name, product, extrainfo)
            for hint in hints:
                lines.append(f"      hint: {hint}")

        lines.append("")

    scan_summary = "\n".join(lines)

    output_format = """
Return your response in markdown using exactly these sections:

## Key Observations
- Brief bullets of the most important findings

## Enumeration Suggestions
- Group suggestions by service or host
- Include relevant tools and useful follow-up ideas

## Potential Attack Paths
- Mention realistic next steps or attack paths suggested by the scan
- Distinguish confirmed findings from assumptions

## Notable Risks or Misconfigurations
- Mention anything unusually exposed or high value
""".strip()

    prompt = f"""
{instructions}

Nmap Scan Summary
=================
{scan_summary}

{output_format}
""".strip()

    logging.debug(f"Built Ollama prompt ({len(prompt)} chars)")
    return prompt


def ollama_chat(base_url: str, model: str, prompt: str) -> str:
    url = base_url.rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    logging.info(f"Sending prompt to Ollama model: {model}")
    logging.debug(f"Ollama URL: {url}")

    r = requests.post(url, json=payload, timeout=180)
    logging.debug(f"Ollama HTTP status: {r.status_code}")
    r.raise_for_status()

    response_text = r.json().get("response", "")
    logging.debug(f"Ollama response length: {len(response_text)} chars")
    return response_text


# ============================================================
# Vault Writing
# ============================================================

def create_obsidian_vault(
    vault_dir: Path,
    scan_name: str,
    scan_data: dict,
    tool_name: str,
    analysis_text: str | None,
    model_name: str | None,
):
    logging.info(f"Writing Obsidian content into vault: {vault_dir}")

    vault_dir.mkdir(parents=True, exist_ok=True)
    hosts_dir = vault_dir / "Hosts"
    scans_dir = vault_dir / "Scans"
    hosts_dir.mkdir(exist_ok=True)
    scans_dir.mkdir(exist_ok=True)

    scan_display = scan_name
    if len(scan_data["hosts"]) == 1:
        scan_display = choose_host_display_name(scan_data["hosts"][0])

    scan_stem = safe_filename(f"{scan_display} - {tool_name}")
    scan_path = scans_dir / ensure_md_suffix(scan_stem)

    logging.debug(f"Scan note path: {scan_path}")

    host_entries = []

    for host in scan_data["hosts"]:
        display = choose_host_display_name(host)
        host_stem = safe_filename(display)
        host_path = hosts_dir / ensure_md_suffix(host_stem)
        primary_ip = get_primary_ipv4(host)
        open_ports = host.get("open_ports", [])

        logging.debug(
            f"Preparing host note: {display} | ip={primary_ip or 'n/a'} | "
            f"open_ports={len(open_ports)} | path={host_path}"
        )

        lines = [
            f"**State:** {host['state']}",
        ]

        if primary_ip:
            lines.append(f"**IP:** {primary_ip}")

        lines.append(f"**Open Port Count:** {len(open_ports)}")
        lines += [
            "",
            "## Open Ports"
        ]

        if open_ports:
            lines.extend(summarize_open_ports(host))
        else:
            lines.append("- None")

        lines += [
            "",
            "## Notes",
            f"- [[Scans/{scan_stem}|{scan_display} - {tool_name}]]"
        ]

        host_path.write_text("\n".join(lines), encoding="utf-8")
        logging.debug(f"Wrote host note: {host_path}")
        host_entries.append((display, host_stem, host))

    scan_lines = [
        f"# {scan_display} - {tool_name}",
        "",
        f"- **Source:** {scan_data['source_file']}",
        f"- **Parsed:** {scan_data['parsed_at']}",
        "",
        "## Hosts",
        ""
    ]

    for display, host_stem, host in host_entries:
        scan_lines.append(f"### [[Hosts/{host_stem}|{display}]]")
        if host.get("open_ports"):
            for p in host["open_ports"]:
                scan_lines.append(f"- **{p['protocol']}/{p['port']}** — {render_service_string(p)}")
        else:
            scan_lines.append("- No open ports detected")
        scan_lines.append("")

    scan_lines += [
        "## Analysis",
        ""
    ]

    if model_name:
        scan_lines.append(f"Model: `{model_name}`\n")

    scan_lines.append(analysis_text or "_No AI analysis generated._")

    scan_path.write_text("\n".join(scan_lines), encoding="utf-8")
    logging.info(f"Wrote scan note: {scan_path}")

    return {"scan_note": str(scan_path)}


# ============================================================
# Canvas (Host File Cards)
# ============================================================

def make_canvas(
    vault_dir: Path,
    canvas_name: str,
    cols: int,
    card_w: int,
    card_h: int,
    gap_x: int,
    gap_y: int,
    start_x: int,
    start_y: int,
):
    hosts_dir = vault_dir / "Hosts"
    host_notes = sorted(hosts_dir.glob("*.md"))

    logging.info(f"Generating canvas from {len(host_notes)} host notes")

    nodes = []
    cols = max(1, cols)

    for i, hp in enumerate(host_notes):
        row = i // cols
        col = i % cols
        x = start_x + col * (card_w + gap_x)
        y = start_y + row * (card_h + gap_y)

        rel_file = str(hp.relative_to(vault_dir)).replace("\\", "/")

        logging.debug(
            f"Adding canvas node for {rel_file} at x={x}, y={y}, w={card_w}, h={card_h}"
        )

        nodes.append({
            "id": new_canvas_id("host_"),
            "type": "file",
            "file": rel_file,
            "x": x,
            "y": y,
            "width": card_w,
            "height": card_h,
        })

    canvas = {"nodes": nodes, "edges": []}
    out = vault_dir / canvas_name
    out.write_text(json.dumps(canvas, indent=2), encoding="utf-8")
    logging.info(f"Wrote canvas: {out}")
    return out


# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", default=None, help="Process a single Nmap XML file")
    ap.add_argument("--scans-dir", default="scans", help="Base scans directory (default: ./scans)")
    ap.add_argument("--vault", default="Obsidian", help="Obsidian vault directory (default: ./Obsidian)")
    ap.add_argument("--tool-name", default="Nmap")
    ap.add_argument("--model", default="qwen2.5:14b-instruct-q5_K_M")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--no-ollama", action="store_true")
    ap.add_argument("--no-canvas", action="store_true")

    ap.add_argument("--canvas-name", default="Assessment Canvas.canvas")
    ap.add_argument("--canvas-cols", type=int, default=2)
    ap.add_argument("--canvas-card-w", type=int, default=360)
    ap.add_argument("--canvas-card-h", type=int, default=220)
    ap.add_argument("--canvas-gap-x", type=int, default=120)
    ap.add_argument("--canvas-gap-y", type=int, default=120)
    ap.add_argument("--canvas-start-x", type=int, default=900)
    ap.add_argument("--canvas-start-y", type=int, default=900)

    ap.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=1,
        help="Increase verbosity (-v=debug, default=info)"
    )

    args = ap.parse_args()

    level = logging.WARNING
    if args.verbose >= 1:
        level = logging.INFO
    if args.verbose >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s"
    )

    logging.debug(f"Parsed arguments: {vars(args)}")

    vault_dir = Path(args.vault).resolve()
    logging.debug(f"Resolved vault dir: {vault_dir}")

    xml_files: list[Path] = []

    if args.xml:
        xml_path = Path(args.xml).resolve()
        logging.debug(f"Using single XML file: {xml_path}")

        if not xml_path.exists():
            logging.error(f"XML file does not exist: {xml_path}")
            return

        xml_files = [xml_path]
    else:
        base = Path(args.scans_dir).resolve()
        nmap_dir = base / "nmap"
        if not nmap_dir.exists():
            nmap_dir = base / "Nmap"

        logging.debug(f"Looking for XML files in: {nmap_dir}")
        xml_files = sorted(nmap_dir.glob("*.xml"))

    if not xml_files:
        logging.warning("No XML files found to process")
        return

    logging.info(f"Found {len(xml_files)} XML file(s) to process")

    for xml_path in xml_files:
        logging.info(f"Processing scan file: {xml_path}")
        scan_data = parse_nmap_xml(xml_path)

        analysis = None
        if not args.no_ollama:
            try:
                prompt = build_ollama_prompt(scan_data)
                analysis = ollama_chat(args.ollama_url, args.model, prompt)
            except Exception as e:
                logging.warning(f"Ollama failed for {xml_path.name}: {e}")
                analysis = f"_Ollama failed: {e}_"
        else:
            logging.info("Skipping Ollama analysis due to --no-ollama")

        create_obsidian_vault(
            vault_dir,
            xml_path.stem,
            scan_data,
            args.tool_name,
            analysis,
            None if args.no_ollama else args.model
        )

    if not args.no_canvas:
        make_canvas(
            vault_dir,
            args.canvas_name,
            args.canvas_cols,
            args.canvas_card_w,
            args.canvas_card_h,
            args.canvas_gap_x,
            args.canvas_gap_y,
            args.canvas_start_x,
            args.canvas_start_y,
        )
    else:
        logging.info("Skipping canvas generation due to --no-canvas")

    logging.info("Done")


if __name__ == "__main__":
    main()
