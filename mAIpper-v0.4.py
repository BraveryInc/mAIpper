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
import os
import re
import uuid
from pathlib import Path
import xml.etree.ElementTree as ET
import logging

import requests
from dotenv import load_dotenv


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
    lines = [
        f"Nmap args: {scan_data.get('nmap_args', '')}",
        f"Hosts count: {len(hosts)}"
    ]
    for h in hosts:
        name = choose_host_display_name(h)
        ports = ", ".join(f"{p['protocol']}/{p['port']}" for p in h["open_ports"]) or "none"
        lines.append(f"- {name} ({h['state']}): open={ports}")

    prompt = "Analyze the following Nmap summary:\n\n" + "\n".join(lines)
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
    load_dotenv()

    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", default=os.getenv("XML_PATH"))
    ap.add_argument("--scans-dir", default=os.getenv("SCANS_DIR"))
    ap.add_argument("--vault", default=os.getenv("VAULT_PATH", "Vault"))
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
        default=0,
        help="Increase verbosity (-v, -vv for more detail)"
    )

    args = ap.parse_args()

    if args.verbose == 0:
        level = logging.WARNING
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s"
    )

    logging.debug(f"Parsed arguments: {vars(args)}")

    vault_dir = Path(args.vault).resolve()
    logging.debug(f"Resolved vault dir: {vault_dir}")

    xml_files = []

    if args.scans_dir:
        base = Path(args.scans_dir)
        nmap_dir = base / "nmap"
        if not nmap_dir.exists():
            nmap_dir = base / "Nmap"

        logging.debug(f"Looking for XML files in: {nmap_dir}")
        xml_files = sorted(nmap_dir.glob("*.xml"))

    elif args.xml:
        xml_files = [Path(args.xml)]
        logging.debug(f"Using single XML file: {xml_files[0]}")

    else:
        logging.error("Provide --scans-dir or --xml")
        return

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
