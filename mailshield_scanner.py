#!/usr/bin/env python3

import argparse
import os
import re
import sys
import requests
from rich.console import Console
from rich.table import Table

# --- Config ---
VT_API_KEY = "a11e7c873ee746963e43e27bc410ff3ce4a52fb697f8a3190f7cf37b9fb530ec"

console = Console()
URL_RX = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

def show_banner():

    banner = """
    [bold cyan]
    ███╗   ███╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
    ████╗ ████║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
    ██╔████╔██║███████╗███████║██║█████╗  ██║     ██║  ██║
    ██║╚██╔╝██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
    ██║ ╚═╝ ██║███████║██║  ██║██║███████╗███████╗██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
    [/bold cyan]
    [bold white]   > mshield v8.5 | [/bold white][bold green]Developed by: ESMAIL [/bold green]
    """
    console.print(banner)

def perform_local_analysis(content):
    red_flags = [
        "win", "prize", "bank", "account", "secure", "login", "password", 
        "verify", "urgent", "congratulations", "gift", "money", "update",
        "action required", "suspended", "security alert", "claim", "free",
        "bit.ly", "t.co", "tinyurl", "gift-card", "winner"
    ]
    bad_url_patterns = ["secure-", "login-", "-verify", "update-", "verify-", ".xyz", ".top", ".info", "free-"]
    
    score = 0
    detected_indicators = []
    urls = URL_RX.findall(content)
    
    for flag in red_flags:
        if flag.lower() in content.lower():
            score += 1
            detected_indicators.append(f"keyword:{flag}")
            
    for url in urls:
        score += 2
        for pattern in bad_url_patterns:
            if pattern in url.lower():
                score += 2
                detected_indicators.append(f"bad_url_pattern:{pattern}")

    if "!" in content or "URGENT" in content.upper():
        score += 1
        detected_indicators.append("urgency_detected")

    if score >= 4:
        verdict = "Malicious"
    elif score >= 1:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        
    return verdict, ", ".join(detected_indicators) if detected_indicators else "No threats detected"

def check_virustotal(url):
    if not VT_API_KEY: return "Skipped"
    try:
        headers = {'x-apikey': VT_API_KEY}
        resp = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url}, timeout=10)
        if resp.status_code == 200:
            analysis_id = resp.json()['data']['id']
            report = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers, timeout=10)
            stats = report.json()['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            return f"[bold red]Detected ({malicious})[/bold red]" if malicious > 0 else "[bold green]Clean[/bold green]"
        return f"Error ({resp.status_code})"
    except: return "Connection Error"

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="mshield: Lightweight Phishing Scanner")
    parser.add_argument('-t', '--text', help='Target text/URL to scan')
    args = parser.parse_args()

    if not args.text:
        console.print("[yellow]Usage: python3 mshield.py -t 'your text'[/yellow]")
        return

    with console.status("[bold blue]Scanning...[/bold blue]"):
        verdict, analysis_desc = perform_local_analysis(args.text)
        urls = URL_RX.findall(args.text)
        vt_results = [f"{u}: {check_virustotal(u)}" for u in urls]
        vt_final = "\n".join(vt_results) if vt_results else "No Links Found"

    results_table = Table(title="MSHIELD SECURITY REPORT", header_style="bold cyan")
    results_table.add_column("Metric", style="magenta")
    results_table.add_column("Details", style="white")

    v_color = "green" if verdict == "Safe" else "yellow" if verdict == "Suspicious" else "red"
    results_table.add_row("Verdict", f"[bold {v_color}]{verdict}[/bold {v_color}]")
    results_table.add_row("Logic", analysis_desc)
    results_table.add_row("VirusTotal", vt_final)

    console.print(results_table)

if __name__ == '__main__':
    main()
