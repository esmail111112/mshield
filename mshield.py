#!/usr/bin/env python3

import argparse
import os
import re
import requests
import time
from rich.console import Console
from rich.table import Table

# --- Config ---
VT_API_KEY = os.getenv("VT_API_KEY")

console = Console()
URL_RX = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

def show_banner():
 3768f9a (Improve security: use environment variable for VirusTotal API key)
    banner = """
    [bold cyan]
    ███╗   ███╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
    ████╗ ████║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
    ██╔████╔██║███████╗███████║██║█████╗  ██║     ██║  ██║
    ██║╚██╔╝██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
    ██║ ╚═╝ ██║███████║██║  ██║██║███████╗███████╗██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
    [/bold cyan]
    [bold white]   > mshield v9.0 | [/bold white][bold green]Developed by: ESMAIL [/bold green]
    """
    console.print(banner)

def perform_local_analysis(content):
    red_flags = [
        "win", "prize", "bank", "account", "secure", "login", "password", 
        "verify", "urgent", "congratulations", "gift", "money", "update",
        "action required", "suspended", "security alert", "claim", "free",
        "bit.ly", "t.co", "tinyurl", "gift-card", "winner"
    ]

    bad_url_patterns = [
        "secure-", "login-", "-verify", "update-", "verify-", 
        ".xyz", ".top", ".info", "free-"
    ]

    score = 0
    detected_indicators = []
    urls = URL_RX.findall(content)

    for flag in red_flags:
        if flag.lower() in content.lower():
            score += 1
            detected_indicators.append(f"keyword:{flag}")

    for url in urls:
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
    if not VT_API_KEY:
        return "API Key Missing"

    try:
        headers = {'x-apikey': VT_API_KEY}

        # إرسال الرابط للتحليل
        resp = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url},
            timeout=10
        )

        if resp.status_code != 200:
            return f"Error ({resp.status_code})"

        analysis_id = resp.json()['data']['id']

        # انتظار بسيط عشان التقرير يجهز
        time.sleep(2)

        report = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers,
            timeout=10
        )

        if report.status_code != 200:
            return "Report Error"

        stats = report.json()['data']['attributes']['stats']

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())

        if malicious > 0:
            return f"[bold red]{malicious}/{total} engines flagged[/bold red]"
        elif suspicious > 0:
            return f"[bold yellow]{suspicious}/{total} suspicious[/bold yellow]"
        else:
            return "[bold green]Clean[/bold green]"

    except Exception:
        return "Connection Error"


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

        vt_results = []
        for u in urls:
            result = check_virustotal(u)
            vt_results.append(f"{u}\n -> {result}")

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
