#!/usr/bin/env python3

import argparse
import os
import re
import time
import requests
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API KEYS (secure)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

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
    [bold white]   > mshield v10 | Secure Version [/bold white]
    """
    console.print(banner)

def local_analysis(text):
    score = 0
    reasons = []

    keywords = ["login", "verify", "urgent", "password", "bank", "free", "winner"]

    urls = URL_RX.findall(text)

    for k in keywords:
        if k in text.lower():
            score += 1
            reasons.append(f"keyword:{k}")

    if urls:
        score += len(urls)
        reasons.append("url_detected")

    if score >= 4:
        verdict = "Malicious"
    elif score >= 2:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return verdict, reasons


def virustotal_check(url):
    if not VT_API_KEY:
        return "Missing API Key"

    try:
        headers = {"x-apikey": VT_API_KEY}

        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if res.status_code != 200:
            return "VT Error"

        analysis_id = res.json()["data"]["id"]

        time.sleep(2)

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats = report.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)

        total = sum(stats.values())

        return f"{malicious}/{total} engines flagged"

    except:
        return "Connection Error"


def main():
    show_banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--text", required=True)
    args = parser.parse_args()

    text = args.text

    with console.status("Scanning..."):
        verdict, reasons = local_analysis(text)
        urls = URL_RX.findall(text)

        vt_results = []
        for u in urls:
            vt_results.append(f"{u} -> {virustotal_check(u)}")

    table = Table(title="MSHIELD REPORT")
    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Verdict", verdict)
    table.add_row("Reasons", ", ".join(reasons))
    table.add_row("VirusTotal", "\n".join(vt_results) if vt_results else "No URLs")

    console.print(table)


if __name__ == "__main__":
    main()
