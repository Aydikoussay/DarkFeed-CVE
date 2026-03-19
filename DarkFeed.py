#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              DARKFEED — CVE Intelligence Tool                    ║
║                                                                  ║
║   Author  :  Atrox                                               ║
║   Version :  1.0                                                 ║
║                                                                  ║
║                                                                  ║
║   "Know the vulnerability before the enemy does."                ║
╚══════════════════════════════════════════════════════════════════╝

Features:
  - CVE search via NVD API v2
  - CWE category, Attack Vector, Affected CPE versions
  - PoC availability check (GitHub)
  - Patch status check (NVD + GitHub)
  - Exploit chain mapping (CVE → ExploitDB → Metasploit → PoC)
  - Export to TXT / JSON
  - Severity / year / score filters

Usage: python3 darkfeed.py
"""

import requests
import subprocess
import json
import sys
import os
import time
import re
from datetime import datetime

# ─── COLORS ───────────────────────────────────────────────────────────────────
R    = "\033[1;31m"
G    = "\033[1;32m"
Y    = "\033[1;33m"
B    = "\033[1;34m"
M    = "\033[1;35m"
C    = "\033[1;36m"
W    = "\033[1;37m"
DIM  = "\033[2;37m"
RESET= "\033[0m"
BOLD = "\033[1m"

SEV_COLOR = {
    "CRITICAL": R,
    "HIGH":     M,
    "MEDIUM":   Y,
    "LOW":      G,
    "UNKNOWN":  DIM,
}

NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API   = "https://api.github.com/search/repositories"
GITHUB_CODE  = "https://api.github.com/search/code"

# ─── SESSION ──────────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "darkfeed/1.0"})

NVD_KEY    = os.environ.get("NVD_API_KEY", "")
GITHUB_KEY = os.environ.get("GITHUB_TOKEN", "")

if NVD_KEY:
    SESSION.headers["apiKey"] = NVD_KEY

# ─── BANNER ───────────────────────────────────────────────────────────────────
def banner():
    os.system("clear")
    print(f"""
{R} ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗███████╗███████╗██████╗ {RESET}
{R} ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗{RESET}
{R} ██║  ██║███████║██████╔╝█████╔╝ █████╗  █████╗  █████╗  ██║  ██║{RESET}
{R} ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══╝  ██╔══╝  ██║  ██║{RESET}
{R} ██████╔╝██║  ██║██║  ██║██║  ██╗██║     ███████╗███████╗██████╔╝{RESET}
{R} ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═════╝ {RESET}
{DIM}  ─────────────────────────────────────────────────────────────────────{RESET}
{DIM}  CVE Intelligence  │  PoC Hunter  │  Exploit Chain  │  Patch Status{RESET}
{DIM}  NVD v2  +  ExploitDB  +  Metasploit  +  GitHub{RESET}
{DIM}  ───────────────────────────────────────────────────────────────────────{RESET}
{DIM}  Author  {RESET}{C}Atrox{RESET}          {DIM}Version  {RESET}{W}1.0{RESET}          {DIM}License  {RESET}{W}MIT{RESET}
{DIM}  “Know the vulnerability before the enemy does.”{RESET}
{C}  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC{RESET}{"   " + R + "[NVD KEY OK]" + RESET if NVD_KEY else ""}{"   " + G + "[GITHUB TOKEN OK]" + RESET if GITHUB_KEY else ""}
{DIM}  ─────────────────────────────────────────────────────────────────────{RESET}""")

# ─── MENU ─────────────────────────────────────────────────────────────────────
def menu():
    print(f"""
{W}  SEARCH{RESET}
  {C}[1]{RESET} Keyword search              {DIM}apache, log4j, vsftpd 2.3.4{RESET}
  {C}[2]{RESET} CVE ID lookup               {DIM}CVE-2021-44228{RESET}
  {C}[3]{RESET} Service + version           {DIM}openssh 7.4{RESET}
  {C}[4]{RESET} Latest CVEs from NVD

{W}  RECON{RESET}
  {C}[5]{RESET} Exploit chain for CVE       {DIM}CVE → EDB → MSF → PoC → Patch{RESET}
  {C}[6]{RESET} PoC hunter (GitHub)         {DIM}search PoC repos by keyword{RESET}

{W}  TOOLS{RESET}
  {C}[7]{RESET} ExploitDB search            {DIM}requires searchsploit{RESET}
  {C}[8]{RESET} Metasploit search           {DIM}requires msfconsole{RESET}
  {C}[9]{RESET} Export last results         {DIM}TXT or JSON{RESET}
  {C}[0]{RESET} Exit
{DIM}  ──────────────────────────────────────────────────────────────────────{RESET}""")

# ─── STATE ────────────────────────────────────────────────────────────────────
LAST_RESULTS = {"cves": [], "exploits": [], "msf": [], "pocs": [], "query": ""}

# ─── UTILS ────────────────────────────────────────────────────────────────────
def spin(msg):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    for i in range(18):
        sys.stdout.write(f"\r{C}  {frames[i%len(frames)]}  {msg}{RESET}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\r{' '*70}\r")
    sys.stdout.flush()

def sep(char="─", color=DIM):
    print(f"{color}  {'─'*68}{RESET}")

def wrap(text, width=66, indent=7):
    words = text.split()
    lines, line = [], ""
    for w in words:
        if len(line)+len(w)+1 > width:
            lines.append(line.rstrip())
            line = w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line.strip())
    return ("\n"+" "*indent).join(lines[:4])

def prompt(msg):
    try:
        return input(f"\n{C}  [>] {msg}: {W}").strip()
    except (KeyboardInterrupt, EOFError):
        print(RESET)
        return ""
    finally:
        print(RESET, end="")

# ─── NVD PARSE ────────────────────────────────────────────────────────────────
def parse_nvd(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve      = item.get("cve", {})
        cve_id   = cve.get("id", "N/A")
        descs    = cve.get("descriptions", [])
        desc     = next((d["value"] for d in descs if d["lang"] == "en"), "No description")
        published= cve.get("published", "")[:10]
        modified = cve.get("lastModified", "")[:10]

        # CVSS score + severity + vector
        metrics  = cve.get("metrics", {})
        score, severity, vector = None, "UNKNOWN", None
        for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m    = metrics[key][0]
                cvss = m.get("cvssData", {})
                score    = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", m.get("baseSeverity","UNKNOWN")).upper()
                vector   = cvss.get("vectorString")
                break

        # CWE
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value","").startswith("CWE-"):
                    cwes.append(d["value"])

        # CPE (affected versions)
        cpes = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        uri = match.get("criteria","")
                        # parse human-readable version from CPE URI
                        parts = uri.split(":")
                        if len(parts) >= 6:
                            vendor  = parts[3] if parts[3] != "*" else ""
                            product = parts[4] if parts[4] != "*" else ""
                            version = parts[5] if parts[5] not in ("*","-","") else ""
                            ver_end = match.get("versionEndIncluding") or match.get("versionEndExcluding","")
                            label   = f"{vendor}/{product}"
                            if version:
                                label += f" {version}"
                            elif ver_end:
                                op = "<=" if match.get("versionEndIncluding") else "<"
                                label += f" {op}{ver_end}"
                            if label.strip("/"):
                                cpes.append(label)

        # Patch / fix references
        refs = cve.get("references", [])
        patch_refs = []
        for r in refs:
            tags = r.get("tags", [])
            url  = r.get("url","")
            if any(t in tags for t in ["Patch","Fix","Vendor Advisory"]) or \
               any(k in url for k in ["patch","fix","advisory","commit","release"]):
                patch_refs.append(url)

        all_refs = [r["url"] for r in refs[:3]]

        results.append({
            "id":        cve_id,
            "desc":      desc,
            "score":     score,
            "severity":  severity,
            "vector":    vector,
            "cwes":      cwes[:3],
            "cpes":      list(dict.fromkeys(cpes))[:6],   # deduplicated
            "published": published,
            "modified":  modified,
            "patch_refs":patch_refs[:3],
            "refs":      all_refs,
        })
    return results

# ─── NVD CALLS ────────────────────────────────────────────────────────────────
def nvd_search(keyword, limit=20, min_score=None, year_from=None, severities=None):
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 100)}
        r = SESSION.get(NVD_API, params=params, timeout=15)
        if r.status_code == 403:
            print(f"\n{Y}  [!] NVD rate limit hit — set NVD_API_KEY env var for higher limits{RESET}")
            return []
        if r.status_code != 200:
            print(f"\n{R}  [!] NVD API returned {r.status_code}{RESET}")
            return []
        results = parse_nvd(r.json())
        return apply_filters(results, min_score, year_from, severities)
    except requests.exceptions.ConnectionError:
        print(f"\n{R}  [!] Cannot reach NVD API — check internet connection{RESET}")
        return []
    except Exception as e:
        print(f"\n{R}  [!] NVD error: {e}{RESET}")
        return []

def nvd_by_id(cve_id):
    try:
        r = SESSION.get(NVD_API, params={"cveId": cve_id.upper()}, timeout=10)
        if r.status_code != 200:
            return []
        return parse_nvd(r.json())
    except Exception as e:
        print(f"\n{R}  [!] Error: {e}{RESET}")
        return []

def nvd_latest(limit=15):
    try:
        r = SESSION.get(NVD_API, params={"resultsPerPage": limit}, timeout=15)
        if r.status_code != 200:
            return []
        return parse_nvd(r.json())
    except Exception as e:
        print(f"\n{R}  [!] Error: {e}{RESET}")
        return []

def apply_filters(results, min_score=None, year_from=None, severities=None):
    out = []
    for c in results:
        if min_score and (c["score"] is None or c["score"] < float(min_score)):
            continue
        if year_from and c["published"]:
            try:
                if int(c["published"][:4]) < int(year_from):
                    continue
            except:
                pass
        if severities and c["severity"] not in severities:
            continue
        out.append(c)
    return out

# ─── GITHUB PoC ───────────────────────────────────────────────────────────────
def github_poc_check(cve_id):
    """Search GitHub for PoC repositories matching a CVE ID."""
    headers = {}
    if GITHUB_KEY:
        headers["Authorization"] = f"token {GITHUB_KEY}"
    try:
        r = requests.get(
            GITHUB_API,
            params={"q": cve_id, "sort": "stars", "order": "desc", "per_page": 5},
            headers=headers,
            timeout=10
        )
        if r.status_code == 403:
            return [], "rate_limited"
        if r.status_code != 200:
            return [], "error"
        items = r.json().get("items", [])
        pocs  = []
        for item in items:
            name = item.get("full_name","")
            desc = item.get("description","") or ""
            stars= item.get("stargazers_count", 0)
            url  = item.get("html_url","")
            # filter for likely PoC repos
            if any(k in (name+desc).lower() for k in [
                cve_id.lower(), "poc", "exploit", "proof","rce","cve"
            ]):
                pocs.append({
                    "repo":  name,
                    "desc":  desc[:80],
                    "stars": stars,
                    "url":   url
                })
        return pocs, "ok"
    except requests.exceptions.ConnectionError:
        return [], "offline"
    except Exception as e:
        return [], str(e)

# ─── PATCH CHECK ──────────────────────────────────────────────────────────────
def patch_check(cve):
    """Determine patch status from NVD references."""
    patch_refs = cve.get("patch_refs", [])
    modified   = cve.get("modified", "")
    published  = cve.get("published", "")

    if patch_refs:
        return "PATCHED", patch_refs
    # Heuristic: if modified > published by meaningful margin, likely patched
    if modified and published and modified > published:
        return "LIKELY PATCHED", []
    return "NO PATCH FOUND", []

# ─── EXPLOITDB ────────────────────────────────────────────────────────────────
def search_exploitdb(query):
    try:
        r = subprocess.run(
            ["searchsploit","--json", query],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout:
            data  = json.loads(r.stdout)
            items = data.get("RESULTS_EXPLOIT", [])[:15]
            return [{"title":i.get("Title",""), "edb":i.get("EDB-ID",""),
                     "type":i.get("Type",""), "platform":i.get("Platform",""),
                     "url": f"https://www.exploit-db.com/exploits/{i.get('EDB-ID','')}"}
                    for i in items]
        return []
    except FileNotFoundError:
        print(f"\n{Y}  [!] searchsploit not found{RESET}")
        return []
    except Exception:
        return []

# ─── METASPLOIT ───────────────────────────────────────────────────────────────
def search_msf(query):
    try:
        r = subprocess.run(
            ["msfconsole","-q","-x",f"search {query}; exit"],
            capture_output=True, text=True, timeout=30
        )
        mods = []
        for line in r.stdout.split("\n"):
            if any(t in line for t in ["exploit/","auxiliary/","post/"]):
                parts = line.strip().split()
                if len(parts) >= 2:
                    mods.append({
                        "module": parts[1] if len(parts)>1 else parts[0],
                        "name":   " ".join(parts[3:]) if len(parts)>3 else ""
                    })
        return mods[:10]
    except FileNotFoundError:
        print(f"\n{Y}  [!] msfconsole not found{RESET}")
        return []
    except Exception:
        return []

# ─── PRINT CVEs ───────────────────────────────────────────────────────────────
def print_cves(cves, verbose=True):
    if not cves:
        print(f"\n{Y}  [~] No CVEs found{RESET}\n")
        return

    critical = sum(1 for c in cves if c["severity"]=="CRITICAL")
    high     = sum(1 for c in cves if c["severity"]=="HIGH")
    medium   = sum(1 for c in cves if c["severity"]=="MEDIUM")
    low      = sum(1 for c in cves if c["severity"] in ("LOW","UNKNOWN"))

    risk_col = R if critical else M if high else Y if medium else G
    print(f"\n{C}  ┌─ RISK SUMMARY {'─'*50}{RESET}")
    print(f"{C}  │{RESET}  Total: {W}{len(cves)}{RESET}  "
          f"{R}CRITICAL:{critical}{RESET}  "
          f"{M}HIGH:{high}{RESET}  "
          f"{Y}MEDIUM:{medium}{RESET}  "
          f"{G}LOW:{low}{RESET}")
    print(f"{C}  └{'─'*65}{RESET}\n")

    for i, c in enumerate(cves, 1):
        col   = SEV_COLOR.get(c["severity"], DIM)
        score = f"{W}{c['score']}{RESET}" if c["score"] else f"{DIM}N/A{RESET}"
        badge = f"{col}[{c['severity']}]{RESET}"

        print(f"  {DIM}{i:02d}.{RESET} {C}{c['id']}{RESET}  {badge}  "
              f"CVSS:{score}  {DIM}Published:{c['published']}{RESET}")

        # Description
        print(f"       {DIM}{wrap(c['desc'])}{RESET}")

        if verbose:
            # Attack vector
            if c.get("vector"):
                # Parse vector string into readable parts
                vparts = c["vector"].replace("CVSS:3.1/","").replace("CVSS:3.0/","")
                print(f"       {Y}Vector  {RESET}{DIM}{vparts}{RESET}")

            # CWE
            if c.get("cwes"):
                cwe_str = "  ".join(c["cwes"])
                print(f"       {M}CWE     {RESET}{DIM}{cwe_str}{RESET}")

            # Affected CPEs
            if c.get("cpes"):
                print(f"       {G}Affects {RESET}", end="")
                cpe_lines = c["cpes"]
                print(f"{DIM}{cpe_lines[0]}{RESET}")
                for cp in cpe_lines[1:]:
                    print(f"               {DIM}{cp}{RESET}")

            # Patch status
            status, prefs = patch_check(c)
            patch_col = G if "PATCHED" in status else R
            print(f"       {patch_col}Patch   {RESET}{DIM}{status}{RESET}", end="")
            if prefs:
                print(f"  {DIM}→ {prefs[0][:60]}{RESET}", end="")
            print()

            # Refs
            if c.get("refs"):
                print(f"       {DIM}→ {c['refs'][0]}{RESET}")

        print()

# ─── PRINT EXPLOITS ───────────────────────────────────────────────────────────
def print_exploits(exploits):
    if not exploits:
        print(f"\n{Y}  [~] No exploits found in ExploitDB{RESET}\n")
        return
    print(f"\n{R}  ┌─ EXPLOITDB ({len(exploits)}) {'─'*52}{RESET}")
    for i, e in enumerate(exploits, 1):
        print(f"{R}  │{RESET}  {Y}{i:02d}.{RESET} {W}{e['title']}{RESET}")
        print(f"       {DIM}Type:{e['type']}  Platform:{e['platform']}  "
              f"EDB-{e['edb']}{RESET}")
        print(f"       {C}{e['url']}{RESET}\n")
    print(f"{R}  └{'─'*65}{RESET}\n")

# ─── PRINT MSF ────────────────────────────────────────────────────────────────
def print_msf(mods):
    if not mods:
        print(f"\n{Y}  [~] No Metasploit modules found{RESET}\n")
        return
    print(f"\n{R}  ┌─ METASPLOIT MODULES ({len(mods)}) {'─'*42}{RESET}")
    for i, m in enumerate(mods, 1):
        print(f"{R}  │{RESET}  {Y}{i:02d}.{RESET} {W}{m['module']}{RESET}")
        if m.get("name"):
            print(f"       {DIM}{m['name']}{RESET}")
        print()
    print(f"{R}  └{'─'*65}{RESET}\n")

# ─── PRINT PoCs ───────────────────────────────────────────────────────────────
def print_pocs(pocs, status="ok"):
    if status == "rate_limited":
        print(f"\n{Y}  [!] GitHub rate limit — set GITHUB_TOKEN env var{RESET}\n")
        return
    if status == "offline":
        print(f"\n{Y}  [!] Cannot reach GitHub API{RESET}\n")
        return
    if not pocs:
        print(f"\n{Y}  [~] No PoC repositories found on GitHub{RESET}\n")
        return
    print(f"\n{M}  ┌─ PoC REPOSITORIES ({len(pocs)}) {'─'*44}{RESET}")
    for i, p in enumerate(pocs, 1):
        print(f"{M}  │{RESET}  {Y}{i:02d}.{RESET} {W}{p['repo']}{RESET}  {DIM}★{p['stars']}{RESET}")
        if p["desc"]:
            print(f"       {DIM}{p['desc']}{RESET}")
        print(f"       {C}{p['url']}{RESET}\n")
    print(f"{M}  └{'─'*65}{RESET}\n")

# ─── EXPLOIT CHAIN ────────────────────────────────────────────────────────────
def print_chain(cve_id, cve_data, exploits, msf_mods, pocs, poc_status):
    """Full exploit chain report for one CVE."""
    col = SEV_COLOR.get(cve_data.get("severity","UNKNOWN"), DIM) if cve_data else DIM

    print(f"\n{C}  ╔══ EXPLOIT CHAIN — {cve_id} {'═'*40}{RESET}")

    # 1. CVE
    if cve_data:
        status, prefs = patch_check(cve_data)
        patch_col = G if "PATCHED" in status else R
        print(f"{C}  ║{RESET}")
        print(f"{C}  ║{RESET}  {col}[CVE]{RESET}  {W}{cve_id}{RESET}  "
              f"CVSS:{W}{cve_data.get('score','N/A')}{RESET}  "
              f"{col}[{cve_data.get('severity','?')}]{RESET}")
        if cve_data.get("vector"):
            vp = cve_data["vector"].replace("CVSS:3.1/","").replace("CVSS:3.0/","")
            print(f"{C}  ║{RESET}         {DIM}Vector: {vp}{RESET}")
        if cve_data.get("cwes"):
            print(f"{C}  ║{RESET}         {DIM}CWE: {', '.join(cve_data['cwes'])}{RESET}")
        if cve_data.get("cpes"):
            print(f"{C}  ║{RESET}         {DIM}Affects: {', '.join(cve_data['cpes'][:3])}{RESET}")
        print(f"{C}  ║{RESET}         {patch_col}Patch: {status}{RESET}", end="")
        if prefs:
            print(f"  {DIM}→ {prefs[0][:55]}{RESET}", end="")
        print()

    # 2. ExploitDB
    print(f"{C}  ║{RESET}")
    print(f"{C}  ║{RESET}  {R}[EXPLOITDB]{RESET}  ", end="")
    if exploits:
        print(f"{R}{len(exploits)} exploit(s) found{RESET}")
        for e in exploits[:3]:
            print(f"{C}  ║{RESET}         {DIM}EDB-{e['edb']} — {e['title'][:55]}{RESET}")
            print(f"{C}  ║{RESET}         {C}{e['url']}{RESET}")
    else:
        print(f"{DIM}no public exploits{RESET}")

    # 3. Metasploit
    print(f"{C}  ║{RESET}")
    print(f"{C}  ║{RESET}  {R}[METASPLOIT]{RESET} ", end="")
    if msf_mods:
        print(f"{R}{len(msf_mods)} module(s) found{RESET}")
        for m in msf_mods[:3]:
            print(f"{C}  ║{RESET}         {DIM}{m['module']}{RESET}")
    else:
        print(f"{DIM}no modules found{RESET}")

    # 4. PoC
    print(f"{C}  ║{RESET}")
    print(f"{C}  ║{RESET}  {M}[PoC GITHUB]{RESET} ", end="")
    if poc_status == "rate_limited":
        print(f"{Y}rate limited — set GITHUB_TOKEN{RESET}")
    elif pocs:
        print(f"{M}{len(pocs)} PoC repo(s) found{RESET}")
        for p in pocs[:3]:
            print(f"{C}  ║{RESET}         {DIM}{p['repo']}  ★{p['stars']}{RESET}")
            print(f"{C}  ║{RESET}         {C}{p['url']}{RESET}")
    else:
        print(f"{DIM}no PoC repositories found{RESET}")

    # Risk verdict
    has_exploit = bool(exploits or msf_mods or pocs)
    risk_msg    = f"{R}⚠  HIGH RISK — public exploit available{RESET}" if has_exploit \
                  else f"{G}✓  No public exploit found{RESET}"
    print(f"{C}  ║{RESET}")
    print(f"{C}  ╚══ VERDICT: {RESET}{risk_msg}")
    print()

# ─── EXPORT ───────────────────────────────────────────────────────────────────
def export_results(data):
    fmt = prompt("Export format [txt/json]").lower()
    ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    q   = re.sub(r'[^a-zA-Z0-9_-]', '_', data.get("query","results"))[:30]

    if fmt == "json":
        fname = f"darkfeed_{q}_{ts}.json"
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n{G}  [+] Exported JSON → {W}{fname}{RESET}\n")

    elif fmt == "txt":
        fname = f"darkfeed_{q}_{ts}.txt"
        with open(fname, "w") as f:
            f.write(f"DARKFEED — CVE Report\n")
            f.write(f"Query   : {data.get('query','')}\n")
            f.write(f"Date    : {datetime.utcnow().isoformat()} UTC\n")
            f.write("="*70 + "\n\n")

            cves = data.get("cves", [])
            f.write(f"CVEs FOUND: {len(cves)}\n\n")
            for c in cves:
                f.write(f"{c['id']}  [{c['severity']}]  CVSS:{c['score']}  {c['published']}\n")
                f.write(f"  Description : {c['desc'][:200]}\n")
                if c.get("vector"):
                    f.write(f"  Vector      : {c['vector']}\n")
                if c.get("cwes"):
                    f.write(f"  CWE         : {', '.join(c['cwes'])}\n")
                if c.get("cpes"):
                    f.write(f"  Affects     : {', '.join(c['cpes'][:4])}\n")
                status, prefs = patch_check(c)
                f.write(f"  Patch       : {status}\n")
                if prefs:
                    f.write(f"  Patch URL   : {prefs[0]}\n")
                if c.get("refs"):
                    f.write(f"  Reference   : {c['refs'][0]}\n")
                f.write("\n")

            exploits = data.get("exploits", [])
            if exploits:
                f.write("="*70 + "\nEXPLOITDB\n\n")
                for e in exploits:
                    f.write(f"  EDB-{e['edb']} — {e['title']}\n  {e['url']}\n\n")

            msf = data.get("msf", [])
            if msf:
                f.write("="*70 + "\nMETASPLOIT MODULES\n\n")
                for m in msf:
                    f.write(f"  {m['module']}  {m.get('name','')}\n")

            pocs = data.get("pocs", [])
            if pocs:
                f.write("\n"+"="*70 + "\nPoC REPOSITORIES\n\n")
                for p in pocs:
                    f.write(f"  {p['repo']}  ★{p['stars']}\n  {p['url']}\n\n")

        print(f"\n{G}  [+] Exported TXT  → {W}{fname}{RESET}\n")
    else:
        print(f"{R}  [!] Unknown format{RESET}\n")

# ─── FILTER PROMPT ────────────────────────────────────────────────────────────
def ask_filters():
    print(f"\n{DIM}  Filters (press Enter to skip each one):{RESET}")
    min_score  = prompt("Min CVSS score (e.g. 7.0)")
    year_from  = prompt("Min year (e.g. 2020)")
    sev_input  = prompt("Severities only — CRITICAL,HIGH,MEDIUM,LOW (comma sep)")
    severities = None
    if sev_input:
        severities = [s.strip().upper() for s in sev_input.split(",") if s.strip()]
    return (float(min_score) if min_score else None,
            int(year_from)   if year_from  else None,
            severities)

# ─── ACTIONS ──────────────────────────────────────────────────────────────────
def action_keyword():
    query = prompt("Keyword (e.g. apache log4j)")
    if not query:
        return
    min_score, year_from, severities = ask_filters()

    spin(f"NVD search: {query}")
    cves = nvd_search(query, min_score=min_score, year_from=year_from, severities=severities)
    LAST_RESULTS.update({"cves": cves, "query": query, "exploits":[], "msf":[], "pocs":[]})
    print_cves(cves)

    spin("ExploitDB")
    exploits = search_exploitdb(query)
    LAST_RESULTS["exploits"] = exploits
    print_exploits(exploits)

    spin("Metasploit")
    msf = search_msf(query)
    LAST_RESULTS["msf"] = msf
    print_msf(msf)


def action_cve_id():
    cve_id = prompt("CVE ID (e.g. CVE-2021-44228)")
    if not cve_id:
        return
    if not cve_id.upper().startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    cve_id = cve_id.upper()

    spin(f"Looking up {cve_id}")
    cves = nvd_by_id(cve_id)
    LAST_RESULTS.update({"cves": cves, "query": cve_id, "exploits":[], "msf":[], "pocs":[]})
    print_cves(cves)

    spin("ExploitDB")
    exploits = search_exploitdb(cve_id)
    LAST_RESULTS["exploits"] = exploits
    print_exploits(exploits)

    spin("Metasploit")
    msf = search_msf(cve_id)
    LAST_RESULTS["msf"] = msf
    print_msf(msf)

    spin("GitHub PoC hunt")
    pocs, status = github_poc_check(cve_id)
    LAST_RESULTS["pocs"] = pocs
    print_pocs(pocs, status)


def action_service():
    service = prompt("Service name (e.g. openssh, vsftpd, nginx)")
    version = prompt("Version (e.g. 2.3.4 — blank to skip)")
    if not service:
        return
    query = f"{service} {version}".strip()
    min_score, year_from, severities = ask_filters()

    spin(f"NVD: {query}")
    cves = nvd_search(query, min_score=min_score, year_from=year_from, severities=severities)
    LAST_RESULTS.update({"cves": cves, "query": query, "exploits":[], "msf":[], "pocs":[]})
    print_cves(cves)

    spin("ExploitDB")
    exploits = search_exploitdb(query)
    LAST_RESULTS["exploits"] = exploits
    print_exploits(exploits)

    spin("Metasploit")
    msf = search_msf(query)
    LAST_RESULTS["msf"] = msf
    print_msf(msf)


def action_latest():
    spin("Fetching latest NVD CVEs")
    cves = nvd_latest(15)
    LAST_RESULTS.update({"cves": cves, "query": "latest", "exploits":[], "msf":[], "pocs":[]})
    print_cves(cves, verbose=True)


def action_chain():
    cve_id = prompt("CVE ID for full exploit chain (e.g. CVE-2021-44228)")
    if not cve_id:
        return
    if not cve_id.upper().startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    cve_id = cve_id.upper()

    spin(f"NVD: {cve_id}")
    cves = nvd_by_id(cve_id)
    cve_data = cves[0] if cves else None

    spin("ExploitDB")
    exploits = search_exploitdb(cve_id)

    spin("Metasploit")
    msf = search_msf(cve_id)

    spin("GitHub PoC")
    pocs, poc_status = github_poc_check(cve_id)

    LAST_RESULTS.update({
        "cves": cves, "query": cve_id,
        "exploits": exploits, "msf": msf, "pocs": pocs
    })

    print_chain(cve_id, cve_data, exploits, msf, pocs, poc_status)


def action_poc_hunter():
    query = prompt("Search GitHub PoC repos (e.g. log4shell, EternalBlue)")
    if not query:
        return
    spin(f"GitHub PoC: {query}")
    pocs, status = github_poc_check(query)
    LAST_RESULTS["pocs"] = pocs
    print_pocs(pocs, status)


def action_exploitdb():
    query = prompt("ExploitDB search")
    if not query:
        return
    spin(f"ExploitDB: {query}")
    exploits = search_exploitdb(query)
    LAST_RESULTS["exploits"] = exploits
    print_exploits(exploits)


def action_msf():
    query = prompt("Metasploit search")
    if not query:
        return
    spin(f"Metasploit: {query}")
    msf = search_msf(query)
    LAST_RESULTS["msf"] = msf
    print_msf(msf)


def action_export():
    if not any([LAST_RESULTS["cves"], LAST_RESULTS["exploits"],
                LAST_RESULTS["msf"],  LAST_RESULTS["pocs"]]):
        print(f"\n{Y}  [!] No results to export — run a search first{RESET}\n")
        return
    export_results(LAST_RESULTS)

# ─── MAIN ─────────────────────────────────────────────────────────────────────
ACTIONS = {
    "1": action_keyword,
    "2": action_cve_id,
    "3": action_service,
    "4": action_latest,
    "5": action_chain,
    "6": action_poc_hunter,
    "7": action_exploitdb,
    "8": action_msf,
    "9": action_export,
}

def main():
    banner()
    while True:
        menu()
        try:
            choice = input(f"{C}  root@darkfeed{RESET}:{Y}~{RESET}$ ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n{C}  [*] Exiting DARKFEED. Stay dangerous.{RESET}\n")
            sys.exit(0)

        if choice == "0":
            print(f"\n{C}  [*] Exiting DARKFEED. Stay dangerous.{RESET}\n")
            sys.exit(0)
        elif choice in ACTIONS:
            ACTIONS[choice]()
            input(f"\n{DIM}  [press Enter to continue]{RESET}")
            banner()
        else:
            print(f"\n{R}  [!] Invalid option{RESET}")

if __name__ == "__main__":
    main()
