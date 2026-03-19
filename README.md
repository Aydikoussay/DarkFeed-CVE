<div align="center">

```
 ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗███████╗███████╗██████╗
 ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗
 ██║  ██║███████║██████╔╝█████╔╝ █████╗  █████╗  █████╗  ██║  ██║
 ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══╝  ██╔══╝  ██║  ██║
 ██████╔╝██║  ██║██║  ██║██║  ██╗██║     ███████╗███████╗██████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═════╝
```

**Advanced CVE Intelligence Tool for Penetration Testers**

*"Know the vulnerability before the enemy does."*

![Python](https://img.shields.io/badge/Python-3.8%2B-red?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red?style=flat-square)
![Author](https://img.shields.io/badge/Author-Atrox-red?style=flat-square)

</div>

---

## What is DARKFEED?

DARKFEED is a pure terminal CVE intelligence tool built for senior penetration testers. It aggregates vulnerability data from multiple sources in real time, cross-references public exploits and Metasploit modules, hunts for PoC code on GitHub, and maps full exploit chains — all from a single Python script with no GUI required.

Built to answer one question fast: **"Is this target exploitable right now?"**

---

## Features

| Feature | Description |
|---|---|
| CVE keyword search | Query NVD for any product, technology, or keyword |
| CVE ID lookup | Full details for a specific CVE including vector, CWE, CPE |
| Service + version matching | Input a service name and version to find matching CVEs |
| Latest NVD feed | Real-time stream of the most recently published CVEs |
| **Exploit chain** | CVE → ExploitDB → Metasploit → GitHub PoC → Patch status |
| PoC hunter | Search GitHub for public proof-of-concept repositories |
| ExploitDB search | Cross-reference via `searchsploit` |
| Metasploit search | Check if an MSF module exists for the target |
| Patch status | Detect if a fix is available via NVD references |
| Export | Save results to TXT or JSON for reporting |
| Filters | Filter by severity, year, minimum CVSS score |

---

## Installation

```bash
# Clone the repo
git clone https://github.com/Aydikoussay/DarkFeed-CVE
cd darkfeed

# Install dependencies (only requests)
pip install requests

# Run
python3 darkfeed.py
```

---

## Optional: API Keys (Recommended)

DARKFEED works without any API keys, but setting them removes rate limits.

### NVD API Key — removes NVD rate limit (free)
1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Fill the form — you get the key by email in minutes
3. Set it:
```bash
export NVD_API_KEY="your-key-here"
```

### GitHub Token — enables PoC hunter without limits (free)
1. Go to https://github.com/settings/tokens
2. Generate a new token (classic) — no special scopes needed
3. Set it:
```bash
export GITHUB_TOKEN="your-token-here"
```

To make them permanent, add both lines to your `~/.bashrc` or `~/.zshrc`.

---

## Optional: External Tools

These are not required but unlock additional features:

| Tool | Feature unlocked | Install |
|---|---|---|
| `searchsploit` | ExploitDB search | `sudo apt install exploitdb` |
| `msfconsole` | Metasploit module search | Install Metasploit Framework |

On Kali Linux, both are typically already installed.

---

## Usage

```
python3 darkfeed.py
```

```
  SEARCH
  [1] Keyword search              apache, log4j, vsftpd 2.3.4
  [2] CVE ID lookup               CVE-2021-44228
  [3] Service + version           openssh 7.4

  RECON
  [5] Exploit chain for CVE       CVE → EDB → MSF → PoC → Patch
  [6] PoC hunter (GitHub)         search PoC repos by keyword

  TOOLS
  [7] ExploitDB search
  [8] Metasploit search
  [9] Export last results         TXT or JSON
```

---

## Example: Exploit Chain for Log4Shell

```
╔══ EXPLOIT CHAIN — CVE-2021-44228
║
║  [CVE]       CVSS: 10.0  [CRITICAL]
║              Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
║              CWE: CWE-917 Improper Neutralization
║              Affects: apache/log4j <=2.14.1
║              Patch: PATCHED → github.com/apache/logging-log4j2/...
║
║  [EXPLOITDB]  3 exploit(s) found
║              EDB-51183 — Apache Log4j RCE (Log4Shell)
║
║  [METASPLOIT] 1 module(s) found
║              exploit/multi/misc/log4shell_header_injection
║
║  [PoC GITHUB] 4 PoC repo(s) found
║              kozmer/log4j-shell-poc  ★2341
║
╚══ VERDICT: ⚠  HIGH RISK — public exploit available
```

---

## Data Sources

| Source | API / Method |
|---|---|
| **NIST NVD** | REST API v2.0 — https://nvd.nist.gov |
| **ExploitDB** | `searchsploit` CLI (local DB) |
| **Metasploit** | `msfconsole` CLI |
| **GitHub** | REST API v3 — repository search |

---

## Ethical Use

This tool is intended for authorized penetration testing, security research, and educational purposes only. Always obtain written permission before testing any system you do not own. The author takes no responsibility for misuse.

---

## Author :  **Atrox** 


