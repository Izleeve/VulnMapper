# VulnMapper

VulnMapper is an automated security reconnaissance tool that performs aggressive network scanning using Nmap, identifies open ports and services, and searches for known exploits using SearchSploit.

## Features
- Performs aggressive scanning (`-T4 -A -sV --version-intensity 9 --script=version -Pn`)
- Identifies open ports, services, and versions
- Searches for known exploits using `searchsploit`
- Generates a scan report

## Prerequisites
Ensure you have the following installed:
- **Python 3.x**
- **Nmap** (`sudo apt install nmap`)
- **SearchSploit** (part of ExploitDB, install via `sudo apt install exploitdb`)

## Installation
```bash
git clone https://github.com/Izleeve/VulnMapper.git
cd VulnMapper
pip install python-nmap
```
## Usage
Run the script and follow the prompts:

```bash
python3 vulnmapper.py
```
- Enter the target IP or domain.
- Select an open port from the scan results.
- The tool will search for exploits related to the service and version.
- A scan report will be generated (scan_report.txt).

### Example Output
```bash
Performing aggressive scan on *Target IP*
Results for *Target IP*:
Port 80 (http) - Version: Apache 2.4.29 - State: open
Port 22 (ssh) - Version: OpenSSH 7.6p1 - State: open

Select an open port from [80, 22] to list vulnerabilities: 80

Exploits found for Apache 2.4.29:
----------------------------------------
Exploit Title                                        | Path
----------------------------------------------------|------------------
Apache HTTPD 2.4.29 mod_session_cookie Remote Code  | exploits/...
...

Scan completed! Report saved as scan_report.txt
```
## Contributions
Pull requests and feature suggestions are welcome!
