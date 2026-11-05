# Reconnaissance: Scanning and Content Discovery

Before attacking, adversaries map the target. MITRE ATT&CK: T1595 Active Scanning and T1595.003 Wordlist Scanning.

## Indicators

- Many requests for paths that do not exist (a high number of distinct 404s from one IP).
- Probes for well-known sensitive locations: `/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin`, `/server-status`, `/.aws/credentials`, backup files.
- Scanner user agents: Nikto, sqlmap, Nmap scripting engine, masscan, zgrab, gobuster, ffuf, nuclei, WPScan.
- Requests at a steady, machine-like rate across alphabetically ordered paths.

## Response

Scanning alone is usually low-to-medium severity, but it often precedes an exploitation attempt from the same IP or subnet. Correlate the scanner IP with injection or traversal alerts. Block or tarpit persistent scanners, and confirm that every path they found with a 200 response is meant to be public.

## Prevention

Do not deploy `.git` directories, `.env` files or backups to the web root. Return the same 404 for every missing resource so responses do not leak structure. Rate-limit clients that generate many 404s.
