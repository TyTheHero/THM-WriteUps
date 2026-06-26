# CTF Write-Up: FutureVera — Subdomain Enumeration
 
**Target:** `futurevera.thm` / `10.66.161.252`  
**Category:** Reconnaissance / Web  
**Difficulty:** Easy  
 
---
 
## Overview
 
This challenge required enumerating subdomains of a target web server, inspecting TLS certificates for hidden information, and recognizing that a secure subdomain was also accessible over plain HTTP — where the flag was exposed in the URL.
 
---
 
## Step 1: Initial Nmap Scan
 
Started with a basic port scan to map the attack surface.
 
```bash
nmap 10.66.161.252
```
 
**Results:**
 
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```
 
Three services were running: SSH, HTTP, and HTTPS. With both web ports open, the next logical step was subdomain enumeration.
 
---
 
## Step 2: Subdomain Hint — `support.futurevera.thm`
 
The challenge hinted at the existence of subdomains. A `support` subdomain is a common entry point in CTF environments, so it was the first to investigate.
 
Added it to `/etc/hosts`:
 
```bash
echo "10.66.161.252  support.futurevera.thm" >> /etc/hosts
```
 
---
 
## Step 3: TLS Certificate Inspection
 
Rather than immediately fuzzing, the TLS certificate on port 443 was inspected for Subject Alternative Names (SANs) — a common place where additional subdomains are disclosed.
 
```bash
openssl s_client -connect 10.66.161.252:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative"
```
 
The certificate revealed an additional subdomain:
 
```
12834845support.futurevera.thm
```
 
This random-looking numeric prefix is a pattern used to obscure internal or staging subdomains — but since it appeared in the cert's SANs, it was fully enumerable without any brute-forcing.
 
---
 
## Step 4: Accessing the Hidden Subdomain
 
Added the discovered subdomain to `/etc/hosts`:
 
```bash
echo "10.66.161.252  12834845support.futurevera.thm" >> /etc/hosts
```
 
Attempting to access it over HTTPS either failed or returned nothing useful. Switching to HTTP revealed the flag directly in the URL:
 
```
http://12834845support.futurevera.thm
```
 
**Flag captured.**
 
---
 
## Key Takeaways
 
**TLS certificates leak subdomains.** SANs in self-signed or internal certificates are frequently overlooked but can expose hidden infrastructure instantly — no wordlist needed.
 
**HTTP fallback is a real attack surface.** Even when HTTPS is configured, HTTP may still be active and unprotected. Always check both protocols.
 
**Numeric prefixes aren't real security.** Obscuring a subdomain with a random number (`12834845support`) provides no protection if the name is baked into a publicly readable certificate.
 
---
 
## Tools Used
 
| Tool | Purpose |
|---|---|
| `nmap` | Port discovery |
| `openssl s_client` | TLS certificate inspection |
| `/etc/hosts` | Manual DNS resolution for `.thm` domains |
| `curl` / browser | Accessing discovered subdomains |
