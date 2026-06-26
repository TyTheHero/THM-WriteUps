# CTF Write-Up: FutureVera — Subdomain Enumeration

**Target:** `futurevera.thm` / `10.66.161.252`  
**Category:** Reconnaissance / Web  
**Difficulty:** Easy  


---

## Step 1: Initial Nmap Scan

```bash
nmap 10.66.161.252
```

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Three services exposed. With both HTTP and HTTPS open, subdomain enumeration was the next step.

---

## Step 2: Visiting support.futurevera.thm

Added `support.futurevera.thm` to `/etc/hosts` and visited it over HTTPS. The page showed a simple under-construction placeholder — but the real value was the TLS certificate it was serving.

<img width="1189" height="885" alt="image" src="https://github.com/user-attachments/assets/9d0b91bb-3a69-4f29-a83e-f78e2f9d4d9e" />

---

## Step 3: TLS Certificate Inspection — SAN Leak

Inspected the certificate on `support.futurevera.thm` for Subject Alternative Names (SANs):

```bash
openssl s_client -connect 10.66.161.252:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative"
```

The SAN field disclosed a hidden subdomain: `secrethelpdesk934752.support.futurevera.thm`

<img width="1191" height="859" alt="image" src="https://github.com/user-attachments/assets/2ea02b27-a38d-42ef-afd3-733daba66093" />



The numeric prefix is meant to obscure the subdomain — but embedding it in a publicly readable certificate completely defeats that purpose.

---

## Step 4: Accessing the Hidden Subdomain over HTTP

Added the discovered subdomain to `/etc/hosts` and accessed it. HTTPS failed, but switching to **HTTP** triggered a redirect to an AWS S3 URL with the flag in the hostname.
<img width="1191" height="840" alt="image" src="https://github.com/user-attachments/assets/fbe75785-ce66-4684-a2dc-72574237e635" />



```
```

---

## Key Takeaways

- **TLS certs leak subdomains** — always check SANs before brute-forcing
- **HTTP ≠ HTTPS** — always probe both protocols even when HTTPS is configured
- **Numeric prefixes aren't security** — obscuring a name means nothing if it's in the cert
- **Redirects can expose data** — the misconfiguration itself was the vulnerability
