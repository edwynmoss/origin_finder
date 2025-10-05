# Origin Finder

A powerful tool to discover origin servers behind CDN/proxy services (Cloudflare, AWS CloudFront, Akamai, Fastly) by testing direct IP access and comparing responses with Host header manipulation.

## 🎯 Features

- **Smart CDN Filtering** - Automatically filters out CDN IPs (Cloudflare, AWS, Akamai, Fastly)
- **Mass Scanning** - Test hundreds or thousands of IPs concurrently
- **IP Range Support** - Scan entire subnets with CIDR or range notation
- **Tabulated Output** - Clean, organized results display
- **CSV Export** - Save results for analysis
- **Origin Verification** - Deep verification tool to confirm origin servers
- **Multi-Protocol** - Tests both HTTP and HTTPS

## 📋 How It Works

1. **Baseline Test**: Makes a direct request to an IP without Host header manipulation
2. **Host Header Test**: Makes a request with the `Host` header set to your target domain
3. **Comparison**: Compares response sizes and identifies IPs that return different content
4. **CDN Detection**: Filters out known CDN IPs and detects CDN headers
5. **Verdict**: Only non-CDN IPs with significantly different responses are flagged as potential origins

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/edwynmoss/origin_finder.git
cd origin_finder

# Install dependencies
pip install -r requirements.txt
```

## 💻 Usage

### Basic Scanning

```bash
# Scan IPs from a file
py origin_finder_cloudflare.py --domain example.com --single-domain-set ips.txt

# Scan a single IP
py origin_finder_cloudflare.py --domain example.com --ip 192.168.1.100

# Scan multiple IPs
py origin_finder_cloudflare.py --domain example.com --ip 1.2.3.4 --ip 5.6.7.8
```

### Mass Scanning

```bash
# Scan IP range (192.168.1.1 to 192.168.1.254)
py origin_finder_cloudflare.py --domain example.com --ip-range 192.168.1.1-254

# Scan CIDR subnet
py origin_finder_cloudflare.py --domain example.com --ip-range 192.168.1.0/24

# High-speed scanning with more threads
py origin_finder_cloudflare.py --domain example.com --ip-range 10.0.0.0/24 --threads 50
```

### CSV Export

```bash
# Save results to CSV
py origin_finder_cloudflare.py --domain example.com --single-domain-set ips.txt --csv results.csv
```

### Advanced Options

```bash
# Disable CDN filtering (show all results)
py origin_finder_cloudflare.py --domain example.com --single-domain-set ips.txt --no-filter

# Increase timeout for slow servers
py origin_finder_cloudflare.py --domain example.com --single-domain-set ips.txt --timeout 10
```

### Origin Verification

Once you find potential origins, verify them:

```bash
# Verify a potential origin IP
py verify_origin.py --domain example.com --ip 192.168.1.100

# Verify with HTTP instead of HTTPS
py verify_origin.py --domain example.com --ip 192.168.1.100 --protocol http

# Verify multiple IPs
py verify_origin.py --domain example.com --ip 1.2.3.4 --ip 5.6.7.8
```

## 📊 Example Output

### Origin Finder Output

```
[*] Starting Origin Finder
[*] Target domain: example.com
[*] Testing 100 IP(s)
[*] CDN Filtering: Enabled
[*] CSV output: results.csv

-------------------------------------------------------------------------------
| IP Address      | Proto | Status | Size     | Baseline | Verdict    |
-------------------------------------------------------------------------------
| 192.168.1.100   | https | 200    |    45632 |     1234 | DIFFERENT  |
| 192.168.1.100   | http  | 200    |    45632 |     1234 | DIFFERENT  |
| 192.168.1.101   | https | None   |        0 |        0 | None       |
| 192.168.1.101   | http  | None   |        0 |        0 | None       |
-------------------------------------------------------------------------------

[*] Filtered out 15 CDN IPs (30 tests)
[*] Detected 5 IPs with CDN headers (10 tests)

[!] POTENTIAL ORIGINS FOUND (2):
-------------------------------------------------------------------------------
| IP Address      | Proto | Status | Size     | Baseline | Diff       |
-------------------------------------------------------------------------------
| 192.168.1.100   | https | 200    |    45632 |     1234 |      44398 |
| 192.168.1.100   | http  | 200    |    45632 |     1234 |      44398 |
-------------------------------------------------------------------------------
```

### Verification Output

```
================================================================================
[*] VERIFYING ORIGIN: 192.168.1.100
[*] Domain: example.com
[*] Protocol: https
================================================================================

[1] Checking SSL Certificate...
  [+] Common Name: example.com
  [+] Issuer: Let's Encrypt
  [+] Certificate matches domain!

[2] Getting legitimate response (through CDN)...
  [+] Status: 200
  [+] Content Length: 45632 bytes
  [+] Server: nginx

[3] Getting response from potential origin (192.168.1.100)...
  [+] Status: 200
  [+] Content Length: 45632 bytes
  [+] Server: nginx

[4] Comparing responses...
  Content Length Similarity: 100.0%
  Content Similarity: 98.5%
  Server Headers: nginx (Match: YES)
  CDN Detection: No CDN headers detected

================================================================================
[+++] VERDICT: LIKELY ORIGIN
================================================================================
```

## 🔍 Finding IPs to Test

### 1. Historical DNS Records
- [SecurityTrails](https://securitytrails.com/)
- [ViewDNS](https://viewdns.info/)

### 2. Certificate Transparency
- [crt.sh](https://crt.sh/)
- [Censys](https://search.censys.io/)

### 3. Subdomain Enumeration
Look for subdomains not behind CDN (FTP, mail, direct, origin, etc.)

### 4. Search Engines
- [Shodan](https://www.shodan.io/)
- [Censys](https://search.censys.io/)

## 📝 Command Line Arguments

### origin_finder_cloudflare.py

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--domain` | `-d` | Target domain name (required) | - |
| `--single-domain-set` | - | File with IP addresses to test | - |
| `--ip` | - | Single IP to test (repeatable) | - |
| `--ip-range` | - | IP range (e.g., 192.168.1.1-254) | - |
| `--timeout` | `-t` | Request timeout in seconds | 5 |
| `--threads` | - | Number of concurrent threads | 10 |
| `--csv` | `-c` | Save results to CSV file | - |
| `--no-filter` | - | Disable CDN filtering | False |

### verify_origin.py

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--domain` | `-d` | Target domain name (required) | - |
| `--ip` | `-i` | IP address to verify (repeatable) | - |
| `--protocol` | `-p` | Protocol (http/https) | https |
| `--timeout` | `-t` | Request timeout in seconds | 10 |

## 🛡️ Legal Notice

**IMPORTANT**: This tool is for authorized security testing and research purposes only.

- ✅ **Authorized Use**: Your own infrastructure, penetration testing with permission
- ❌ **Unauthorized Use**: Testing systems without explicit written permission

**Always obtain proper authorization before testing any systems.**

Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

## 🔒 Detected CDN Providers

The tool automatically detects and filters:

- **Cloudflare** (104.x.x.x, 172.64-71.x.x ranges)
- **AWS CloudFront** (13.x.x.x, 52.x.x.x, 54.x.x.x ranges)
- **Akamai** (23.x.x.x, 2.16-18.x.x ranges)
- **Fastly** (151.101.x.x, 199.232.x.x ranges)

CDN detection also checks response headers for:
- `cf-ray`, `cf-cache-status` (Cloudflare)
- `x-amz-cf-id` (AWS CloudFront)
- `x-akamai-*` (Akamai)
- Server headers containing CDN identifiers

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

The authors are not responsible for misuse of this tool. Users are responsible for ensuring they have proper authorization before conducting any security testing.

## 🔗 Links

- Repository: [https://github.com/edwynmoss/origin_finder.git](https://github.com/edwynmoss/origin_finder.git)
- Issues: Report bugs or request features

---

**Built for security professionals and researchers** 🔐
