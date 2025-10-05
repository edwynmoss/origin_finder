#!/usr/bin/env python3
"""
Origin Verification Tool - Confirms if an IP is the actual origin server
Compares responses between direct IP access and normal domain access
"""

import argparse
import requests
import urllib3
from difflib import unified_diff
import json
from typing import Dict, Any
import ssl
import socket
import sys

# Fix Windows console encoding issues
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OriginVerifier:
    """Verify if an IP is the actual origin server"""
    
    def __init__(self, domain: str, timeout: int = 10, proxy: str = None):
        self.domain = domain
        self.timeout = timeout
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        
        # Configure proxy if provided
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
    def get_legitimate_response(self, protocol: str = "https") -> Dict[str, Any]:
        """Get the legitimate response from the domain (through CDN)"""
        url = f"{protocol}://{self.domain}/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'cookies': dict(response.cookies),
                'url': response.url,
                'success': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_origin_response(self, ip: str, protocol: str = "https") -> Dict[str, Any]:
        """Get response from potential origin IP with Host header"""
        url = f"{protocol}://{ip}/"
        headers = {
            'Host': self.domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=True
            )
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'cookies': dict(response.cookies),
                'url': response.url,
                'success': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_ssl_cert_info(self, ip: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information from an IP"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract relevant info
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    san = cert.get('subjectAltName', [])
                    
                    return {
                        'success': True,
                        'common_name': subject.get('commonName', 'N/A'),
                        'issuer': issuer.get('organizationName', 'N/A'),
                        'san': [name[1] for name in san if name[0] == 'DNS'],
                        'not_before': cert.get('notBefore', 'N/A'),
                        'not_after': cert.get('notAfter', 'N/A')
                    }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def compare_responses(self, legitimate: Dict, origin: Dict) -> Dict[str, Any]:
        """Compare two responses and provide similarity analysis"""
        if not legitimate['success'] or not origin['success']:
            return {
                'error': 'One or both requests failed'
            }
        
        # Status code comparison
        status_match = legitimate['status_code'] == origin['status_code']
        
        # Content length comparison
        len_diff = abs(legitimate['content_length'] - origin['content_length'])
        len_similarity = 100 - (len_diff / max(legitimate['content_length'], 1) * 100)
        
        # Content similarity (basic)
        legit_lines = legitimate['content'].splitlines()
        origin_lines = origin['content'].splitlines()
        
        # Calculate simple similarity
        matching_lines = sum(1 for l, o in zip(legit_lines, origin_lines) if l == o)
        total_lines = max(len(legit_lines), len(origin_lines))
        content_similarity = (matching_lines / max(total_lines, 1)) * 100
        
        # Server header comparison
        legit_server = legitimate['headers'].get('Server', 'Unknown')
        origin_server = origin['headers'].get('Server', 'Unknown')
        
        # Check for CDN headers
        cdn_headers = ['cf-ray', 'x-cache', 'x-cdn', 'x-amz-cf-id', 'x-served-by']
        legit_has_cdn = any(h in [k.lower() for k in legitimate['headers'].keys()] for h in cdn_headers)
        origin_has_cdn = any(h in [k.lower() for k in origin['headers'].keys()] for h in cdn_headers)
        
        return {
            'status_code_match': status_match,
            'status_codes': {
                'legitimate': legitimate['status_code'],
                'origin': origin['status_code']
            },
            'content_length': {
                'legitimate': legitimate['content_length'],
                'origin': origin['content_length'],
                'difference': len_diff,
                'similarity_pct': round(len_similarity, 2)
            },
            'content_similarity_pct': round(content_similarity, 2),
            'server_headers': {
                'legitimate': legit_server,
                'origin': origin_server,
                'match': legit_server == origin_server
            },
            'cdn_detection': {
                'legitimate_has_cdn_headers': legit_has_cdn,
                'origin_has_cdn_headers': origin_has_cdn
            },
            'verdict': self._determine_verdict(
                status_match, 
                len_similarity, 
                content_similarity,
                legit_has_cdn,
                origin_has_cdn
            )
        }
    
    def _determine_verdict(self, status_match: bool, len_sim: float, 
                          content_sim: float, legit_cdn: bool, origin_cdn: bool) -> str:
        """Determine if the IP is likely the origin"""
        score = 0
        
        if status_match:
            score += 20
        if len_sim > 95:
            score += 30
        if content_sim > 90:
            score += 30
        if legit_cdn and not origin_cdn:  # Legitimate has CDN but origin doesn't
            score += 20
        
        if score >= 80:
            return "LIKELY ORIGIN"
        elif score >= 50:
            return "POSSIBLE ORIGIN"
        else:
            return "UNLIKELY ORIGIN"
    
    def verify(self, ip: str, protocol: str = "https") -> None:
        """Perform full verification of a potential origin IP"""
        print(f"\n{'='*80}")
        print(f"[*] VERIFYING ORIGIN: {ip}")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] Protocol: {protocol}")
        print(f"{'='*80}\n")
        
        # Step 1: Get SSL Certificate Info
        print("[1] Checking SSL Certificate...")
        if protocol == "https":
            cert_info = self.get_ssl_cert_info(ip)
            if cert_info['success']:
                print(f"  [+] Common Name: {cert_info['common_name']}")
                print(f"  [+] Issuer: {cert_info['issuer']}")
                print(f"  [+] SAN: {', '.join(cert_info['san'][:3])}{'...' if len(cert_info['san']) > 3 else ''}")
                
                # Check if domain is in certificate
                domain_in_cert = (
                    self.domain in cert_info['san'] or 
                    cert_info['common_name'] == self.domain or
                    cert_info['common_name'] == f"*.{'.'.join(self.domain.split('.')[1:])}"
                )
                if domain_in_cert:
                    print(f"  [+] Certificate matches domain!")
                else:
                    print(f"  [!] Certificate does NOT match domain")
            else:
                print(f"  [-] Error: {cert_info['error']}")
        else:
            print("  [-] Skipped (HTTP protocol)")
        
        # Step 2: Get legitimate response
        print("\n[2] Getting legitimate response (through CDN)...")
        legit_response = self.get_legitimate_response(protocol)
        if legit_response['success']:
            print(f"  [+] Status: {legit_response['status_code']}")
            print(f"  [+] Content Length: {legit_response['content_length']} bytes")
            print(f"  [+] Server: {legit_response['headers'].get('Server', 'N/A')}")
        else:
            print(f"  [-] Error: {legit_response['error']}")
            return
        
        # Step 3: Get origin response
        print(f"\n[3] Getting response from potential origin ({ip})...")
        origin_response = self.get_origin_response(ip, protocol)
        if origin_response['success']:
            print(f"  [+] Status: {origin_response['status_code']}")
            print(f"  [+] Content Length: {origin_response['content_length']} bytes")
            print(f"  [+] Server: {origin_response['headers'].get('Server', 'N/A')}")
        else:
            print(f"  [-] Error: {origin_response['error']}")
            return
        
        # Step 4: Compare responses
        print("\n[4] Comparing responses...")
        comparison = self.compare_responses(legit_response, origin_response)
        
        print(f"\n  Status Code Match: {'YES' if comparison['status_code_match'] else 'NO'}")
        print(f"    Legitimate: {comparison['status_codes']['legitimate']}")
        print(f"    Origin: {comparison['status_codes']['origin']}")
        
        print(f"\n  Content Length Similarity: {comparison['content_length']['similarity_pct']}%")
        print(f"    Legitimate: {comparison['content_length']['legitimate']} bytes")
        print(f"    Origin: {comparison['content_length']['origin']} bytes")
        print(f"    Difference: {comparison['content_length']['difference']} bytes")
        
        print(f"\n  Content Similarity: {comparison['content_similarity_pct']}%")
        
        print(f"\n  Server Headers:")
        print(f"    Legitimate: {comparison['server_headers']['legitimate']}")
        print(f"    Origin: {comparison['server_headers']['origin']}")
        print(f"    Match: {'YES' if comparison['server_headers']['match'] else 'NO'}")
        
        print(f"\n  CDN Detection:")
        print(f"    Legitimate has CDN headers: {'Yes' if comparison['cdn_detection']['legitimate_has_cdn_headers'] else 'No'}")
        print(f"    Origin has CDN headers: {'Yes' if comparison['cdn_detection']['origin_has_cdn_headers'] else 'No'}")
        
        # Final verdict
        verdict = comparison['verdict']
        verdict_symbols = {
            'LIKELY ORIGIN': '[+++]',
            'POSSIBLE ORIGIN': '[+/-]',
            'UNLIKELY ORIGIN': '[---]'
        }
        
        print(f"\n{'='*80}")
        print(f"{verdict_symbols.get(verdict, '[?]')} VERDICT: {verdict}")
        print(f"{'='*80}\n")
        
        # Additional recommendations
        if verdict == "LIKELY ORIGIN":
            print("[*] Recommendations:")
            print("  - This IP is likely the actual origin server")
            print("  - Verify by checking unique content or server behavior")
            print("  - Test other endpoints (/admin, /api, etc.)")
        elif verdict == "POSSIBLE ORIGIN":
            print("[*] Recommendations:")
            print("  - Needs more investigation")
            print("  - Try different protocols (HTTP vs HTTPS)")
            print("  - Check for unique endpoints or parameters")
        else:
            print("[*] Recommendations:")
            print("  - This IP may not be the origin")
            print("  - Could be another CDN edge or proxy")
            print("  - Try other potential IPs")


def main():
    parser = argparse.ArgumentParser(
        description='Verify if an IP is the actual origin server behind a CDN',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --domain example.com --ip 1.2.3.4
  %(prog)s --domain example.com --ip 1.2.3.4 --protocol http
  %(prog)s -d example.com -i 1.2.3.4 -i 5.6.7.8
        """
    )
    
    parser.add_argument(
        '--domain', '-d',
        required=True,
        help='Target domain name (e.g., example.com)'
    )
    
    parser.add_argument(
        '--ip', '-i',
        action='append',
        required=True,
        help='IP address to verify (can be used multiple times)'
    )
    
    parser.add_argument(
        '--protocol', '-p',
        choices=['http', 'https'],
        default='https',
        help='Protocol to use (default: https)'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)'
    )
    
    args = parser.parse_args()
    
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}\n")
    
    verifier = OriginVerifier(args.domain, timeout=args.timeout, proxy=args.proxy)
    
    for ip in args.ip:
        verifier.verify(ip, protocol=args.protocol)
        if len(args.ip) > 1:
            print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()

