#!/usr/bin/env python3
"""
Origin Finder Tool - Discovers origin servers behind CDN/proxy services
Tests IPs by comparing baseline responses with Host header manipulation
"""

import argparse
import requests
import urllib3
from typing import List, Tuple, Optional
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import time

# Fix Windows console encoding issues
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """Store results from testing an IP"""
    ip: str
    protocol: str
    status_code: Optional[int]
    size: int
    baseline: int
    verdict: str
    response_time: float = 0.0


class OriginFinder:
    """Main class for finding origin servers"""
    
    def __init__(self, domain: str, timeout: int = 5, threads: int = 10, filter_cdn: bool = True, proxy: str = None):
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.filter_cdn = filter_cdn
        self.proxy = proxy
        self.baseline_size = None
        self.session = requests.Session()
        self.session.verify = False
        
        # Configure proxy if provided
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # CDN IP ranges to filter
        self.cdn_ranges = [
            # Cloudflare
            ('104.16.', '104.31.'), ('172.64.', '172.71.'), ('173.245.', '173.245.'),
            ('188.114.', '188.114.'), ('190.93.', '190.93.'), ('197.234.', '197.234.'),
            ('198.41.', '198.41.'), ('162.158.', '162.158.'), ('141.101.', '141.101.'),
            # AWS CloudFront
            ('13.', '54.'), ('52.', '99.'), ('18.', '35.'),
            # Akamai
            ('23.', '2.16.'), ('2.17.', '2.18.'),
            # Fastly
            ('151.101.', '199.232.'),
        ]
        
    def is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN ranges"""
        for range_start, range_end in self.cdn_ranges:
            if ip.startswith(range_start):
                return True
            # Check if IP is within range
            if '.' in range_end and len(range_end.split('.')) > 1:
                ip_prefix = '.'.join(ip.split('.')[:len(range_start.split('.'))])
                range_prefix = range_start
                if ip_prefix == range_prefix:
                    return True
        return False
    
    def has_cdn_headers(self, headers: dict) -> bool:
        """Check if response has CDN headers"""
        cdn_headers = {
            'cf-ray', 'cf-cache-status', 'x-cache', 'x-cdn', 
            'x-amz-cf-id', 'x-served-by', 'server'
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check for CDN-specific headers
        if any(h in headers_lower for h in ['cf-ray', 'x-amz-cf-id', 'x-akamai']):
            return True
        
        # Check Server header for CDN strings
        server = headers_lower.get('server', '')
        if any(cdn in server for cdn in ['cloudflare', 'cloudfront', 'akamai', 'fastly']):
            return True
        
        return False
    
    def get_baseline(self, ip: str, protocol: str = "https") -> Tuple[Optional[int], dict]:
        """Get baseline response size and headers from IP without Host header manipulation"""
        url = f"{protocol}://{ip}/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=False
            )
            return len(response.content), dict(response.headers)
        except Exception:
            return None, {}
    
    def test_with_host(self, ip: str, protocol: str = "https") -> Tuple[Optional[int], int, float, dict]:
        """Test IP with Host header set to target domain"""
        url = f"{protocol}://{ip}/"
        headers = {
            'Host': self.domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        start_time = time.time()
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            return response.status_code, len(response.content), response_time, dict(response.headers)
        except Exception as e:
            response_time = time.time() - start_time
            return None, 0, response_time, {}
    
    def test_ip(self, ip: str, protocols: List[str] = ["https", "http"]) -> List[TestResult]:
        """Test a single IP with both protocols"""
        results = []
        
        # Skip CDN IPs if filtering is enabled
        if self.filter_cdn and self.is_cdn_ip(ip):
            for protocol in protocols:
                result = TestResult(
                    ip=ip,
                    protocol=protocol,
                    status_code=None,
                    size=0,
                    baseline=0,
                    verdict="CDN_FILTERED",
                    response_time=0.0
                )
                results.append(result)
            return results
        
        for protocol in protocols:
            # Get baseline
            baseline_size, baseline_headers = self.get_baseline(ip, protocol)
            
            if baseline_size is None:
                baseline_size = 0
            
            # Test with Host header
            status_code, response_size, response_time, response_headers = self.test_with_host(ip, protocol)
            
            # ALWAYS check if it's CDN (regardless of filter setting)
            is_cdn = self.is_cdn_ip(ip) or self.has_cdn_headers(response_headers)
            
            # Determine verdict
            if is_cdn and self.filter_cdn:
                # If filtering enabled, mark as CDN_DETECTED (will be hidden from output)
                verdict = "CDN_DETECTED"
            elif is_cdn:
                # If filtering disabled, mark as CDN_FOUND (shown in output but not as potential origin)
                verdict = "CDN_FOUND"
            else:
                # Non-CDN IP - normal verdict
                verdict = "None"
                if baseline_size > 0 and response_size > 0:
                    if abs(baseline_size - response_size) > 100:  # Significant difference
                        verdict = "DIFFERENT"
                    else:
                        verdict = "xxxxxxxxxx"  # Same/similar response
            
            result = TestResult(
                ip=ip,
                protocol=protocol,
                status_code=status_code,
                size=response_size,
                baseline=baseline_size,
                verdict=verdict,
                response_time=response_time
            )
            
            results.append(result)
            
        return results
    
    def print_result(self, result: TestResult):
        """Print a test result in tabulated format"""
        status_str = str(result.status_code) if result.status_code else "None"
        print(f"| {result.ip:15s} | {result.protocol:5s} | {status_str:6s} | "
              f"{result.size:8d} | {result.baseline:8d} | {result.verdict:10s} |")
    
    def scan_ips(self, ip_list: List[str], csv_output: str = None):
        """Scan multiple IPs concurrently"""
        # Print table header
        print(f"\n{'-' * 79}")
        print(f"| {'IP Address':15s} | {'Proto':5s} | {'Status':6s} | "
              f"{'Size':8s} | {'Baseline':8s} | {'Verdict':10s} |")
        print(f"{'-' * 79}")
        
        all_results = []
        potential_origins = []
        cdn_filtered_count = 0
        cdn_detected_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.test_ip, ip): ip for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results = future.result()
                    for result in results:
                        all_results.append(result)
                        
                        # Skip printing CDN filtered results
                        if result.verdict == "CDN_FILTERED":
                            cdn_filtered_count += 1
                            continue
                        
                        if result.verdict == "CDN_DETECTED":
                            cdn_detected_count += 1
                            continue
                        
                        self.print_result(result)
                        
                        # ONLY add non-CDN IPs with DIFFERENT verdict to potential origins
                        # Never add CDN_FOUND to potential origins
                        if result.verdict == "DIFFERENT":
                            potential_origins.append(result)
                            
                except Exception as e:
                    print(f"| {'ERROR':15s} | {ip:5s} | {str(e)[:40]:6s} |")
        
        print(f"{'-' * 79}\n")
        
        # Print filtering stats
        if self.filter_cdn:
            print(f"[*] Filtered out {cdn_filtered_count // 2} CDN IPs ({cdn_filtered_count} tests)")
            print(f"[*] Detected {cdn_detected_count // 2} IPs with CDN headers ({cdn_detected_count} tests)\n")
        
        # Summary
        if potential_origins:
            print(f"\n[!] POTENTIAL ORIGINS FOUND ({len(potential_origins)}):")
            print(f"{'-' * 79}")
            print(f"| {'IP Address':15s} | {'Proto':5s} | {'Status':6s} | "
                  f"{'Size':8s} | {'Baseline':8s} | {'Diff':10s} |")
            print(f"{'-' * 79}")
            for result in potential_origins:
                diff = abs(result.size - result.baseline)
                print(f"| {result.ip:15s} | {result.protocol:5s} | "
                      f"{str(result.status_code) if result.status_code else 'None':6s} | "
                      f"{result.size:8d} | {result.baseline:8d} | {diff:10d} |")
            print(f"{'-' * 79}\n")
        
        # CSV output
        if csv_output:
            self._write_csv(all_results, csv_output)
            print(f"[*] Results saved to: {csv_output}")
        
        return all_results
    
    def _write_csv(self, results: List[TestResult], filename: str):
        """Write results to CSV file"""
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Protocol', 'Status', 'Size', 'Baseline', 'Verdict', 'ResponseTime'])
            for result in results:
                writer.writerow([
                    result.ip,
                    result.protocol,
                    result.status_code or 'None',
                    result.size,
                    result.baseline,
                    result.verdict,
                    f"{result.response_time:.3f}"
                ])


def load_ips_from_file(filepath: str) -> List[str]:
    """Load IP addresses from a file"""
    try:
        with open(filepath, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return ips
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)


def parse_ip_range(ip_range: str) -> List[str]:
    """Parse IP range (e.g., 192.168.1.1-192.168.1.254 or 192.168.1.0/24)"""
    ips = []
    
    try:
        # Handle CIDR notation (e.g., 192.168.1.0/24)
        if '/' in ip_range:
            import ipaddress
            network = ipaddress.ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        
        # Handle range notation (e.g., 192.168.1.1-192.168.1.254)
        elif '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start_parts = start_ip.strip().split('.')
            end_parts = end_ip.strip().split('.')
            
            # If end_ip is just a number, use start IP's prefix
            if len(end_parts) == 1:
                end_parts = start_parts[:3] + end_parts
            
            start_num = int(start_parts[3])
            end_num = int(end_parts[3])
            base = '.'.join(start_parts[:3])
            
            for i in range(start_num, end_num + 1):
                ips.append(f"{base}.{i}")
        else:
            print(f"Error: Invalid IP range format: {ip_range}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error parsing IP range: {e}")
        sys.exit(1)
    
    return ips


def main():
    parser = argparse.ArgumentParser(
        description='Origin Finder - Discover origin servers behind CDN/proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --domain example.com --single-domain-set ips.txt
  %(prog)s --domain example.com --ip 1.2.3.4
  %(prog)s --domain example.com --ip 1.2.3.4 --ip 5.6.7.8
        """
    )
    
    parser.add_argument(
        '--domain', '-d',
        required=True,
        help='Target domain name (e.g., example.com)'
    )
    
    parser.add_argument(
        '--single-domain-set',
        help='File containing list of IP addresses to test'
    )
    
    parser.add_argument(
        '--ip',
        action='append',
        help='Single IP address to test (can be used multiple times)'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=5,
        help='Request timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '--csv', '-c',
        help='Save results to CSV file'
    )
    
    parser.add_argument(
        '--ip-range',
        help='IP range to scan (e.g., 192.168.1.1-192.168.1.254)'
    )
    
    parser.add_argument(
        '--no-filter',
        action='store_true',
        help='Disable CDN filtering (show all IPs including CDN)'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)'
    )
    
    args = parser.parse_args()
    
    # Collect IPs from various sources
    ip_list = []
    
    if args.single_domain_set:
        ip_list.extend(load_ips_from_file(args.single_domain_set))
    
    if args.ip:
        ip_list.extend(args.ip)
    
    if args.ip_range:
        ip_list.extend(parse_ip_range(args.ip_range))
    
    if not ip_list:
        print("Error: No IPs provided. Use --single-domain-set, --ip, or --ip-range")
        sys.exit(1)
    
    print(f"\n[*] Starting Origin Finder")
    print(f"[*] Target domain: {args.domain}")
    print(f"[*] Testing {len(ip_list)} IP(s)")
    print(f"[*] Timeout: {args.timeout}s | Threads: {args.threads}")
    print(f"[*] CDN Filtering: {'Disabled' if args.no_filter else 'Enabled'}")
    if args.proxy:
        print(f"[*] Proxy: {args.proxy}")
    if args.csv:
        print(f"[*] CSV output: {args.csv}")
    
    finder = OriginFinder(args.domain, timeout=args.timeout, threads=args.threads, 
                         filter_cdn=not args.no_filter, proxy=args.proxy)
    finder.scan_ips(ip_list, csv_output=args.csv)
    
    print("\n[*] Scan complete")


if __name__ == "__main__":
    main()

