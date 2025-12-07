#!/usr/bin/env python3
"""
OSC - Open Source Code Scanner
Fixed Version - No more parameter errors
Author : iyanji
"""

import requests
import re
import json
import os
import sys
import time
import argparse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import threading
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class EnhancedOSCScanner:
    def __init__(self, target, session_cookie=None, max_threads=10, timeout=10):  # ✅ Diubah ke 'target'
        self.target = target.rstrip('/')
        self.session_cookie = session_cookie
        self.max_threads = max_threads
        self.timeout = timeout
        self.session = requests.Session()
        self.found_sensitive_data = []
        self.visited_urls = set()
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Security headers to avoid blocking
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })
        
        # Add session cookie if provided
        if session_cookie:
            self.session.cookies.update({'session': session_cookie})
            print(f"{Fore.GREEN}[+] Session cookie loaded{Style.RESET_ALL}")
        
        # Enhanced regex patterns for sensitive data
        self.patterns = {
            'api_keys': [
                r'["\']?(api[_-]?key|apikey)["\']?\s*[=:]\s*["\']([^"\']{10,60})["\']',
                r'["\']?(api[_-]?secret|secret[_-]?key)["\']?\s*[=:]\s*["\']([^"\']{10,60})["\']',
                r'sk_(live|test)_[A-Za-z0-9]{24}',
                r'AKIA[0-9A-Z]{16}',
                r'ya29\.[0-9A-Za-z\-_]+',
                r'AIza[0-9A-Za-z\-_]{35}',
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            ],
            'tokens': [
                r'["\']?(token|access[_-]?token|auth[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{10,200})["\']',
                r'["\']?(refresh[_-]?token|bearer[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{10,200})["\']',
                r'eyJhbGciOiJ[^"\'<>]{20,500}',
                r'[\w-]+\.[\w-]+\.[\w-]+',  # JWT pattern
            ],
            'passwords': [
                r'["\']?(password|pass|pwd|passwd)["\']?\s*[=:]\s*["\']([^"\']{3,50})["\']',
                r'["\']?(db[_-]?password|database[_-]?pass)["\']?\s*[=:]\s*["\']([^"\']{3,50})["\']',
                r'["\']?(secret|passphrase)["\']?\s*[=:]\s*["\']([^"\']{3,50})["\']',
            ],
            'database': [
                r'["\']?(database[_-]?url|db[_-]?url|connection[_-]?string)["\']?\s*[=:]\s*["\']([^"\']+?)["\']',
                r'(mysql|postgresql|postgres|mongodb)://[^"\'\s]+',
                r'["\']?(host|port|dbname|database)["\']?\s*[=:]\s*["\']([^"\']+?)["\']',
            ],
            'emails': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'internal_ips': [
                r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
                r'\b(192\.168\.\d{1,3}\.\d{1,3})\b',
                r'\b(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b',
                r'\b(127\.0\.0\.1|localhost)\b',
            ],
            'config_files': [
                r'["\']?(config|configuration|settings)["\']?\s*[=:]\s*["\']([^"\']+?\.(json|yml|yaml|ini|conf|config|php|py))["\']',
                r'["\']?(env|environment)["\']?\s*[=:]\s*["\']([^"\']+?\.(env|local|production|development))["\']',
            ],
            'financial': [
                r'["\']?(stripe|paypal|braintree)_(secret|key|token)["\']?\s*[=:]\s*["\']([^"\']{10,60})["\']',
                r'["\']?(merchant[_-]?id|account[_-]?number)["\']?\s*[=:]\s*["\']([^"\']{5,30})["\']',
            ]
        }

        # Extended sensitive files list
        self.sensitive_files = [
            # Environment files
            '.env', '.env.local', '.env.production', '.env.development',
            # Configuration files
            'config.php', 'configuration.php', 'settings.php', 'wp-config.php',
            'config.json', 'settings.json', 'configuration.json',
            'config.yml', 'config.yaml', 'settings.yml', 'app.config',
            'web.config', '.htaccess', 'robots.txt',
            # Database files
            'database.yml', 'database.json', 'db.config',
            # Backup files
            '.bak', '.backup', '.old', '.tmp', '.temp', '.save',
            '.orig', '.copy', '.bk', '.back',
            # Log files
            '.log', 'logs.txt', 'error.log', 'access.log',
            # Key files
            '.pem', '.key', '.crt', '.cert', '.pfx',
            'id_rsa', 'id_dsa', 'private.key',
            # Data files
            '.sql', '.db', '.sqlite', '.mdb',
            '.dump', '.export', '.dat',
        ]

    def print_banner(self):
        banner = f"""
{Fore.RED}
  ██████  ███████  ██████
 ██    ██ ██      ██      
 ██    ██ ███████ ██      
 ██    ██      ██ ██      
  ██████  ███████  ██████
{Style.RESET_ALL}
{Fore.CYAN}OSC - Open Source Code Scanner
{Fore.YELLOW}Author : iyanji
{Style.RESET_ALL}
Target: {self.target}
Session: {'Provided' if self.session_cookie else 'Not Provided'}
Threads: {self.max_threads} | Timeout: {self.timeout}s
        """
        print(banner)

    def print_help(self):
        """Print help information"""
        help_text = f"""
{Fore.CYAN}OSC - Open Source Code Scanner{Style.RESET_ALL}
{Fore.YELLOW}Author: iyanji{Style.RESET_ALL}

{Fore.GREEN}USAGE:{Style.RESET_ALL}
    python3 osc.py [OPTIONS] TARGET_URL

{Fore.GREEN}OPTIONS:{Style.RESET_ALL}
    -s, --session SESSION    Session cookie for authenticated scanning
    -t, --threads THREADS    Number of threads (default: 10)
    --timeout TIMEOUT        Request timeout in seconds (default: 10)
    -o, --output FILE        Output file for JSON report
    -h, --help               Show this help message

{Fore.GREEN}EXAMPLES:{Style.RESET_ALL}
    {Fore.WHITE}Basic scan:{Style.RESET_ALL}
    python3 osc.py https://example.com

    {Fore.WHITE}Scan with session cookie:{Style.RESET_ALL}
    python3 osc.py -s "session_cookie_value" https://example.com

    {Fore.WHITE}Custom threads and timeout:{Style.RESET_ALL}
    python3 osc.py -t 5 --timeout 15 https://example.com

    {Fore.WHITE}Save report to file:{Style.RESET_ALL}
    python3 osc.py -o scan_report.json https://example.com

{Fore.GREEN}FEATURES:{Style.RESET_ALL}
    • API Keys & Tokens detection
    • Database credentials scanning
    • Sensitive file discovery
    • Configuration files detection
    • Email addresses and internal IPs
    • Financial data scanning
    • Multi-threaded scanning
    • JSON report generation

{Fore.RED}LEGAL DISCLAIMER:{Style.RESET_ALL}
    Use this tool only on websites you own or have explicit permission to test.
    Unauthorized scanning may be illegal in your jurisdiction.
        """
        print(help_text)

    def scan_url(self, url):
        """Scan a single URL for sensitive data"""
        try:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)
            
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                content_length = len(response.content)
                
                # Skip very large files
                if content_length > 10000000:  # 10MB
                    return
                
                # Scan text-based content
                if any(text_type in content_type for text_type in [
                    'text/html', 'application/javascript', 'text/javascript', 
                    'application/json', 'text/plain', 'application/xml'
                ]):
                    self.analyze_content(url, response.text, content_type)
                    
                # Also check for sensitive files by URL pattern
                self.check_sensitive_file_by_url(url, response)
                    
        except Exception as e:
            pass

    def analyze_content(self, url, content, content_type):
        """Analyze content for sensitive data patterns"""
        findings = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Handle different group patterns
                        if len(match.groups()) >= 2:
                            value = match.group(2)  # Get the actual value from second group
                        else:
                            value = match.group()
                            
                        if value and self.is_valid_finding(category, value, url):
                            findings.append({
                                'url': url,
                                'category': category,
                                'value': self.sanitize_value(value),
                                'pattern': pattern,
                                'content_type': content_type
                            })
                except Exception as e:
                    continue
        
        # Check for sensitive file references
        file_findings = self.find_file_references(url, content)
        findings.extend(file_findings)
        
        # Save findings
        if findings:
            with self.lock:
                self.found_sensitive_data.extend(findings)
                for finding in findings:
                    self.print_finding(finding)

    def sanitize_value(self, value):
        """Sanitize value for display"""
        if len(value) > 100:
            return value[:100] + '...'
        return value

    def is_valid_finding(self, category, value, url):
        """Validate if the finding is actually sensitive"""
        false_positives = [
            'example', 'test', 'demo', 'placeholder', 'your_', 'changeme',
            'password', 'secret', 'key', 'token',  # Common placeholder names
        ]
        
        # Skip common false positives
        if any(fp in value.lower() for fp in false_positives):
            return False
            
        # Skip image emails
        if category == 'emails' and any(ext in url.lower() for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg']):
            return False
        
        # Validate specific patterns
        if category == 'api_keys':
            if len(value) < 10:
                return False
                
        return True

    def find_file_references(self, url, content):
        """Find references to sensitive files"""
        findings = []
        
        # Look for file references in content
        for file_ext in self.sensitive_files:
            patterns = [
                rf'["\']([^"\']*{re.escape(file_ext)})["\']',
                rf'([^"\'>\s]*{re.escape(file_ext)})',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    file_path = match.group(1) if match.groups() else match.group()
                    if self.is_potential_sensitive_file(file_path):
                        findings.append({
                            'url': url,
                            'category': 'sensitive_file_reference',
                            'value': file_path,
                            'pattern': pattern,
                            'content_type': 'file_reference'
                        })
        
        return findings

    def is_potential_sensitive_file(self, file_path):
        """Check if file path looks like a sensitive file"""
        if not file_path or len(file_path) > 200:
            return False
            
        file_lower = file_path.lower()
        
        # Check for sensitive extensions
        for ext in self.sensitive_files:
            if file_lower.endswith(ext) or f'/{ext}' in file_lower:
                return True
                
        # Check for common sensitive file patterns
        sensitive_patterns = [
            'config', 'secret', 'private', 'key', 'password', 
            'database', 'backup', 'log', 'env'
        ]
        
        if any(pattern in file_lower for pattern in sensitive_patterns):
            return True
            
        return False

    def check_sensitive_file_by_url(self, url, response):
        """Check if the URL itself points to a sensitive file"""
        url_lower = url.lower()
        
        for file_pattern in self.sensitive_files:
            if file_pattern in url_lower:
                # Check if this looks like a sensitive file exposure
                content_type = response.headers.get('content-type', '').lower()
                content_length = len(response.content)
                
                # Common indicators of sensitive file exposure
                if (content_length < 1000000 and  # Reasonable size
                    any(indicator in content_type for indicator in ['text/', 'application/', 'json', 'xml']) or
                    response.text.strip().startswith(('{', '[', '<', '<?', '---', 'export'))):
                    
                    finding = {
                        'url': url,
                        'category': 'exposed_sensitive_file',
                        'value': f"Exposed {file_pattern} file ({content_length} bytes)",
                        'pattern': 'direct_access',
                        'content_type': content_type
                    }
                    
                    with self.lock:
                        self.found_sensitive_data.append(finding)
                        self.print_finding(finding)

    def discover_urls(self, base_url):
        """Discover URLs from sitemap, robots.txt, and page links"""
        urls_to_scan = set()
        
        # Extended common paths to check
        common_paths = [
            # Root and common files
            '/', '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
            '/sitemap/', '/sitemap1.xml', '/sitemap-index.xml',
            
            # Configuration files
            '/.env', '/.env.local', '/.env.production', 
            '/config.php', '/wp-config.php', '/configuration.php',
            '/config.json', '/settings.json', '/app/config.json',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/graphql', '/rest',
            '/api/users', '/api/config', '/api/settings',
            '/api/admin', '/api/auth', '/api/token',
            
            # Admin panels
            '/admin', '/administrator', '/wp-admin', '/manager',
            '/login', '/signin', '/dashboard', '/console',
            
            # Backup directories
            '/backup', '/backups', '/bak', '/old', '/temp',
            '/tmp', '/archive', '/archives',
            
            # Source code
            '/src', '/source', '/js', '/javascript', '/static',
            '/assets', '/resources', '/includes',
            
            # Documentation
            '/docs', '/documentation', '/api-docs', '/swagger',
            '/redoc', '/api.json', '/swagger.json',
            
            # Log files
            '/logs', '/log', '/error.log', '/access.log',
        ]
        
        # Add common paths with variations
        for path in common_paths:
            urls_to_scan.add(urljoin(base_url, path))
            # Also try with different cases
            urls_to_scan.add(urljoin(base_url, path.upper()))
        
        # Try to find URLs from robots.txt
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.startswith(('Allow:', 'Disallow:', 'Sitemap:')):
                        path = line.split(':')[1].strip()
                        if path and path != '/':
                            full_url = urljoin(base_url, path)
                            urls_to_scan.add(full_url)
        except:
            pass
        
        # Try to find URLs from sitemap
        try:
            sitemap_urls = [urljoin(base_url, '/sitemap.xml'), urljoin(base_url, '/sitemap_index.xml')]
            for sitemap_url in sitemap_urls:
                response = self.session.get(sitemap_url, timeout=5)
                if response.status_code == 200:
                    # Simple sitemap parsing
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for url in urls:
                        urls_to_scan.add(url)
        except:
            pass
        
        return urls_to_scan

    def print_finding(self, finding):
        """Print finding with colored output"""
        colors = {
            'api_keys': Fore.RED,
            'tokens': Fore.MAGENTA,
            'passwords': Fore.RED,
            'database': Fore.YELLOW,
            'emails': Fore.BLUE,
            'internal_ips': Fore.CYAN,
            'config_files': Fore.GREEN,
            'sensitive_file_reference': Fore.YELLOW,
            'exposed_sensitive_file': Fore.RED,
            'financial': Fore.RED,
        }
        
        color = colors.get(finding['category'], Fore.WHITE)
        category_display = finding['category'].upper().replace('_', ' ')
        
        print(f"{color}[{category_display}] {Fore.WHITE}{finding['url']}")
        print(f"     {Fore.CYAN}Data: {Fore.WHITE}{finding['value']}")
        if finding.get('content_type'):
            print(f"     {Fore.CYAN}Type: {Fore.WHITE}{finding['content_type']}")
        print()

    def print_summary_report(self):
        """Print comprehensive summary report at the end"""
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{' OSC SCAN SUMMARY REPORT ':^60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # Basic scan info
        print(f"{Fore.YELLOW}Scan Information:{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Session: {'Provided' if self.session_cookie else 'Not Provided'}")
        print(f"  URLs Scanned: {len(self.visited_urls)}")
        print(f"  Scan Duration: {round(time.time() - self.start_time, 2)} seconds")
        
        # Findings summary
        print(f"\n{Fore.YELLOW}Findings Summary:{Style.RESET_ALL}")
        print(f"  Total Findings: {len(self.found_sensitive_data)}")
        
        # Group by category
        findings_by_category = {}
        for finding in self.found_sensitive_data:
            category = finding['category']
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        # Print findings by category
        risk_colors = {
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }
        
        for category, findings in findings_by_category.items():
            risk_level = self.get_risk_level(category)
            color = risk_colors.get(risk_level, Fore.WHITE)
            category_display = category.upper().replace('_', ' ')
            print(f"  {color}{category_display}: {len(findings)} findings ({risk_level} risk){Style.RESET_ALL}")
        
        # Risk assessment
        overall_risk = self.assess_overall_risk(findings_by_category)
        risk_color = risk_colors.get(overall_risk, Fore.WHITE)
        print(f"\n{Fore.YELLOW}Overall Risk Assessment:{Style.RESET_ALL}")
        print(f"  {risk_color}{overall_risk} RISK{Style.RESET_ALL}")
        
        # Critical findings highlight
        critical_categories = ['api_keys', 'passwords', 'database', 'financial']
        critical_findings = []
        for category in critical_categories:
            if category in findings_by_category:
                critical_findings.extend(findings_by_category[category])
        
        if critical_findings:
            print(f"\n{Fore.RED}CRITICAL FINDINGS ({len(critical_findings)}):{Style.RESET_ALL}")
            for i, finding in enumerate(critical_findings[:5], 1):  # Show top 5
                print(f"  {i}. {finding['url']}")
                print(f"     Data: {finding['value']}")
            if len(critical_findings) > 5:
                print(f"  ... and {len(critical_findings) - 5} more critical findings")
        
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    def get_risk_level(self, category):
        """Get risk level for a category"""
        risk_levels = {
            'api_keys': 'HIGH',
            'passwords': 'HIGH', 
            'database': 'HIGH',
            'financial': 'HIGH',
            'tokens': 'HIGH',
            'exposed_sensitive_file': 'MEDIUM',
            'config_files': 'MEDIUM',
            'internal_ips': 'MEDIUM',
            'sensitive_file_reference': 'LOW',
            'emails': 'LOW'
        }
        return risk_levels.get(category, 'LOW')

    def assess_overall_risk(self, findings_by_category):
        """Assess overall risk based on findings"""
        risk_scores = {
            'HIGH': 0,
            'MEDIUM': 0, 
            'LOW': 0
        }
        
        for category, findings in findings_by_category.items():
            risk_level = self.get_risk_level(category)
            risk_scores[risk_level] += len(findings)
        
        if risk_scores['HIGH'] > 0:
            return 'HIGH'
        elif risk_scores['MEDIUM'] > 2:
            return 'MEDIUM'
        elif risk_scores['LOW'] > 0:
            return 'LOW'
        else:
            return 'NONE'

    def generate_report(self, output_file=None):
        """Generate comprehensive report"""
        report = {
            'scan_info': {
                'target': self.target,
                'session_provided': bool(self.session_cookie),
                'scan_duration': round(time.time() - self.start_time, 2),
                'urls_scanned': len(self.visited_urls),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'summary': {
                'total_findings': len(self.found_sensitive_data),
                'findings_by_category': {},
                'risk_assessment': self.assess_overall_risk({})
            },
            'findings': self.found_sensitive_data
        }
        
        # Group by category and count
        for finding in self.found_sensitive_data:
            category = finding['category']
            if category not in report['summary']['findings_by_category']:
                report['summary']['findings_by_category'][category] = []
            report['summary']['findings_by_category'][category].append(finding)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"{Fore.GREEN}[+] Report saved to: {output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error saving report: {e}{Style.RESET_ALL}")
        
        return report

    def run_scan(self, output_file=None):
        """Main scanning function"""
        self.print_banner()
        
        print(f"{Fore.GREEN}[*] Starting OSC Scan...{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Discovering URLs...{Style.RESET_ALL}")
        
        # Discover URLs to scan
        urls_to_scan = self.discover_urls(self.target)
        
        print(f"{Fore.GREEN}[*] Found {len(urls_to_scan)} URLs to scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Scanning for sensitive data...{Style.RESET_ALL}\n")
        
        # Scan URLs with threading
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_url, urls_to_scan)
        
        # Generate report and print summary
        report = self.generate_report(output_file)
        self.print_summary_report()
        
        return report

def main():
    parser = argparse.ArgumentParser(description='OSC - Open Source Code Scanner', add_help=False)
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-s', '--session', help='Session cookie for authenticated scanning')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    # Show help if requested or no target provided
    if args.help or not args.target:
        scanner = EnhancedOSCScanner('http://example.com')
        scanner.print_help()
        sys.exit(0)
    
    # Validate target URL
    target = args.target
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    try:
        # ✅ FIXED: Sekarang menggunakan parameter yang benar
        scanner = EnhancedOSCScanner(
            target=target,
            session_cookie=args.session,
            max_threads=args.threads,
            timeout=args.timeout
        )
        scanner.run_scan(output_file=args.output)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
