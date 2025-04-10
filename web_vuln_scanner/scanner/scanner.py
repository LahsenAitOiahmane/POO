# scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from .vulnerabilities.xss import XSSScanner
from .vulnerabilities.sql_injection import SQLInjectionScanner
from .vulnerabilities.csrf import CSRFScanner
from .vulnerabilities.header_check import HeaderScanner
from .vulnerabilities.open_directory import DirectoryScanner

class Scanner:
    def __init__(self, target_url, max_pages=10, threads=4):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.urls_to_visit = [target_url]
        self.forms_found = []
        self.max_pages = max_pages
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        })
        
        # Initialize scanners
        self.xss_scanner = XSSScanner(self.session)
        self.sqli_scanner = SQLInjectionScanner(self.session)
        self.csrf_scanner = CSRFScanner(self.session)
        self.header_scanner = HeaderScanner()
        self.directory_scanner = DirectoryScanner(self.session)
        
        # Results container
        self.results = {
            'target_url': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'vulnerabilities': {
                'xss': [],
                'sql_injection': [],
                'csrf': [],
                'headers': [],
                'open_directories': []
            }
        }
    
    def is_same_domain(self, url):
        """Check if URL belongs to the same domain as target"""
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.base_domain
    
    def crawl(self):
        """Crawl the website and collect pages and forms"""
        pages_visited = 0
        
        while self.urls_to_visit and pages_visited < self.max_pages:
            url = self.urls_to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
                
            try:
                response = self.session.get(url, timeout=10)
                self.visited_urls.add(url)
                pages_visited += 1
                
                # Check headers for the current page
                header_issues = self.header_scanner.scan(url, response)
                self.results['vulnerabilities']['headers'].extend(header_issues)
                
                # Count issues by severity
                for issue in header_issues:
                    self.results['summary'][issue['severity']] += 1
                
                # Parse the page
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    if form_action:
                        form_action = urljoin(url, form_action)
                    else:
                        form_action = url
                        
                    form_method = form.get('method', 'get').lower()
                    inputs = []
                    
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        input_type = input_field.get('type', 'text')
                        input_name = input_field.get('name', '')
                        input_value = input_field.get('value', '')
                        
                        if input_name:
                            inputs.append({
                                'type': input_type,
                                'name': input_name,
                                'value': input_value
                            })
                    
                    self.forms_found.append({
                        'url': url,
                        'action': form_action,
                        'method': form_method,
                        'inputs': inputs
                    })
                
                # Extract links for further crawling
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    full_url = urljoin(url, href)
                    
                    # Only follow links to the same domain
                    if self.is_same_domain(full_url) and full_url not in self.visited_urls and full_url not in self.urls_to_visit:
                        self.urls_to_visit.append(full_url)
            
            except Exception as e:
                print(f"Error crawling {url}: {str(e)}")
        
        return self.visited_urls, self.forms_found
    
    def scan_vulnerabilities(self):
        """Run vulnerability scanners on collected data"""
        # Scan for XSS vulnerabilities
        for form in self.forms_found:
            xss_issues = self.xss_scanner.scan_form(form)
            self.results['vulnerabilities']['xss'].extend(xss_issues)
            
            # Count XSS issues by severity
            for issue in xss_issues:
                self.results['summary'][issue['severity']] += 1
            
            # Scan for SQL injection vulnerabilities
            sql_issues = self.sqli_scanner.scan_form(form)
            self.results['vulnerabilities']['sql_injection'].extend(sql_issues)
            
            # Count SQL issues by severity
            for issue in sql_issues:
                self.results['summary'][issue['severity']] += 1
            
            # Scan for CSRF vulnerabilities
            csrf_issues = self.csrf_scanner.scan_form(form)
            self.results['vulnerabilities']['csrf'].extend(csrf_issues)
            
            # Count CSRF issues by severity
            for issue in csrf_issues:
                self.results['summary'][issue['severity']] += 1
        
        # Scan for open directories
        for url in self.visited_urls:
            directory_issues = self.directory_scanner.scan(url)
            self.results['vulnerabilities']['open_directories'].extend(directory_issues)
            
            # Count directory issues by severity
            for issue in directory_issues:
                self.results['summary'][issue['severity']] += 1
    
    def start_scan(self):
        """Start the complete scanning process"""
        print(f"Starting scan of {self.target_url}")
        
        # Step 1: Crawl the website
        print("Crawling website...")
        self.crawl()
        print(f"Crawled {len(self.visited_urls)} pages and found {len(self.forms_found)} forms")
        
        # Step 2: Scan for vulnerabilities
        print("Scanning for vulnerabilities...")
        self.scan_vulnerabilities()
        print("Vulnerability scan complete")
        
        # Prepare the results for display
        for category in self.results['vulnerabilities']:
            for issue in self.results['vulnerabilities'][category]:
                # Add a severity class for bootstrap alerts
                if issue['severity'] == 'high':
                    issue['severity_class'] = 'danger'
                elif issue['severity'] == 'medium':
                    issue['severity_class'] = 'warning'
                elif issue['severity'] == 'low':
                    issue['severity_class'] = 'info'
                else:
                    issue['severity_class'] = 'secondary'
        
        return self.results