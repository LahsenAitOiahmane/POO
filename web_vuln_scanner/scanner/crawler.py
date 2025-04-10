# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time
import re
import random
from requests.exceptions import RequestException, Timeout, TooManyRedirects

class WebCrawler:
    def __init__(self, base_url, max_pages=20, depth=3, respect_robots=True, delay=0.5):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.urls_to_visit = [(base_url, 0)]  # (url, depth)
        self.forms = []
        self.max_pages = max_pages
        self.max_depth = depth
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        # Paths/patterns to exclude (common admin paths, etc.)
        self.exclude_patterns = [
            r'/logout',
            r'/signout',
            r'/admin',
            r'/wp-admin',
            r'\?random=',
            r'\?timestamp=',
        ]
        
        # Respect robots.txt if requested
        self.disallowed_paths = []
        if respect_robots:
            self._parse_robots_txt()
    
    def _parse_robots_txt(self):
        """Parse robots.txt file to respect disallowed paths"""
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
        except Exception as e:
            print(f"Error parsing robots.txt: {str(e)}")
    
    def is_allowed(self, url):
        """Check if URL is allowed to be crawled"""
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # Check if URL path matches any disallowed paths from robots.txt
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        
        # Check if URL matches any exclude patterns
        for pattern in self.exclude_patterns:
            if re.search(pattern, url):
                return False
        
        return True
    
    def normalize_url(self, url):
        """Normalize URL to avoid duplicates"""
        parsed = urlparse(url)
        # Remove common tracking parameters
        if parsed.query:
            query_params = parsed.query.split('&')
            filtered_params = []
            for param in query_params:
                if not param.startswith(('utm_', 'ref_', 'source=')):
                    filtered_params.append(param)
            
            new_query = '&'.join(filtered_params)
            url = parsed._replace(query=new_query).geturl()
        
        # Remove trailing slash for consistency
        if url.endswith('/') and parsed.query == '':
            url = url[:-1]
        
        return url
    
    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.base_domain
    
    def extract_links(self, soup, current_url):
        """Extract links from the page"""
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip anchor links and javascript URLs
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            
            # Get absolute URL
            absolute_url = urljoin(current_url, href)
            
            # Normalize URL to avoid duplicates
            normalized_url = self.normalize_url(absolute_url)
            
            # Only add if it's the same domain and allowed
            if self.is_same_domain(normalized_url) and self.is_allowed(normalized_url):
                links.add(normalized_url)
        
        return links
    
    def extract_forms(self, soup, page_url):
        """Extract forms from the page"""
        page_forms = []
        
        for form in soup.find_all('form'):
            form_action = form.get('action', '')
            if form_action:
                form_action = urljoin(page_url, form_action)
            else:
                form_action = page_url
                
            form_method = form.get('method', 'get').lower()
            form_id = form.get('id', '')
            form_name = form.get('name', '')
            
            inputs = []
            
            # Get all input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', 'text')
                input_name = input_field.get('name', '')
                input_value = input_field.get('value', '')
                input_id = input_field.get('id', '')
                input_required = input_field.has_attr('required')
                
                if input_name:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value,
                        'id': input_id,
                        'required': input_required
                    })
            
            # Add form to list if it has inputs
            if inputs:
                page_forms.append({
                    'url': page_url,
                    'action': form_action,
                    'method': form_method,
                    'id': form_id,
                    'name': form_name,
                    'inputs': inputs
                })
        
        return page_forms
    
    def crawl(self):
        """Start crawling the website"""
        pages_visited = 0
        start_time = time.time()
        
        print(f"Starting crawler on {self.base_url}")
        
        while self.urls_to_visit and pages_visited < self.max_pages:
            # Get the next URL and its depth from the queue
            current_url, depth = self.urls_to_visit.pop(0)
            
            # Skip if already visited or max depth reached
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            try:
                # Add a small delay to be polite
                time.sleep(self.delay * (1 + random.random()))
                
                # Send request
                response = self.session.get(current_url, timeout=10)
                
                # Skip non-HTML responses
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type:
                    continue
                
                # Mark as visited
                self.visited_urls.add(current_url)
                pages_visited += 1
                
                print(f"Crawling {pages_visited}/{self.max_pages}: {current_url}")
                
                # Parse page
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                page_forms = self.extract_forms(soup, current_url)
                self.forms.extend(page_forms)
                
                # Extract links for next level
                if depth < self.max_depth:
                    links = self.extract_links(soup, current_url)
                    
                    # Add new links to the queue
                    for link in links:
                        if link not in self.visited_urls and (link, depth + 1) not in self.urls_to_visit:
                            self.urls_to_visit.append((link, depth + 1))
            
            except Timeout:
                print(f"Timeout while requesting {current_url}")
            except TooManyRedirects:
                print(f"Too many redirects for {current_url}")
            except RequestException as e:
                print(f"Error crawling {current_url}: {str(e)}")
            except Exception as e:
                print(f"Unexpected error crawling {current_url}: {str(e)}")
        
        crawl_time = time.time() - start_time
        print(f"Crawling completed: {pages_visited} pages visited in {crawl_time:.2f} seconds")
        print(f"Found {len(self.forms)} forms")
        
        return {
            'visited_urls': list(self.visited_urls),
            'forms': self.forms,
            'crawl_stats': {
                'pages_visited': pages_visited,
                'forms_found': len(self.forms),
                'crawl_time': crawl_time
            }
        }