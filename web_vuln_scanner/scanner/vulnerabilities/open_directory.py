
# open_directory.py
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class DirectoryScanner:
    def __init__(self, session):
        self.session = session
        self.common_directories = [
            'admin/', 'backup/', 'config/', 'db/', 'logs/',
            'test/', 'tmp/', 'upload/', 'private/', 'includes/',
            '.git/', '.svn/', '.env'
        ]
    
    def scan(self, url):
        """Scan for open directories and sensitive files"""
        issues = []
        base_url = url.rstrip('/') + '/'
        
        for directory in self.common_directories:
            test_url = urljoin(base_url, directory)
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check if directory listing is enabled
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for typical directory listing patterns
                    if re.search(r'Index of /', response.text) or \
                       (soup.find('title') and 'Index of' in soup.find('title').text) or \
                       len(soup.find_all('a', href=re.compile(r'\.\./|\./|/$'))) > 3:
                        
                        severity = 'high' if directory in ['admin/', 'config/', 'backup/', '.git/', '.svn/', '.env'] else 'medium'
                        
                        issues.append({
                            'title': 'Directory Listing Enabled',
                            'description': f'Directory listing is enabled for {directory}, potentially exposing sensitive files.',
                            'url': test_url,
                            'details': None,
                            'severity': severity
                        })
                        
                        # Check for sensitive files in the directory listing
                        links = soup.find_all('a', href=True)
                        sensitive_files = ['config.php', 'database.sql', 'backup.zip', 'users.csv', 
                                          'password.txt', '.env', 'credentials.json', 'wp-config.php']
                        
                        for link in links:
                            href = link['href']
                            if any(sf in href for sf in sensitive_files):
                                issues.append({
                                    'title': 'Sensitive File Exposed',
                                    'description': f'A potentially sensitive file was found in an open directory.',
                                    'url': urljoin(test_url, href),
                                    'details': f'File: {href}',
                                    'severity': 'high'
                                })
            
            except Exception as e:
                print(f"Error checking directory {test_url}: {str(e)}")
        
        return issues