
# header_check.py
class HeaderScanner:
    def __init__(self):
        self.security_headers = {
            'Content-Security-Policy': {
                'severity': 'medium',
                'description': 'Content Security Policy helps prevent XSS attacks by specifying which dynamic resources are allowed to load.'
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'description': 'X-XSS-Protection enables browser-based XSS filters.'
            },
            'X-Content-Type-Options': {
                'severity': 'low',
                'description': 'X-Content-Type-Options prevents MIME type sniffing.'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'X-Frame-Options prevents clickjacking attacks.'
            },
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security ensures secure connections to the server.'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Referrer Policy controls how much referrer information should be included with requests.'
            }
        }
    
    def scan(self, url, response):
        """Scan response headers for security issues"""
        issues = []
        headers = response.headers
        
        # Check for missing security headers
        for header, info in self.security_headers.items():
            if header not in headers:
                issues.append({
                    'title': f'Missing Security Header: {header}',
                    'description': info['description'],
                    'url': url,
                    'details': None,
                    'severity': info['severity']
                })
        
        # Check cookies for security attributes
        if 'Set-Cookie' in headers:
            cookies = response.cookies
            for cookie in cookies:
                secure_issues = []
                
                if not cookie.secure:
                    secure_issues.append('Missing Secure flag')
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    secure_issues.append('Missing HttpOnly flag')
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    secure_issues.append('Missing SameSite attribute')
                
                if secure_issues:
                    issues.append({
                        'title': 'Insecure Cookie Configuration',
                        'description': f"Cookie '{cookie.name}' has insecure settings.",
                        'url': url,
                        'details': ', '.join(secure_issues),
                        'severity': 'medium'
                    })
        
        return issues
