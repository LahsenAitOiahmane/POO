# xss.py
import re
from bs4 import BeautifulSoup
from urllib.parse import parse_qs, urlparse

class XSSScanner:
    def __init__(self, session):
        self.session = session
        self.payloads = [
            "<script>alert('XSS')</script>",
            "1<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
    
    def scan_form(self, form):
        """Scan a form for XSS vulnerabilities"""
        issues = []
        form_url = form['url']
        form_action = form['action']
        form_method = form['method']
        inputs = form['inputs']
        
        for payload in self.payloads:
            # Prepare form data with the payload
            data = {}
            for input_field in inputs:
                if input_field['type'] not in ['submit', 'image', 'button', 'hidden']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value']
            
            try:
                # Submit the form
                if form_method == 'post':
                    response = self.session.post(form_action, data=data, timeout=10)
                else:
                    response = self.session.get(form_action, params=data, timeout=10)
                
                # Check if payload is reflected in the response
                if payload in response.text:
                    # Check if payload is properly encoded/escaped
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for unescaped script tags or event handlers
                    if re.search(f'<script.*?>.*?{re.escape(payload.replace("<script>", "").replace("</script>", ""))}.*?</script>', response.text, re.IGNORECASE | re.DOTALL) or \
                       re.search(f'on\\w+\\s*=\\s*["\'][^"\']*{re.escape(payload)}[^"\']*["\']', response.text, re.IGNORECASE):
                        
                        # This is likely a real XSS vulnerability
                        issues.append({
                            'title': 'Cross-Site Scripting (XSS) Vulnerability',
                            'description': f'A potential XSS vulnerability was found in a form on the page.',
                            'url': form_url,
                            'details': f'Form action: {form_action}\nMethod: {form_method}\nPayload: {payload}',
                            'severity': 'high'
                        })
            
            except Exception as e:
                print(f"Error testing XSS on {form_action}: {str(e)}")
        
        return issues
