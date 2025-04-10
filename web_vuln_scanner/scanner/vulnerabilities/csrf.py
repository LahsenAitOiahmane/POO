
# csrf.py
import re
from bs4 import BeautifulSoup

class CSRFScanner:
    def __init__(self, session):
        self.session = session
    
    def scan_form(self, form):
        """Scan a form for CSRF vulnerabilities"""
        issues = []
        form_url = form['url']
        form_action = form['action']
        form_method = form['method']
        inputs = form['inputs']
        
        # Only non-GET forms are typically vulnerable to CSRF
        if form_method.lower() == 'post':
            # Check for CSRF token in form
            has_csrf_token = False
            for input_field in inputs:
                input_name = input_field['name'].lower()
                if 'csrf' in input_name or 'token' in input_name or '_token' in input_name:
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                # Try to submit the form without referer to check if it's accepted
                try:
                    # Prepare form data
                    data = {}
                    for input_field in inputs:
                        data[input_field['name']] = input_field['value'] if input_field['value'] else 'test'
                    
                    # Send request without referer
                    headers = {'Referer': ''}
                    response = self.session.post(form_action, data=data, headers=headers, timeout=10)
                    
                    # If response is 200 OK and doesn't contain error messages, it might be vulnerable
                    if response.status_code == 200 and not re.search(r'(error|invalid|token|csrf)', response.text, re.IGNORECASE):
                        issues.append({
                            'title': 'Cross-Site Request Forgery (CSRF) Vulnerability',
                            'description': 'This form lacks anti-CSRF tokens and accepts requests without proper referer headers.',
                            'url': form_url,
                            'details': f'Form action: {form_action}\nMethod: {form_method}',
                            'severity': 'medium'
                        })
                
                except Exception as e:
                    print(f"Error testing CSRF on {form_action}: {str(e)}")
        
        return issues
