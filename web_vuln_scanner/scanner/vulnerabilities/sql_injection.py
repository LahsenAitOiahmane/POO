
# sql_injection.py
import re
import time

class SQLInjectionScanner:
    def __init__(self, session):
        self.session = session
        self.payloads = [
            "'",
            "1' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "1; SELECT * FROM information_schema.tables--",
            "' UNION SELECT 1,2,3--"
        ]
        
        self.error_patterns = [
            "sql syntax",
            "syntax error",
            "unclosed quotation",
            "sql command",
            "ORA-",
            "MySQL",
            "SQLSTATE",
            "microsoft sql server",
            "postgresql",
            "sqlite"
        ]
    
    def scan_form(self, form):
        """Scan a form for SQL injection vulnerabilities"""
        issues = []
        form_url = form['url']
        form_action = form['action']
        form_method = form['method']
        inputs = form['inputs']
        
        for payload in self.payloads:
            # Prepare form data with the payload
            data = {}
            for input_field in inputs:
                if input_field['type'] not in ['submit', 'image', 'button']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value']
            
            try:
                # Submit the form
                if form_method == 'post':
                    response = self.session.post(form_action, data=data, timeout=10)
                else:
                    response = self.session.get(form_action, params=data, timeout=10)
                
                # Check for SQL error messages
                response_text = response.text.lower()
                for pattern in self.error_patterns:
                    if pattern in response_text:
                        issues.append({
                            'title': 'SQL Injection Vulnerability',
                            'description': f'A potential SQL injection vulnerability was found in a form on the page.',
                            'url': form_url,
                            'details': f'Form action: {form_action}\nMethod: {form_method}\nPayload: {payload}\nError pattern found: {pattern}',
                            'severity': 'high'
                        })
                        break
                
                # Time-based SQL injection test
                start_time = time.time()
                time_payload = f"{payload} AND (SELECT * FROM (SELECT(SLEEP(2)))a)"
                
                if form_method == 'post':
                    time_data = dict(data)
                    for key in time_data:
                        if time_data[key] == payload:
                            time_data[key] = time_payload
                    self.session.post(form_action, data=time_data, timeout=5)
                else:
                    time_data = dict(data)
                    for key in time_data:
                        if time_data[key] == payload:
                            time_data[key] = time_payload
                    self.session.get(form_action, params=time_data, timeout=5)
                
                time_diff = time.time() - start_time
                
                # If response took over 2 seconds, it might be vulnerable to time-based injection
                if time_diff > 2:
                    issues.append({
                        'title': 'Time-Based SQL Injection Vulnerability',
                        'description': f'A potential time-based SQL injection vulnerability was found.',
                        'url': form_url,
                        'details': f'Form action: {form_action}\nMethod: {form_method}\nPayload: {time_payload}\nResponse time: {time_diff:.2f}s',
                        'severity': 'high'
                    })
            
            except Exception as e:
                print(f"Error testing SQL injection on {form_action}: {str(e)}")
        
        return issues
