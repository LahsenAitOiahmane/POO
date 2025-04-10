from kivy.uix.filechooser import error
from fastapi import FastAPI, Request, Form, Response, Depends, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware


from scanner.scanner import Scanner
from scanner.vulnerabilities.xss import XSSScanner
from scanner.vulnerabilities.sql_injection import SQLInjectionScanner
from scanner.vulnerabilities.csrf import CSRFScanner
from scanner.vulnerabilities.header_check import HeaderScanner
from scanner.vulnerabilities.open_directory import DirectoryScanner


import uuid
import subprocess
import sys
import os
import threading
import time
import socket
import uvicorn
from typing import Optional, Dict, Any


app = FastAPI(title="Web Vulnerability Scanner")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key="kjveskjrvherkuvh",
    session_cookie="session"
)

# Templates
templates = Jinja2Templates(directory="templates")

def check_port_in_use(port):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def get_session(request: Request) -> Dict[str, Any]:
    """Helper function to get the session from the request"""
    return request.session

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan(request: Request, target_url: str = Form(...), scan_type: str = Form("all")):
    # Validate URL format
    if not target_url.startswith(('http://', 'https://')):
        return JSONResponse(content={'error': 'Invalid URL format. Please include http:// or https://'})
    
    # Create a unique scan ID
    scan_id = str(uuid.uuid4())
    request.session["scan_id"] = scan_id
    
    try:
        # Initialize scanner
        scanner = Scanner(target_url)
        
        # Start scan based on selected type
        if scan_type == 'all':
            results = scanner.start_scan()
        else:
            # Initialize specific scanner
            if scan_type == 'xss':
                vuln_scanner = XSSScanner(scanner.session)
            elif scan_type == 'sql_injection':
                vuln_scanner = SQLInjectionScanner(scanner.session)
            elif scan_type == 'csrf':
                vuln_scanner = CSRFScanner(scanner.session)
            elif scan_type == 'headers':
                vuln_scanner = HeaderScanner()
            elif scan_type == 'open_directory':
                vuln_scanner = DirectoryScanner(scanner.session)
            else:
                return JSONResponse(content={'error': 'Invalid scan type'})
            
            # Run specific scan
            scan_results = vuln_scanner.scan(target_url)
            
            # Add severity class for styling
            for issue in scan_results:
                if issue['severity'] == 'high':
                    issue['severity_class'] = 'danger'
                elif issue['severity'] == 'medium':
                    issue['severity_class'] = 'warning'
                elif issue['severity'] == 'low':
                    issue['severity_class'] = 'info'
                else:
                    issue['severity_class'] = 'secondary'
            
            results = {
                'target_url': target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_type,
                'results': scan_results
            }
        
        # Store results in session
        request.session["scan_results"] = results
        
        return JSONResponse(content={'redirect': '/results'})
    except Exception as e:
        return JSONResponse(content={'error': f'Scan failed: {str(e)}'})

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    scan_results = request.session.get("scan_results", {})
    return templates.TemplateResponse("results.html", {"request": request, "results": scan_results})

# This function will be called when running app.py directly
def run_app():
    try:
        # Define the default port and alternative ports
        default_port = 5000
        alternative_ports = [5001, 5002, 5003, 5050, 8000]
        
        # First check if default port is available
        if not check_port_in_use(default_port):
            selected_port = default_port
        else:
            # Try alternative ports
            selected_port = None
            for port in alternative_ports:
                if not check_port_in_use(port):
                    selected_port = port
                    break
            
            # If all ports are in use, notify and use a higher port
            if selected_port is None:
                selected_port = 8080
                print(f"Warning: Default ports are in use. Attempting to use port {selected_port}")
        
        print(f"Starting Web Vulnerability Scanner on port {selected_port}")
        # Run the main application without reload for direct app instance
        uvicorn.run(app, host="0.0.0.0", port=selected_port)
    
    except ConnectionAbortedError as e:
        print(e)
    finally:
        pass

if __name__ == "__main__":
    run_app()