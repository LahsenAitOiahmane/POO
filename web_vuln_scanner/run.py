#!/usr/bin/env python3
"""
Launcher script for Web Vulnerability Scanner with hot reload support
"""

import uvicorn
import socket
import sys
import os
import subprocess
import signal
import time
import atexit

# Import from app.py to reuse functions
from app import start_test_applications, stop_test_applications, check_port_in_use

def find_available_port(default_port, alternative_ports):
    """Find an available port from the given options"""
    if not check_port_in_use(default_port):
        return default_port
    
    for port in alternative_ports:
        if not check_port_in_use(port):
            return port
    
    # If all ports are in use, return a higher port
    return 8080

def cleanup_on_exit():
    """Clean up resources when the program exits"""
    print("Stopping test applications...")
    stop_test_applications()

if __name__ == "__main__":
    # Define default and alternative ports
    default_port = 5000
    alternative_ports = [5001, 5002, 5003, 5050, 8000]
    
    # Find available port
    port = find_available_port(default_port, alternative_ports)
    
    if port != default_port:
        print(f"Port {default_port} is in use. Using alternative port {port}.")
    
    # Start test applications
    print("Starting test applications...")
    start_test_applications()
    
    # Register cleanup handler
    atexit.register(cleanup_on_exit)
    
    print(f"Starting Web Vulnerability Scanner on port {port} with reload enabled")
    
    # Determine if we're on Windows
    is_windows = os.name == 'nt'
    
    # Configure Uvicorn options
    reload_dirs = ["app.py", "scanner", "templates", "static"]
    log_level = "info"
    
    try:
        # Start the application with reload enabled
        # Using the module:app format which works with reload
        if is_windows:
            # On Windows, use statreload instead of default watchgod
            uvicorn.run(
                "app:app", 
                host="0.0.0.0", 
                port=port, 
                reload=True,
                reload_dirs=reload_dirs,
                log_level=log_level,
                reload_delay=1.0
            )
        else:
            # Standard reload on Unix systems
            uvicorn.run(
                "app:app", 
                host="0.0.0.0", 
                port=port, 
                reload=True,
                reload_dirs=reload_dirs,
                log_level=log_level
            )
    except KeyboardInterrupt:
        print("Received termination signal. Cleaning up...")
    finally:
        # Make sure test applications are stopped
        stop_test_applications() 