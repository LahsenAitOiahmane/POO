#!/usr/bin/env python3
"""
Utility script to kill processes using specific ports

This can help if you have processes stuck on ports needed by test applications.
"""

import os
import sys
import socket
import time

try:
    import psutil
except ImportError:
    print("Error: psutil module not found. Please install with 'pip install psutil'")
    sys.exit(1)

def is_port_in_use(port, host='127.0.0.1'):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

def kill_process_on_port(port, host='127.0.0.1'):
    """Kill any process that is listening on the specified port"""
    killed = False
    for conn in psutil.net_connections():
        if conn.laddr.port == port and (host == '0.0.0.0' or conn.laddr.ip == host or host == '127.0.0.1'):
            try:
                process = psutil.Process(conn.pid)
                # Be a bit safer by only killing Python processes
                if 'python' in process.name().lower() or 'uvicorn' in ' '.join(process.cmdline()).lower():
                    print(f"Killing process {conn.pid} ({process.name()}) using port {port}")
                    process.terminate()
                    killed = True
                    # Give it a chance to terminate gracefully
                    try:
                        process.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        print(f"Process {conn.pid} didn't terminate gracefully, killing forcefully...")
                        process.kill()
                else:
                    print(f"WARNING: Process {conn.pid} ({process.name()}) is using port {port} but is not a Python process. Not killing.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"Could not access process with PID {conn.pid}")
    
    return killed

def main():
    # Ports used by test applications
    target_ports = [8001, 8002, 8003, 8004, 5000]
    
    print("Checking for processes using test application ports...")
    
    for port in target_ports:
        if is_port_in_use(port):
            print(f"Port {port} is in use. Attempting to kill process...")
            if kill_process_on_port(port):
                time.sleep(0.5)  # Give OS time to release the port
                if not is_port_in_use(port):
                    print(f"Successfully freed port {port}")
                else:
                    print(f"Port {port} is still in use after killing process")
            else:
                print(f"No suitable process found using port {port}")
        else:
            print(f"Port {port} is free")
    
    print("\nAll done. You can now start the application.")

if __name__ == "__main__":
    main() 