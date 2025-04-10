# Web Vulnerability Scanner

A comprehensive web vulnerability scanner with test applications for various security issues.

## Overview

This project consists of:
1. A main web vulnerability scanner application built with FastAPI
2. Test applications that demonstrate common web vulnerabilities:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Open Directory Listing
   - Security Header Issues
   - CSRF Vulnerabilities

## Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup

1. Clone the repository:
```
git clone <repository-url>
cd web_vuln_scanner
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the application:
```
python app.py
```

## Usage

1. Access the main scanner at: http://localhost:5000/
2. Enter a target URL to scan for vulnerabilities
3. View the scan results

### Test Applications

The scanner comes with built-in test applications for various vulnerabilities:

- SQL Injection Test: http://localhost:8002
- XSS Test: http://localhost:8001
- Open Directory Test: http://localhost:8003
- Header Security Test: http://localhost:8004

You can access all test applications through: http://localhost:5000/test-apps

## API Endpoints

All endpoints are also available as a REST API:

- `GET /` - Main page
- `POST /scan` - Perform a vulnerability scan
- `GET /results` - View scan results
- `GET /test-apps` - Access test applications
- `POST /start-tests` - Start test applications
- `POST /stop-tests` - Stop test applications

## Project Structure

```
web_vuln_scanner/
├── app.py                  # Main FastAPI application
├── requirements.txt        # Project dependencies
├── run_tests.py            # Standalone script to run test applications
├── scanner/                # Scanner module
│   ├── crawler.py          # Web crawler functionality
│   ├── scanner.py          # Main scanner logic
│   └── vulnerabilities/    # Vulnerability scanners
│       ├── csrf.py
│       ├── header_check.py
│       ├── open_directory.py
│       ├── sql_injection.py
│       └── xss.py
├── static/                 # Static assets (CSS, JS)
├── templates/              # HTML templates
│   ├── index.html          # Main scanner page
│   ├── results.html        # Scan results page
│   ├── test_apps.html      # Test applications index
│   └── various templates for test apps
└── tests/                  # Test applications
    ├── setup_db.py         # Database setup for tests
    ├── test_header_checker.py
    ├── test_open_directory.py
    ├── test_sqli.py
    └── test_xss.py
```

## Customization

### Adding New Test Applications

1. Create a new test application in the `tests/` directory
2. Register the application in `app.py`'s `start_test_applications()` function
3. Add the application to the `test_apps.html` template

### Extending Scanner Functionality

1. Add a new vulnerability scanner in the `scanner/vulnerabilities/` directory
2. Register the scanner in `scanner.py`
3. Update the main `app.py` to use the new scanner

## Troubleshooting

### Common Issues

1. **Port conflicts**: If you already have services running on ports 5000, 8001-8004, stop them or change the ports in the application.

2. **Dependencies**: Make sure all required packages are installed via requirements.txt.

3. **Database errors**: If you encounter database errors, delete the test.db file and restart the application.

## Security Note

The test applications intentionally contain security vulnerabilities for educational purposes. Do not deploy them in a production environment.

## License

This project is licensed under the MIT License. 