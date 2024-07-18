**Name:** ADITYA NAUTIYAL

**Company:** CODTECH IT SOLUTIONS

**Id:** CT6WDS213

**Domain:** Cyber Security

**Duration:** 10Th JUNE 2024 to 22Nd JULY 2024

**Mentor:** SRAVANI GOUNI

# Task 2

# Project: vulnerability scanner
This Python script scans open ports on a given IP or web address and detects outdated software versions and common web server misconfigurations. It checks for SSL/TLS availability, important security headers, and directory indexing. The script is customizable, with verbose mode for detailed output.

### Script Specifications: Open Port Scanner and Web Server Misconfiguration Detector

#### Functionality:
1. **Port Scanning**:
   - Scans a range of ports on a given IP address or web address.
   - Identifies and lists open ports.
   - Supports verbose mode for detailed output (open and closed ports).

2. **Outdated Software Detection**:
   - Identifies web server software and its version.
   - Compares the detected version against the latest known versions.
   - Alerts if the software is outdated.

3. **SSL/TLS Availability Check**:
   - Checks if HTTPS is enabled and properly configured.
   - Reports if HTTPS is not available.

4. **Security Header Check**:
   - Verifies the presence of essential security headers: 
     - Content-Security-Policy
     - X-Content-Type-Options
     - X-Frame-Options
     - Strict-Transport-Security
   - Alerts if any of these headers are missing.

5. **Directory Indexing Check**:
   - Checks for directory indexing on common directories (e.g., /, /admin, /uploads, /images).
   - Reports if directory indexing is enabled.

#### Usage:
- **Command Line Arguments**:
  - `target`: The IP address or web address to scan.
  - `start_port`: The starting port number.
  - `end_port`: The ending port number.
  - `-v, --verbose`: Enable verbose output for detailed results.

- **Example Command**:
  ```sh
  python port_scanner.py example.com 20 80 -v
  ```

#### Dependencies:
- **Python Libraries**:
  - `socket`
  - `argparse`
  - `requests`
  - `packaging`

- **Installation**:
  ```sh
  pip install requests packaging
  ```

#### Limitations:
- The script performs basic checks and might not detect all security issues or misconfigurations.
- The list of latest known versions for server software is hardcoded and should be updated regularly.
- Checking for default credentials is not included in this script.

This script provides a comprehensive yet straightforward solution for identifying open ports, outdated software, and common web server misconfigurations, helping enhance web security.
