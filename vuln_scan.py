import socket
import argparse
import requests
from packaging import version

def scan_ports(target, start_port, end_port, verbose):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve {target}.")
        return

    print(f"Starting scan on {target_ip} from port {start_port} to {end_port}")

    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            open_ports.append(port)
            if verbose:
                print(f"Port {port}: OPEN")
        else:
            if verbose:
                print(f"Port {port}: CLOSED")

        sock.close()

    if not verbose:
        if open_ports:
            print("Open ports:")
            for port in open_ports:
                print(f"Port {port}: OPEN")
        else:
            print("No open ports found.")

    if 80 in open_ports or 443 in open_ports:
        detect_outdated_software(target)
        check_ssl(target)
        check_security_headers(target)
        check_directory_indexing(target)

def detect_outdated_software(target):
    try:
        response = requests.get(f"http://{target}")
    except requests.RequestException:
        try:
            response = requests.get(f"https://{target}")
        except requests.RequestException:
            print(f"Could not connect to {target} on port 80 or 443.")
            return

    server_header = response.headers.get("Server")
    if not server_header:
        print("No Server header found in the response.")
        return

    server_info = server_header.split("/")
    server_name = server_info[0]
    server_version = server_info[1] if len(server_info) > 1 else None

    print(f"Detected server: {server_name} version: {server_version}")

    latest_versions = {
        "nginx": "1.24.0",
        "apache": "2.4.57",
        # Add more server software and their latest versions here
    }

    if server_name.lower() in latest_versions:
        latest_version = latest_versions[server_name.lower()]
        if server_version and version.parse(server_version) < version.parse(latest_version):
            print(f"Outdated {server_name} version detected: {server_version}. Latest version: {latest_version}")
        else:
            print(f"{server_name} is up-to-date.")
    else:
        print(f"No version information available for {server_name}.")

def check_ssl(target):
    try:
        response = requests.get(f"https://{target}", timeout=5)
        if response.status_code == 200:
            print("HTTPS is enabled.")
        else:
            print("HTTPS is not properly configured.")
    except requests.RequestException:
        print("HTTPS is not available.")

def check_security_headers(target):
    try:
        response = requests.get(f"http://{target}")
    except requests.RequestException:
        try:
            response = requests.get(f"https://{target}")
        except requests.RequestException:
            print(f"Could not connect to {target} on port 80 or 443.")
            return

    headers = response.headers
    if "Content-Security-Policy" not in headers:
        print("Missing Content-Security-Policy header.")
    if "X-Content-Type-Options" not in headers:
        print("Missing X-Content-Type-Options header.")
    if "X-Frame-Options" not in headers:
        print("Missing X-Frame-Options header.")
    if "Strict-Transport-Security" not in headers:
        print("Missing Strict-Transport-Security header.")

def check_directory_indexing(target):
    common_directories = ["/", "/admin", "/uploads", "/images"]
    for directory in common_directories:
        url = f"http://{target}{directory}"
        try:
            response = requests.get(url)
            if "Index of" in response.text:
                print(f"Directory indexing is enabled on {url}")
        except requests.RequestException:
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan open ports on a given IP address or web address and detect outdated software versions.")
    parser.add_argument("target", help="The IP address or web address to scan.")
    parser.add_argument("start_port", type=int, help="The starting port number.")
    parser.add_argument("end_port", type=int, help="The ending port number.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    args = parser.parse_args()

    scan_ports(args.target, args.start_port, args.end_port, args.verbose)
