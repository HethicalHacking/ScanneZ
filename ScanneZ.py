import socket
import requests
from termcolor import colored
import time

def resolve_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return [ip]
    except Exception as e:
        print(f"DNS resolution error: {e}")
        return []

def scan_ports(ip):
    open_ports = []
    print(f"\nScanning open ports on {ip}...\n{'-'*60}")
    
    ports_to_scan = [
        22, 80, 443, 8080, 21, 53, 25, 3306, 1433, 3389, 23, 6379, 27017, 11211, 143, 5900, 5432
    ]
    
    critical_ports = {
        22: "SSH", 3306: "MySQL", 21: "FTP", 80: "HTTP", 443: "HTTPS",
        8080: "HTTP-alt", 53: "DNS", 25: "SMTP", 1433: "MSSQL", 3389: "RDP",
        23: "Telnet", 6379: "Redis", 27017: "MongoDB", 11211: "Memcached",
        143: "IMAP", 5900: "VNC", 5432: "PostgreSQL"
    }
    
    for port in ports_to_scan:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                service = critical_ports.get(port, "Unknown")
                if port in [22, 3306, 21, 23, 6379, 27017, 11211, 3389]:
                    print(colored(f"Port {port}: {service}", 'red'))
                elif port in [80, 443, 8080]:
                    print(colored(f"Port {port}: {service}", 'yellow'))
                else:
                    print(colored(f"Port {port}: {service}", 'green'))
            s.close()
        except socket.error:
            continue
    
    return open_ports

def test_http_vulnerabilities(ip):
    print(f"\nTesting for common HTTP vulnerabilities on {ip}...\n{'-'*60}")
    
    potential_files = [
        "/error.php", "/phpinfo.php", "/public_html", "/index.php", "/.htaccess"
    ]
    for file in potential_files:
        url = f"http://{ip}{file}"
        try:
            response = requests.get(url, timeout=2)
            print(f"Checking {url}...")
            if response.status_code == 200:
                print(colored(f"Vulnerability found: {url} is accessible (status code {response.status_code})", 'red'))
                print(f"Response Time: {response.elapsed.total_seconds()}s")
            else:
                print(f"File {url} returned status {response.status_code}")
        except requests.RequestException as e:
            print(f"Error checking {url}: {str(e)}")

def test_directory_traversal(ip):
    print(f"\nTesting for Directory Traversal vulnerabilities on {ip}...\n{'-'*60}")
    
    test_paths = [
        "/../../etc/passwd", "/../../../etc/passwd", "/../../../../etc/passwd",
        "/../../../../../../etc/shadow", "/../../etc/hosts"
    ]
    
    for path in test_paths:
        url = f"http://{ip}{path}"
        try:
            response = requests.get(url, timeout=2)
            print(f"Checking {url}...")
            if response.status_code == 200:
                print(colored(f"Vulnerability found: Directory traversal possible with {path} (status code {response.status_code})", 'red'))
                print(f"Response Time: {response.elapsed.total_seconds()}s")
            else:
                print(f"Path {path} returned status {response.status_code}")
        except requests.RequestException as e:
            print(f"Error checking {url}: {str(e)}")

def test_http_headers(ip):
    print(f"\nTesting for missing HTTP headers on {ip}...\n{'-'*60}")
    
    url = f"http://{ip}"
    try:
        response = requests.get(url, timeout=2)
        headers = response.headers
        missing_headers = []
        
        if 'Strict-Transport-Security' not in headers:
            missing_headers.append("Strict-Transport-Security")
        if 'X-Content-Type-Options' not in headers:
            missing_headers.append("X-Content-Type-Options")
        if 'X-Frame-Options' not in headers:
            missing_headers.append("X-Frame-Options")
        
        if missing_headers:
            print(colored(f"Missing HTTP headers: {', '.join(missing_headers)}", 'yellow'))
        else:
            print(colored("All critical HTTP headers are present.", 'green'))
    except requests.RequestException as e:
        print(f"Error checking HTTP headers: {str(e)}")

def print_table(ips, ports_status):
    print("\n" + '-'*70)
    print(f"{'IP Address':<20} {'Open Ports':<20} {'Service Type':<20}")
    print('-'*70)
    for ip, (ports, services) in zip(ips, ports_status):
        for port, service in zip(ports, services):
            print(f"{ip:<20} {port:<20} {service:<20}")
    print('-'*70)

def main():
    domain = input("Enter the domain (without 'http://'): ").strip()

    ips = resolve_dns(domain)
    if not ips:
        print(f"Could not resolve the domain {domain}")
        return

    print(f"Domain: {domain} has the following associated IPs: {', '.join(ips)}")

    ports_status = []
    for ip in ips:
        print(f"\nAnalyzing IP: {ip}")
        ports = scan_ports(ip)
        
        critical_ports = {
            22: "SSH", 3306: "MySQL", 21: "FTP", 80: "HTTP", 443: "HTTPS",
            8080: "HTTP-alt", 53: "DNS", 25: "SMTP", 1433: "MSSQL", 3389: "RDP",
            23: "Telnet", 6379: "Redis", 27017: "MongoDB", 11211: "Memcached",
            143: "IMAP", 5900: "VNC", 5432: "PostgreSQL"
        }
        services = [critical_ports.get(port, "Unknown") for port in ports]

        ports_status.append((ports, services))
        
        test_http_vulnerabilities(ip)
        test_directory_traversal(ip)
        test_http_headers(ip)

    print_table(ips, ports_status)

if __name__ == "__main__":
    main()
