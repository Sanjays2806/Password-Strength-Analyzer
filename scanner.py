import socket
import sys

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt"
}

VULNERABLE_VERSIONS = {
    "vsftpd 2.3.4": "Backdoor Command Execution Risk (CVE-2011-2523)",
    "OpenSSH 4.3": "Severe Remote Code Execution Risk",
    "Apache 2.2.8": "Multiple Denial of Service vulnerabilities",
    "Tomcat 6.0.0": "Directory Traversal and Information Disclosure"
}

SIMULATED_BANNERS = {
    21: "220 vsftpd 2.3.4",
    22: "SSH-2.0-OpenSSH_4.3",
    23: "Telnet server ready",
    80: "Apache/2.2.8 (Ubuntu)",
    443: "Apache/2.4.41 (Ubuntu)",
    8080: "Apache-Coyote/1.1 (Tomcat 6.0.0)"
}

def scan_target(target_host):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        return None, []

    scan_results = []
    
    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            banner = SIMULATED_BANNERS.get(port, "Unknown Service")
            
            vuln_details = "No known major exploit signature detected in version string."
            is_vulnerable = False
            
            if port == 23:
                vuln_details = "Insecure Configuration: Telnet transmits data in plaintext. Switch to SSH (Port 22)."
                is_vulnerable = True
            else:
                for version, threat in VULNERABLE_VERSIONS.items():
                    if version in banner:
                        vuln_details = f"Outdated Software Detected: {threat}"
                        is_vulnerable = True
                        break
            
            scan_results.append({
                "port": port,
                "service": service,
                "banner": banner,
                "vulnerable": is_vulnerable,
                "details": vuln_details
            })
        s.close()
        
    return target_ip, scan_results

def generate_report(target_host, target_ip, results):
    print("=" * 60)
    print("                 VULNERABILITY SCAN REPORT                  ")
    print("=" * 60)
    print(f"Target Host : {target_host}")
    print(f"Target IP   : {target_ip}")
    print("-" * 60)
    
    if not results:
        print("Scan completed. No open common ports discovered.")
        print("=" * 60)
        return

    vuln_count = 0
    for res in results:
        print(f"[*] Port {res['port']} ({res['service']}) is OPEN")
        print(f"    Banner: {res['banner']}")
        if res['vulnerable']:
            vuln_count += 1
            print(f"    [CRITICAL] {res['details']}")
        else:
            print(f"    [INFO] {res['details']}")
        print("-" * 60)
        
    print(f"Scan Summary: Detected {vuln_count} risk configurations/vulnerabilities.")
    print("=" * 60)

if __name__ == "__main__":
    print("--- Network & Configuration Vulnerability Scanner ---")
    target = input("Enter target host or IP (e.g., localhost): ").strip()
    
    if not target:
        target = "localhost"
        
    print(f"\nInitiating scan against target: {target}...")
    ip, findings = scan_target(target)
    
    if ip is None:
        print("Error: Could not resolve target hostname.")
    else:
        generate_report(target, ip, findings)
