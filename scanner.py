import nmap
import json
import sys

# 🔍 Vulnerability Logic
def check_vulnerability(service, port, version):
    service = service.lower()
    version = version.lower()

    if port == 21:
        return "HIGH: FTP may allow anonymous login"
    elif port == 23:
        return "HIGH: Telnet is insecure"
    elif port == 445:
        return "MEDIUM: SMB exposed (possible lateral movement risk)"
    elif "apache" in service and ("2.2" in version or "2.0" in version):
        return "HIGH: Outdated Apache version"
    elif "ssh" in service:
        return "INFO: Check for weak credentials/brute force"
    elif port == 80 or port == 443:
        return "MEDIUM: Web server - test for XSS/SQLi"
    else:
        return "LOW: No obvious risk"

# 🔎 Scan Function
def scan_target(target):
    scanner = nmap.PortScanner()
    print(f"\n[+] Scanning target: {target}\n")
    
    scanner.scan(target, arguments='-sV')

    results = []

    for host in scanner.all_hosts():
        print(f"[+] Host: {host}")

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in ports:
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']

                risk = check_vulnerability(service, port, version)

                # 📊 Store result
                results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": risk
                })

                # 📺 Clean Output
                print("-" * 60)
                print(f"Port     : {port}")
                print(f"Service  : {service}")
                print(f"Version  : {version}")
                print(f"Risk     : {risk}")
                print("-" * 60)

    return results

# 📊 Summary Function
def summarize(results):
    high = sum(1 for r in results if "HIGH" in r["risk"])
    medium = sum(1 for r in results if "MEDIUM" in r["risk"])
    low = sum(1 for r in results if "LOW" in r["risk"])
    info = sum(1 for r in results if "INFO" in r["risk"])

    print("\n========== SCAN SUMMARY ==========")
    print(f"High Risk   : {high}")
    print(f"Medium Risk : {medium}")
    print(f"Low Risk    : {low}")
    print(f"Info        : {info}")
    print("==================================")

# 💾 Save Report
def save_report(data):
    with open("report.json", "w") as f:
        json.dump(data, f, indent=4)

    print("\n[+] Report saved as report.json")

# 🚀 Main Execution
if __name__ == "__main__":

    # CLI argument support
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target IP: ")

    data = scan_target(target)
    summarize(data)
    save_report(data)