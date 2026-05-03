from flask import Flask, render_template, request
import nmap
import json
import boto3
from datetime import datetime

app = Flask(__name__)

# 🔐 CHANGE THIS
BUCKET_NAME = "vuln-scanner-reports-viq"  

# -------------------------
# Vulnerability Logic
# -------------------------
def check_vulnerability(service, port, version):
    service = (service or "").lower()
    version = (version or "").lower()

    if port == 21:
        return "HIGH: FTP may allow anonymous login"
    elif port == 23:
        return "HIGH: Telnet is insecure"
    elif port == 445:
        return "MEDIUM: SMB exposed (lateral movement risk)"
    elif "ssh" in service:
        return "INFO: Check for weak credentials"
    else:
        return "LOW: No obvious risk"


# -------------------------
# Scanner
# -------------------------
def scan_target(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')

    results = []
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in ports:
                service = scanner[host][proto][port].get('name', '')
                version = scanner[host][proto][port].get('version', '')

                risk = check_vulnerability(service, port, version)

                if "HIGH" in risk:
                    summary["HIGH"] += 1
                elif "MEDIUM" in risk:
                    summary["MEDIUM"] += 1
                elif "LOW" in risk:
                    summary["LOW"] += 1
                else:
                    summary["INFO"] += 1

                results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": risk
                })

    return results, summary


# -------------------------
# Save + Upload to S3
# -------------------------
def save_and_upload(data):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    s3 = boto3.client('s3')
    s3.upload_file(filename, BUCKET_NAME, filename)

    return filename


# -------------------------
# Routes
# -------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")

        results, summary = scan_target(target)

        report_data = {
            "target": target,
            "results": results,
            "summary": summary
        }

        filename = save_and_upload(report_data)

        return render_template(
            "result.html",
            target=target,
            results=results,
            summary=summary,
            file=filename
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
