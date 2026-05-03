# 🔐 Vulnerability Scanner Web App

## 🚀 Overview

A web-based vulnerability scanner built using Python, Flask, and Nmap, deployed on AWS EC2.

## 🧰 Tech Stack

* Python
* Flask
* Nmap
* AWS EC2
* Gunicorn
* systemd (for 24/7 uptime)

## 🌐 Live Demo

http://98.87.18.163:5000

## ⚙️ Features

* Scan target IP for open ports
* Identify services running
* Basic vulnerability insights
* JSON report generation
* Web dashboard UI

## ☁️ Deployment

* Hosted on AWS EC2 (Ubuntu)
* Gunicorn used as WSGI server
* systemd service ensures auto-start and uptime

## 📂 Project Structure

vuln-scanner/
├── app.py
├── scanner.py
├── report.json
├── templates/
│   ├── index.html
│   └── result.html

## ▶️ Run Locally

```bash
pip install -r requirements.txt
python app.py
```
