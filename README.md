# 🛡️ SiteSentinel: Web Security Grader & Recon Tool

SiteSentinel is an automated, full-stack cybersecurity reconnaissance platform. It acts as a primary grading engine that inspects web servers for critical missing HTTP security policies and identifies potential attack vectors. It also features a real-time Open-Source Intelligence (OSINT) dashboard and an active TCP Port Scanner.

## ✨ Core Features

* **HTTP Security Header Analysis:** Automatically grades target URLs based on the presence of crucial security headers (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`).
* **Vulnerability Detection:** Identifies risks associated with Clickjacking, Cross-Site Scripting (XSS), and MITM Protocol Downgrades.
* **Domain Intelligence (OSINT):** Performs real-time WHOIS lookups to gather domain registrar details, creation, and expiration dates.
* **Active Port Scanner:** Features a terminal-style UI that conducts TCP connect scans on critical network ports (21, 22, 80, 443, 3306) to identify exposed services.
* **Exportable Reports:** Generates downloadable `.txt` security reports containing the final grade, score, and header breakdown.

## 💻 Tech Stack

* **Frontend:** HTML5, Tailwind CSS, JavaScript (Fetch API)
* **Backend:** Python 3, Flask
* **Security/Networking:** `socket` (Port Scanning), `python-whois` (OSINT), `requests` (HTTP Analysis)

## 🚀 How to Run Locally

If you want to run this project on your own machine, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/SiteSentinel.git](https://github.com/YOUR_USERNAME/SiteSentinel.git)

   
