Spoof-Me-Not 🕵️ | Forensic Email Header Analyzer

Repository: change-mechanism-2

Spoof-Me-Not is an advanced, web-based forensic email header analyzer and anti-spoofing dashboard built with Python and Streamlit. Designed for cybersecurity analysts, system administrators, and OSINT investigators, this tool slices through malformed headers, detects deep domain forgeries, and automatically traces malicious payloads back to their true origin IP and network provider.

Whether you are investigating targeted phishing campaigns, business email compromise (BEC), or standard spam, Spoof-Me-Not extracts the suppressed artifacts that attackers try to hide.

🚀 Key Features

Intelligent Header Parsing: Automatically detects and strips web-client UI artifacts (like Gmail "Show Original" copy-paste junk) to seamlessly process raw MTA headers without breaking.

Spoof & Anomaly Detection: Cross-references From, Reply-To, and Return-Path domains to instantly flag severe domain misalignment and display name hijacking.

Security Posture Validation: Extracts and evaluates authentication records, displaying real-time pass/fail states for SPF, DKIM, and DMARC, alongside DKIM domain and selector contexts.

Suppressed Leak Extraction: Deep-sweeps headers for obscure cPanel, PHP, and authentication leaks (e.g., X-AntiAbuse, X-Authenticated-Sender, X-PHP-Originating-Script) to expose compromised internal accounts.

Chronological Routing OSINT: Reverses complex Received hops to build a chronological path of the email's journey, zeroing in on the true Target Origin IP.

Automated RDAP Abuse Resolution: Automatically queries global internet registries (RDAP) to fetch the scammer's Network Name, Country, and registered Abuse Desk Emails for rapid takedown reporting.

One-Click Forensic Export: Generates a clean, downloadable .txt report of all findings—perfect for attaching to ISP abuse reports.

🛠️ Installation & Setup

Spoof-Me-Not is lightweight and requires only streamlit to run.

Clone the repository:
```bash
git clone https://www.google.com/search?q=https://github.com/wpimedia1/change-mechanism-2.git
cd change-mechanism-2
```

Install the required dependencies:
```bash
pip install -r requirements.txt
```
(Note: The only external requirement is streamlit)

Launch the dashboard:
```bash
streamlit run app.py
```
The dashboard will automatically open in your default web browser at http://localhost:8501.

🎯 How to Use

Open the email you want to investigate in your email client and select "Show Original" or "View Raw Message".

Copy the entire raw text block.

Paste the text into the text area on the Spoof-Me-Not dashboard.

Click "Analyze Header".

Review the parsed identities, security metrics, and routing paths. Download the Forensic Report at the bottom of the page to submit to the corresponding abuse desks.

🌐 Deploying to Streamlit Community Cloud

This app is fully optimized for immediate deployment on Streamlit Community Cloud:

Ensure your code is pushed to your GitHub repository (change-mechanism-2).

Log into share.streamlit.io.

Click "New App" and select your repository and the streamlit_app.py file.

Click Deploy. Your anti-spoofing dashboard will be live securely on the web within minutes.

🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

Keywords: email header analyzer, forensic email analysis, phishing detection tool, OSINT email tracer, DMARC DKIM SPF checker, anti-spoofing tool, cPanel leak detection, RDAP abuse lookup, cybersecurity dashboard.
