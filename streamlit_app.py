import streamlit as st
import re
import json
import urllib.request
from email.parser import HeaderParser
import datetime

st.set_page_config(
    page_title="Spoof-Me-Not | Forensic Header Analyzer",
    page_icon="🕵️",
    layout="wide"
)

def clean_raw_headers(raw_text):
    match = re.search(r'Download Original\s+Copy to clipboard', raw_text, re.IGNORECASE)
    if match:
        raw_text = raw_text[match.end():]
        
    if not re.match(r'^[A-Za-z0-9-]+:', raw_text.lstrip()):
        match = re.search(r'^(Delivered-To|Return-Path|Received|Authentication-Results|X-[A-Za-z0-9-]+):', raw_text, re.IGNORECASE | re.MULTILINE)
        if match:
            raw_text = raw_text[match.start():]

    return raw_text.lstrip()

@st.cache_data(ttl=3600, show_spinner=False)
def get_abuse_contacts(ip):
    if not ip or ip == "Unknown":
        return {'emails': [], 'name': 'Unknown', 'country': 'Unknown'}
    try:
        url = f"https://rdap.org/ip/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 ForensicDash/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))

        info = {'emails': set(), 'name': data.get('name', 'Unknown Network'), 'country': data.get('country', 'Unknown')}
        
        def search_entities(entities):
            for ent in entities:
                roles = ent.get('roles', [])
                if 'abuse' in roles:
                    for item in ent.get('vcardArray', [[]])[1]:
                        if item[0] == 'email':
                            info['emails'].add(item[3])
                if 'entities' in ent:
                    search_entities(ent['entities'])

        if 'entities' in data:
            search_entities(data['entities'])
            
        info['emails'] = list(info['emails'])
        return info
    except Exception:
        return {'emails': [], 'name': 'Unknown', 'country': 'Unknown'}

def generate_text_report(h, anomalies, leaks, hops, origin_ip, rdap_info):
    lines = []
    lines.append("=== FORENSIC EMAIL HEADER REPORT ===")
    lines.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    lines.append("[+] MESSAGE IDENTITY")
    lines.append(f"From:          {h.get('From', 'None')}")
    lines.append(f"To:            {h.get('To', 'None')}")
    lines.append(f"Reply-To:      {h.get('Reply-To', 'None')}")
    lines.append(f"Subject:       {h.get('Subject', 'None')}")
    lines.append(f"Message-ID:    {h.get('Message-ID', 'None')}")
    lines.append(f"Date:          {h.get('Date', 'None')}\n")

    lines.append("[+] DOMAIN ALIGNMENT & SECURITY")
    lines.append(f"Envelope-From: {h.get('Envelope-from', h.get('Return-Path', 'None'))}")
    
    auth = h.get("Authentication-Results", "")
    auth_flat = auth.replace('\n', ' ').replace('\r', '')
    spf = re.search(r'spf=(\w+)', auth_flat, re.IGNORECASE)
    dkim_res = re.search(r'dkim=(\w+)', auth_flat, re.IGNORECASE)
    dmarc = re.search(r'dmarc=(\w+)', auth_flat, re.IGNORECASE)
    
    lines.append(f"SPF Result:    {spf.group(1).upper() if spf else 'None'}")
    lines.append(f"DKIM Result:   {dkim_res.group(1).upper() if dkim_res else 'None'}")
    lines.append(f"DMARC Result:  {dmarc.group(1).upper() if dmarc else 'None'}")

    dkim_sig = h.get("DKIM-Signature", "")
    dkim_sig_flat = dkim_sig.replace('\n', ' ').replace('\r', '')
    d_dom = re.search(r'd=([^;]+)', dkim_sig_flat)
    d_sel = re.search(r's=([^;]+)', dkim_sig_flat)
    if d_dom and d_sel:
        lines.append(f"DKIM Domain:   {d_dom.group(1).strip()}")
        lines.append(f"DKIM Selector: {d_sel.group(1).strip()}")
    lines.append("")

    lines.append("[+] ANOMALIES & SPOOFING")
    for a in anomalies: lines.append(a)
    mailer = h.get('X-Mailer', h.get('User-Agent', 'Unknown'))
    lines.append(f"Tooling/Mailer: {mailer}\n")

    lines.append("[+] SUPPRESSED LEAKS")
    if leaks:
        for l in leaks: lines.append(l)
    else:
        lines.append("No obvious username or script leaks detected.")
    lines.append("")

    lines.append("[+] ROUTING HOPS (Chronological)")
    if hops:
        for idx, hop in enumerate(hops):
            lines.append(f"Hop {idx+1}: IP: {hop['ip']:<15} | HELO: {hop['helo']}")
    else:
        lines.append("No routing hops detected.")
    lines.append("")

    lines.append("[+] ABUSE REPORTING TARGET")
    lines.append(f"Target Origin IP:  {origin_ip}")
    lines.append(f"Network Name:      {rdap_info['name']}")
    lines.append(f"Country:           {rdap_info['country']}")
    lines.append(f"Abuse Emails:      {', '.join(rdap_info['emails']) if rdap_info['emails'] else 'None found in RDAP'}")
    lines.append(f"AbuseIPDB Link:    https://www.abuseipdb.com/check/{origin_ip}")
    lines.append(f"MXToolbox Link:    https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{origin_ip}")
    
    return "\n".join(lines)

st.title("🕵️ Spoof-Me-Not")
st.markdown("**Forensic Email Header Analyzer & Anti-Spoofing Dashboard**")

raw_input = st.text_area("Paste Raw Email Header Here:", height=200, placeholder="Paste headers here...")

if st.button("Analyze Header", type="primary"):
    if not raw_input.strip():
        st.error("Please paste an email header to begin.")
        st.stop()

    with st.spinner("Analyzing forensics..."):
        clean_text = clean_raw_headers(raw_input)
        
        if not clean_text:
            st.error("Could not parse headers. The input appears to be empty or completely malformed.")
            st.stop()

        parser = HeaderParser()
        h = parser.parsestr(clean_text)

        if not h.keys():
            st.warning("No valid headers detected. Ensure you copied the raw payload and not just the email body.")
            st.stop()

        st.subheader("Message Identity")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**From:** `{h.get('From', 'None')}`")
            st.write(f"**To:** `{h.get('To', 'None')}`")
            st.write(f"**Reply-To:** `{h.get('Reply-To', 'None')}`")
        with col2:
            st.write(f"**Subject:** {h.get('Subject', 'None')}")
            st.write(f"**Message-ID:** `{h.get('Message-ID', 'None')}`")
            st.write(f"**Date:** {h.get('Date', 'None')}")
        
        st.divider()

        st.subheader("Domain Alignment & Security")
        st.write(f"**Envelope-From:** `{h.get('Envelope-from', h.get('Return-Path', 'None'))}`")
        
        auth = h.get("Authentication-Results", "")
        auth_flat = auth.replace('\n', ' ').replace('\r', '')
        spf = re.search(r'spf=(\w+)', auth_flat, re.IGNORECASE)
        dkim_res = re.search(r'dkim=(\w+)', auth_flat, re.IGNORECASE)
        dmarc = re.search(r'dmarc=(\w+)', auth_flat, re.IGNORECASE)
        
        col_sec1, col_sec2, col_sec3 = st.columns(3)
        col_sec1.metric("SPF", spf.group(1).upper() if spf else "NONE")
        col_sec2.metric("DKIM", dkim_res.group(1).upper() if dkim_res else "NONE")
        col_sec3.metric("DMARC", dmarc.group(1).upper() if dmarc else "NONE")

        dkim_sig = h.get("DKIM-Signature", "")
        dkim_sig_flat = dkim_sig.replace('\n', ' ').replace('\r', '')
        d_dom = re.search(r'd=([^;]+)', dkim_sig_flat)
        d_sel = re.search(r's=([^;]+)', dkim_sig_flat)
        if d_dom and d_sel:
            st.info(f"**DKIM Signature Context:** Domain `d={d_dom.group(1).strip()}` | Selector `s={d_sel.group(1).strip()}`")

        st.divider()

        st.subheader("Anomaly & Spoof Detector")
        from_hdr = h.get('From', '')
        return_path = h.get('Return-Path', h.get('Envelope-from', ''))
        reply_to = h.get('Reply-To', '')
        
        from_dom = re.search(r'@([\w.-]+)', from_hdr)
        ret_dom = re.search(r'@([\w.-]+)', return_path)
        rep_dom = re.search(r'@([\w.-]+)', reply_to) if reply_to else None

        from_dom_str = from_dom.group(1).lower() if from_dom else ""
        ret_dom_str = ret_dom.group(1).lower() if ret_dom else ""
        rep_dom_str = rep_dom.group(1).lower() if rep_dom else ""

        anomalies = []
        if from_dom_str and ret_dom_str and from_dom_str != ret_dom_str:
            msg = f"SEVERE FORGERY: 'From' domain ({from_dom_str}) DOES NOT MATCH 'Return-Path' ({ret_dom_str})"
            st.error(msg)
            anomalies.append(msg)
        
        if rep_dom_str and from_dom_str and rep_dom_str != from_dom_str:
            msg = f"WARNING: 'Reply-To' domain ({rep_dom_str}) differs from sender."
            st.warning(msg)
            anomalies.append(msg)

        mailer = h.get('X-Mailer', h.get('User-Agent', 'Unknown'))
        st.info(f"**Tooling/Mailer:** `{mailer}`")
        if not anomalies:
            st.success("No immediate domain mismatches detected.")
            anomalies.append("None detected.")

        st.divider()

        st.subheader("Suppressed Username & Script Leaks")
        leaks = []
        target_headers = ["X-Authenticated-User", "X-AuthUser", "X-Sender", "X-Authenticated-Sender", "Auth-User", "X-AntiAbuse", "X-PHP-Originating-Script", "X-Source", "X-Source-Args", "X-Get-Message-Sender-Via"]
        
        for t in target_headers:
            for val in h.get_all(t, []):
                val = val.replace('\n', ' ').strip()
                leaks.append(f"{t}: {val}")

        if leaks:
            for l in leaks:
                st.code(l, language="text")
        else:
            st.success("No obvious username or script leaks detected in headers.")

        st.divider()

        received = h.get_all("Received", [])
        chronological_hops = list(reversed(received))
        parsed_hops = []
        
        for r in chronological_hops:
            ip_match = re.search(r'\[((?:\d{1,3}\.){3}\d{1,3})\]', r)
            ip = ip_match.group(1) if ip_match else "Unknown"
            helo_match = re.search(r'from\s+([^\s]+)', r, re.IGNORECASE)
            helo = helo_match.group(1) if helo_match else "Unknown"
            parsed_hops.append({'ip': ip, 'helo': helo, 'raw': r.strip()})

        origin_ip = None
        for header in ["X-Originating-IP", "X-Real-IP"]:
            val = h.get(header)
            if val:
                match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val)
                if match: origin_ip = match.group(0); break

        if not origin_ip and parsed_hops:
            for hop in parsed_hops:
                if hop['ip'] != "Unknown":
                    origin_ip = hop['ip']; break

        col_abuse, col_hops = st.columns([1, 1])

        with col_abuse:
            st.subheader("Abuse Reporting Target")
            if origin_ip:
                st.metric(label="Target Origin IP", value=origin_ip)
                rdap_info = get_abuse_contacts(origin_ip)
                
                st.write(f"**Network:** {rdap_info['name']}")
                st.write(f"**Country:** {rdap_info['country']}")
                
                if rdap_info['emails']:
                    for email in rdap_info['emails']:
                        st.success(f"**Abuse Email:** {email}")
                else:
                    st.warning(f"No specific abuse email found in RDAP. Try: `abuse@{origin_ip}`")
                
                st.markdown(f"[Check AbuseIPDB](https://www.abuseipdb.com/check/{origin_ip}) | [Check MXToolbox](https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{origin_ip})")
            else:
                st.error("Could not reliably extract Origin IP from headers.")
                rdap_info = {'name': 'Unknown', 'country': 'Unknown', 'emails': []}

        with col_hops:
            st.subheader("Routing Hops")
            with st.expander("View Full Chronological Hops"):
                for idx, hop in enumerate(parsed_hops):
                    st.code(f"Hop {idx+1} | IP: {hop['ip']} | HELO: {hop['helo']}", language="text")

        st.divider()
        report_text = generate_text_report(h, anomalies, leaks, parsed_hops, origin_ip, rdap_info)
        st.download_button(
            label="📄 Download Forensic Report",
            data=report_text,
            file_name=f"forensic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )