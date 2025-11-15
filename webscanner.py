from flask import Flask, render_template, request, make_response, session, jsonify
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import time
from datetime import datetime
from weasyprint import HTML
import os # For the secret key
import json

# --- Flask App Initialization ---
app = Flask(__name__)
# A secret key is required to use sessions
app.secret_key = os.urandom(24)


# --- FINAL UPGRADE: Recursive Crawler & Form Discovery ---
def crawl_and_discover_forms(start_url, max_pages=10):
    """
    Recursively crawls a website starting from a URL to discover all unique forms.
    """
    netloc = urlparse(start_url).netloc
    pages_to_visit = {start_url}
    visited_pages = set()
    all_forms = []

    with requests.Session() as s:
        s.headers['User-Agent'] = 'WebAppScanner/1.0'
        
        while pages_to_visit and len(visited_pages) < max_pages:
            url = pages_to_visit.pop()
            if url in visited_pages:
                continue
            
            visited_pages.add(url)
            print(f"Crawling: {url}")

            try:
                response = s.get(url, timeout=5)
                soup = BeautifulSoup(response.content, "lxml")

                # Discover forms on the current page
                for form in soup.find_all("form"):
                    details = {}
                    action = form.attrs.get("action")
                    method = form.attrs.get("method", "get").lower()
                    
                    absolute_action = urljoin(url, action)
                    details['action'] = absolute_action
                    details['method'] = method
                    details['inputs'] = []
                    
                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        input_name = input_tag.attrs.get("name")
                        if input_name:
                            details['inputs'].append({"name": input_name, "type": input_tag.attrs.get("type", "text")})
                    
                    if details['inputs']:
                        all_forms.append(details)

                # Discover new links to visit on the same domain
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    absolute_link = urljoin(url, href)
                    if urlparse(absolute_link).netloc == netloc and absolute_link not in visited_pages:
                        pages_to_visit.add(absolute_link)

            except requests.exceptions.RequestException as e:
                print(f"Error crawling {url}: {e}")
                continue
    
    # --- FIX: Use a robust method to find unique forms ---
    unique_forms_list = []
    seen_signatures = set()
    for form in all_forms:
        try:
            # Create a unique signature based on action, method, and sorted input names
            input_names = tuple(sorted(i['name'] for i in form['inputs']))
            signature = (form['action'], form['method'], input_names)
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_forms_list.append(form)
        except (TypeError, KeyError):
            continue
            
    return unique_forms_list, list(visited_pages)


# --- Payloads & Error Signatures (UPGRADED) ---
SQLI_PAYLOADS = ["' OR 1=1 --", "' OR 'a'='a", "') OR ('a'='a", '" OR 1=1 --']
TIME_BASED_SQLI_PAYLOADS = [
    "' AND SLEEP(5)--",          # MySQL
    "' AND pg_sleep(5)--",        # PostgreSQL
    "' AND waitfor delay '0:0:5'--" # SQL Server
]
XSS_PAYLOAD = "<img src=x onerror=alert('WebAppScannerXSS')>" # UPGRADED PAYLOAD
SQL_ERROR_MESSAGES = [
    "you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch_array",
    "odbc driver error", "invalid query", "syntax error", "warning: mysql"
]


# --- Professional Core Scanning Logic (UPGRADED) ---
def scan_forms(forms):
    """
    Tests a list of discovered forms for SQLi and XSS vulnerabilities
    by testing ONE input field at a time with intelligent dummy data.
    """
    vulnerable_sqli = []
    vulnerable_xss = []
    
    with requests.Session() as s:
        s.headers['User-Agent'] = 'WebAppScanner/1.0'
        
        for form in forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            for input_to_test in inputs:
                if input_to_test.get('type') == 'submit': continue

                # --- UPGRADED: Test for SQL Injection (Error-Based and Time-Based) ---
                
                # 1. Test for Error-Based SQLi
                for payload in SQLI_PAYLOADS:
                    data = {}
                    for i in inputs:
                        dummy_data = "WebAppScannerTest"
                        if "email" in i['name'].lower(): dummy_data = "test@test.com"
                        if "password" in i['name'].lower(): dummy_data = "password123"
                        data[i['name']] = payload if i['name'] == input_to_test['name'] else dummy_data
                    
                    try:
                        res = s.post(action, data=data, timeout=5) if method == 'post' else s.get(action, params=data, timeout=5)
                        for error in SQL_ERROR_MESSAGES:
                            if error in res.text.lower():
                                vuln_details = {"url": action, "input_name": input_to_test['name'], "type": "Error-Based"}
                                if action not in [v['url'] for v in vulnerable_sqli]:
                                    vulnerable_sqli.append(vuln_details)
                                break 
                        if vulnerable_sqli and vulnerable_sqli[-1]['url'] == action: break 
                    except requests.exceptions.RequestException: continue
                if vulnerable_sqli and vulnerable_sqli[-1]['url'] == action: continue

                # 2. Test for Time-Based Blind SQLi
                for payload in TIME_BASED_SQLI_PAYLOADS:
                    data = {}
                    for i in inputs:
                        data[i['name']] = payload if i['name'] == input_to_test['name'] else "WebAppScannerTest"

                    try:
                        start_time = time.time()
                        res = s.post(action, data=data, timeout=10) if method == 'post' else s.get(action, params=data, timeout=10)
                        end_time = time.time()
                        
                        if (end_time - start_time) > 4:
                            vuln_details = {"url": action, "input_name": input_to_test['name'], "type": "Time-Based Blind"}
                            if action not in [v['url'] for v in vulnerable_sqli]:
                                vulnerable_sqli.append(vuln_details)
                            break 
                    except requests.exceptions.Timeout:
                        vuln_details = {"url": action, "input_name": input_to_test['name'], "type": "Time-Based Blind (Timeout)"}
                        if action not in [v['url'] for v in vulnerable_sqli]:
                             vulnerable_sqli.append(vuln_details)
                        break
                    except requests.exceptions.RequestException:
                        continue
                if vulnerable_sqli and vulnerable_sqli[-1]['url'] == action: continue

                # --- Test for XSS ---
                data = {}
                for i in inputs:
                    data[i['name']] = XSS_PAYLOAD if i['name'] == input_to_test['name'] else "WebAppScannerTest"

                try:
                    res = s.post(action, data=data, timeout=5) if method == 'post' else s.get(action, params=data, timeout=5)
                    if XSS_PAYLOAD in res.text:
                        vuln_details = {"url": action, "input_name": input_to_test['name']}
                        if action not in [v['url'] for v in vulnerable_xss]:
                            vulnerable_xss.append(vuln_details)
                except requests.exceptions.RequestException: continue

    return vulnerable_sqli, vulnerable_xss


def scan_url_parameters(urls):
    """
    Scans a list of URLs for vulnerabilities in their query parameters.
    """
    vulnerable_sqli_urls = []
    
    with requests.Session() as s:
        s.headers['User-Agent'] = 'WebAppScanner/1.0'
        
        for url in urls:
            parsed_url = urlparse(url)
            # Correctly parse parameters even if there are no values
            try:
                params = {k: v[0] for k, v in requests.utils.parse_qs(parsed_url.query).items()}
            except:
                continue

            if not params:
                continue # Skip URLs with no parameters

            for param_to_test in params.keys():
                # Test for Error-Based SQLi
                for payload in SQLI_PAYLOADS:
                    test_params = params.copy()
                    test_params[param_to_test] = payload
                    
                    try:
                        # Rebuild the URL without the query string for the GET request
                        url_without_query = parsed_url._replace(query="").geturl()
                        res = s.get(url_without_query, params=test_params, timeout=5)
                        for error in SQL_ERROR_MESSAGES:
                            if error in res.text.lower():
                                vuln_details = {"url": url, "parameter": param_to_test, "type": "Error-Based"}
                                if url not in [v['url'] for v in vulnerable_sqli_urls]:
                                    vulnerable_sqli_urls.append(vuln_details)
                                break
                        if vulnerable_sqli_urls and vulnerable_sqli_urls[-1]['url'] == url: break
                    except requests.exceptions.RequestException:
                        continue
                if vulnerable_sqli_urls and vulnerable_sqli_urls[-1]['url'] == url: break
                
    return vulnerable_sqli_urls


# --- UPGRADED: Other Scanning Functions ---
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': 'Enforces secure (HTTP over SSL/TLS) connections to the server.',
            'X-Content-Type-Options': 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
            'Content-Security-Policy': 'Helps to prevent Cross-Site Scripting (XSS), clickjacking, and other code injection attacks.',
            'X-Frame-Options': 'Provides clickjacking protection by not allowing the page to be embedded in a frame.'
        }

        missing_headers_details = []
        # --- NEW LOGIC: Check for CSP before flagging X-Frame-Options ---
        has_csp_frame_ancestors = 'Content-Security-Policy' in headers and 'frame-ancestors' in headers['Content-Security-Policy']

        for header, description in security_headers.items():
            if header not in headers:
                # If X-Frame-Options is missing but CSP with frame-ancestors is present, it's safe.
                if header == 'X-Frame-Options' and has_csp_frame_ancestors:
                    continue # Skip adding it to the missing list
                missing_headers_details.append(f"**{header}:** {description}")

        if missing_headers_details:
            details_text = " Missing Headers Details: " + " ".join(missing_headers_details)
            return {
                "finding": f"Missing {len(missing_headers_details)} critical security headers.",
                "details": "The server is not sending important security headers that protect against common attacks." + details_text,
                "recommendation": "Add the recommended security headers to your server's configuration to improve security posture.",
                "severity": "medium"
            }
        else:
            return {
                "finding": "All recommended security headers are present.",
                "details": "The application is configured with strong security headers.",
                "recommendation": "Regularly review and update your security headers to adapt to new threats.",
                "severity": "safe"
            }
    except requests.exceptions.RequestException as e:
        return {
            "finding": f"Error checking headers: {e}",
            "details": "Could not connect to the server to check for security headers.",
            "recommendation": "Ensure the URL is correct and the server is accessible.",
            "severity": "medium"
        }

def check_ssl_cert(url):
    """
    Validates the SSL/TLS certificate for the given URL's hostname,
    but only if the URL is HTTPS.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if parsed_url.scheme != 'https':
        return {
            "finding": "Site is not served over HTTPS",
            "details": "The connection to this website is not encrypted. Data sent between you and the site could be intercepted.",
            "recommendation": "Migrate the website to HTTPS by obtaining and installing an SSL/TLS certificate.",
            "severity": "medium"
        }

    if not hostname:
        return {"finding": "Invalid URL", "details": "Could not determine hostname from URL.", "recommendation": "Please provide a full URL.", "severity": "info"}
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return {
            "finding": f"SSL certificate is valid for {hostname}",
            "details": "The connection is encrypted and the certificate is trusted.",
            "recommendation": "Ensure your certificate is renewed before its expiration date.",
            "severity": "safe"
        }
    except Exception as e:
        return {
            "finding": f"SSL certificate check failed",
            "details": f"An error occurred: {e}. This could mean the certificate is expired, self-signed, or misconfigured.",
            "recommendation": "Obtain and correctly install a valid SSL certificate from a trusted Certificate Authority (CA).",
            "severity": "critical"
        }

def check_open_ports(url):
    """
    Performs a more intelligent port scan that includes a banner grab
    to help reduce false positives.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return {"finding": "Invalid URL", "details": "Could not determine hostname from URL.", "recommendation": "Please provide a full URL.", "severity": "info"}

    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP Alt'
    }
    open_ports_details = []

    try:
        ip_address = socket.gethostbyname(hostname)
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0) # Increased timeout slightly for banner grab
            result = sock.connect_ex((ip_address, port))
            
            if result == 0:
                # --- NEW LOGIC: Try to grab a banner ---
                try:
                    # Try to receive a small amount of data (the banner)
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                    if banner:
                         open_ports_details.append(f"{port} ({service}) - Banner: {banner[:30]}...") # Show first 30 chars
                    else:
                        # Port is open but sent no data.
                        # We will ignore Port 21 (FTP) in this case as it's a common false positive.
                        if port != 21:
                            open_ports_details.append(f"{port} ({service}) - Open (No Banner)")
                except socket.timeout:
                    # If we time out trying to receive data, it's likely not a real service.
                    if port != 21:
                         open_ports_details.append(f"{port} ({service}) - Open (No Response)")
                except Exception:
                    # Handle other potential errors during recv
                     if port != 21:
                        open_ports_details.append(f"{port} ({service}) - Open (Recv Error)")
            sock.close()

    except socket.gaierror:
        return {"finding": "Hostname could not be resolved", "details": "Could not find the IP address for the server.", "recommendation": "Ensure the domain name is correct and accessible.", "severity": "info"}
    except Exception as e:
        return {"finding": "An error occurred during port scan", "details": str(e), "recommendation": "Please try again later.", "severity": "info"}

    if open_ports_details:
        return {
            "finding": "Potentially unnecessary ports are open.",
            "details": f"Open ports found: {', '.join(open_ports_details)}.",
            "recommendation": "Ensure each open port is necessary. Unused ports should be closed by a firewall to reduce the attack surface.",
            "severity": "medium"
        }
    else:
        return {
            "finding": "No common high-risk ports are open.",
            "details": "The scanner did not find any open ports from its list of common services.",
            "recommendation": "Continue to practice good firewall hygiene and expose only necessary services to the internet.",
            "severity": "safe"
        }


# --- Flask Routes ---
@app.route('/')
def home(): return render_template('home.html')

@app.route('/login')
def login(): return render_template('login.html')

@app.route('/signup')
def signup(): return render_template('signup.html')


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form['url']
        scan_limit_message = None

        try:
            try:
                initial_response = requests.get(url, timeout=15)
                initial_response.raise_for_status()
            except requests.exceptions.RequestException as e:
                error_message = f"Failed to connect to {url}. The site may be down or blocking requests. Error: {e}"
                return render_template('index.html', error=error_message, url=url)

            # --- MODIFIED: The crawler now returns both forms and all discovered links ---
            forms, discovered_links = crawl_and_discover_forms(url)
            print(f"Crawler found {len(forms)} unique forms and {len(discovered_links)} links to test.")

            MAX_FORMS_TO_TEST = 10
            if len(forms) > MAX_FORMS_TO_TEST:
                print(f"WARNING: Too many forms found. Testing the first {MAX_FORMS_TO_TEST} forms only.")
                forms_to_scan = forms[:MAX_FORMS_TO_TEST]
                scan_limit_message = f"Note: The crawler discovered {len(forms)} forms. To ensure a timely response, this scan was limited to the first {MAX_FORMS_TO_TEST} found."
            else:
                forms_to_scan = forms

            # --- MODIFIED: Run both the form scanner and the new URL scanner ---
            vulnerable_sqli_forms, vulnerable_xss = scan_forms(forms_to_scan)
            vulnerable_sqli_urls = scan_url_parameters(discovered_links)

            # --- MODIFIED: Combine the results from both scans ---
            all_vulnerable_sqli = vulnerable_sqli_forms + vulnerable_sqli_urls
            
            if all_vulnerable_sqli:
                details_list = []
                for res in all_vulnerable_sqli:
                    if 'input_name' in res: # It's from a form
                        details_list.append(f"Form ({res['url'].split('/')[-1]} in input '{res['input_name']}')")
                    else: # It's from a URL
                        details_list.append(f"URL ({res['url']} in parameter '{res['parameter']}')")
                details_text = ", ".join(details_list)
                
                sql_injection_result = { "finding": f"Found {len(all_vulnerable_sqli)} SQLi vulnerabilities.", "details": "Vulnerable locations: " + details_text, "recommendation": "Use parameterized queries (Prepared Statements) to prevent user input from being executed as SQL code.", "severity": "critical" }
            else:
                sql_injection_result = { "finding": "No SQL Injection vulnerabilities found.", "details": "The application did not respond to basic SQLi probes in forms or URL parameters.", "recommendation": "Continue to use secure coding practices.", "severity": "safe" }

            if vulnerable_xss:
                details_text = ", ".join([f"{res['url'].split('/')[-1]} (in input '{res['input_name']}')" for res in vulnerable_xss])
                xss_result = { "finding": f"Found {len(vulnerable_xss)} XSS vulnerabilities.", "details": "Vulnerable Forms: " + details_text, "recommendation": "Implement context-aware output encoding for all user-supplied data.", "severity": "critical" }
            else:
                xss_result = { "finding": "No XSS vulnerabilities found.", "details": "The application does not seem to reflect basic script payloads in discovered forms.", "recommendation": "Continue to sanitize all user inputs.", "severity": "safe" }

            headers_result = check_security_headers(url)
            ssl_cert_result = check_ssl_cert(url)
            open_ports_result = check_open_ports(url)
            status_code = initial_response.status_code

            results = {
                'url': url, 'sql_injection': sql_injection_result, 'xss': xss_result,
                'headers': headers_result, 'ssl_cert': ssl_cert_result, 'open_ports': open_ports_result,
                'status_code': status_code, 'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            if 'history' not in session: session['history'] = []
            session['history'].insert(0, results)
            session.modified = True
            return render_template('index.html', results=results, url=url, scan_limit_message=scan_limit_message)

        except requests.exceptions.Timeout:
            error_message = f"Scan timed out. The website at {url} is responding too slowly."
            return render_template('index.html', error=error_message, url=url)
        except Exception as e:
            # We add a print statement here to see the real error in the terminal
            print(f"An unexpected error occurred in /scan: {e}") 
            error_message = f"An unexpected error occurred. Please check the terminal for details."
            return render_template('index.html', error=error_message, url=url)

    return render_template('index.html')


@app.route('/history')
def history():
    scan_history = session.get('history', [])
    return render_template('history.html', history=scan_history)

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        scan_history = session.get('history', [])
        if not scan_history: return "No scan history found.", 404
        scan_data = scan_history[0]
        rendered_html = render_template('report_template.html', data=scan_data)
        pdf = HTML(string=rendered_html).write_pdf()
        hostname = urlparse(scan_data.get('url', 'report')).hostname or 'report'
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=WebAppScanner_Report_{hostname}.pdf'
        return response
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return "Sorry, there was an error creating the PDF report.", 500

@app.route('/ask_assistant', methods=['POST'])
def ask_assistant():
    user_message = request.json.get('message')
    if not user_message: return jsonify({'error': 'No message provided'}), 400
    API_KEY = "AIzaSyC2pVpje6XInu6Z9UK6X4LXh1dApScNifs"
    API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={API_KEY}"
    system_prompt = "You are a friendly and helpful Web Security Assistant..."
    payload = { "contents": [{"parts": [{"text": user_message}]}], "systemInstruction": {"parts": [{"text": system_prompt}]}, }
    try:
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        data = response.json()
        bot_response = data['candidates'][0]['content']['parts'][0]['text']
        return jsonify({'response': bot_response})
    except Exception as e:
        return jsonify({'error': f'API request failed: {e}'}), 500

if __name__ == "__main__":
    app.run(debug=True)