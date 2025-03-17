
---

## Description

**SQLiScanner** is an advanced and highly customizable tool designed for SQL injection vulnerability scanning. It is capable of detecting various types of SQL injection vulnerabilities including error-based, boolean-based, time-based, union-based, and stacked queries. The scanner uses machine learning to enhance detection accuracy and can discover URLs and forms, making it an all-in-one solution for detecting vulnerabilities in web applications.

This tool supports multi-threading for efficient scanning, integrates with external tools like `waybackurls` for discovering URLs, and provides detailed vulnerability reports with severity levels and confidence scores. It also includes prevention tips for mitigating detected vulnerabilities.

---

## Features

- **Multi-threaded Scanning**: Scan multiple URLs and forms simultaneously for faster vulnerability detection.
- **SQL Injection Detection**: Supports various injection techniques like error-based, boolean-based, time-based, union-based, and stacked queries.
- **Machine Learning Model**: Utilizes a pre-trained model (RandomForestClassifier) to help identify potential SQL injection vulnerabilities.
- **URL and Form Discovery**: Automatically discovers URLs with parameters using `waybackurls` and crawls web pages to find forms.
- **Detailed Reports**: Generates a comprehensive report with detailed vulnerability information including URL, parameter, payload, severity, and confidence.
- **Prevention Tips**: Provides actionable steps to prevent SQL injection attacks based on the detected vulnerability type.
- **Verbose Mode**: Option to enable detailed logging for in-depth troubleshooting and analysis.

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/komal0x01/SQLiScanner
   cd SQLiScanner
   ```

2. **Install Dependencies**:
   The required Python libraries can be installed using `pip`:
   ```bash
   pip install -r requirements.txt
   ```

   **Dependencies**:
   - `requests`
   - `beautifulsoup4`
   - `validators`
   - `colorama`
   - `sklearn`
   - `numpy`
   - `threading`
   - `subprocess`

3. **Install `waybackurls` Tool**:
   This tool requires `waybackurls` for URL discovery. You can install it by running:
   ```bash
   go install github.com/tomnomnom/waybackurls@latest
   ```

---

## Usage

1. **Run the Scanner**:
   After installation, run the scanner by executing the Python script:
   ```bash
   python3 SQLi.py
   ```

2. **Input Parameters**:
   The tool will prompt you to input:
   - Target domain (e.g., example.com)
   - Enable verbose mode (yes/no)
   - Number of threads (default: 10)
   - Delay between requests (default: 1 second)

3. **View Results**:
   The tool will print results in real-time, including the detected vulnerabilities and their severity. At the end of the scan, it will generate a detailed report of all findings.

---

## Example

```bash
$ python3 SQLi.py
Enter the target domain (e.g., example.com): example.com
Enable verbose mode? (yes/no): no
Enter the number of threads (default 10): 10
Enter the delay between requests (default 1 second): 1
```

---

## Report Example

```
[!] Critical severity SQL injection vulnerability detected!
URL: http://example.com/product?id=1
Parameter: id
Payload: ' OR '1'='1
Type: error-based
Confidence: 95.60%
Response: MySQL syntax error...
--------------------------------------------------
```


