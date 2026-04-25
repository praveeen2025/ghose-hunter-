#!/usr/bin/env python3
"""
🔐 AI Web Vulnerability Scanner (PRO & ZAP Edition) - ADVANCED AI INTEGRATED
============================================================================
Automated Web Vulnerability Scanner for Ethical Hackers
  • SQL Injection, XSS, Command Injection, Directory Traversal
  • SSRF, XXE, Security Misconfiguration (Deep SSL Check)
  • 🆕 ADVANCED AI-POWERED ANALYSIS (Diff-Logic & Similarity Heuristics)
  • CVSS Risk Scoring & OWASP Top 10 Mapping
  • Tests BOTH GET and POST Methods
  • Multi-format Report Generation (HTML, AI-JSON, Text)
  • ADVANCED MULTI-THREADED PORT SCANNING
  • OWASP ZAP INTEGRATION (Active & Passive Scanning)
  • 🆕 CUSTOM PAYLOAD LIMIT SELECTION

⚠️  DISCLAIMER: For AUTHORIZED ethical hacking and security
    assessment ONLY. Unauthorized scanning is ILLEGAL.
"""

import requests
import socket
import ssl
import re
import json
import time
import random
import hashlib
import urllib.parse
import os
import sys
import threading
import queue
import difflib
from datetime import datetime
from html import escape as html_escape
from collections import defaultdict

# Try importing cryptography for Deep SSL Check
try:
    from cryptography import x509
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# ──────────────────────────────────────────────
# SECTION 1: CONFIGURATION & CONSTANTS
# ──────────────────────────────────────────────

VERSION = "1.2.0-PAYLOAD-LIMIT"
USER_AGENT = "AI-VulnScanner/1.2"
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0.2
MAX_REDIRECTS = 5
MAX_THREADS = 100

# Payload Limit Presets
PAYLOAD_PRESETS = {
    "quick": 10,       # Quick scan - 10 payloads per category
    "low": 25,         # Low intensity - 25 payloads
    "medium": 50,      # Medium intensity - 50 payloads
    "high": 100,       # High intensity - 100 payloads
    "extreme": 250,    # Extreme - 250 payloads
    "all": 0           # All payloads (0 = no limit)
}

SEVERITY_LEVELS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

CVSS_BASE_SCORES = {
    "sql_injection": 9.8, "xss": 6.1, "command_injection": 9.8,
    "directory_traversal": 7.5, "xxe": 8.6, "ssrf": 8.6,
    "security_misconfig": 5.3, "csrf": 4.3, "zap_alert": 7.5
}

OWASP_MAPPING = {
    "sql_injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "command_injection": "A03:2021 - Injection",
    "directory_traversal": "A01:2021 - Broken Access Control",
    "xxe": "A05:2021 - Security Misconfiguration",
    "ssrf": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "security_misconfig": "A05:2021 - Security Misconfiguration",
    "csrf": "A01:2021 - Broken Access Control",
    "zap_alert": "Dynamic Analysis"
}

PREVENTION_RECOMMENDATIONS = {
    "sql_injection": ["Use Prepared Statements", "Use ORM frameworks", "Validate input"],
    "xss": ["Use output encoding", "Implement Content Security Policy", "Sanitize HTML"],
    "command_injection": ["Avoid system shell functions", "Use language-specific APIs"],
    "directory_traversal": ["Validate file paths", "Use allowlists", "Disable direct file access"],
    "xxe": ["Disable external entities in XML parsers", "Use JSON"],
    "ssrf": ["Block internal IP addresses", "Sanitize URLs"],
    "security_misconfig": ["Update software", "Remove default pages", "Harden SSL config"],
    "csrf": ["Implement anti-CSRF tokens", "Use SameSite cookies"],
    "zap_alert": ["Review OWASP ZAP report for specific context"]
}

# ──────────────────────────────────────
# SECTION 2: DISPLAY UTILITIES
# ──────────────────────────────────────

class Display:
    @staticmethod
    def _c(color, text):
        if HAS_COLORAMA:
            colors = {
                "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW, 
                "blue": Fore.BLUE, "cyan": Fore.CYAN, "magenta": Fore.MAGENTA, 
                "white": Fore.WHITE, "reset": Style.RESET_ALL, 
                "bright_red": Fore.RED + Style.BRIGHT, "bright_blue": Fore.BLUE + Style.BRIGHT, 
                "bright_cyan": Fore.CYAN + Style.BRIGHT, "bright_green": Fore.GREEN + Style.BRIGHT, 
                "bright_magenta": Fore.MAGENTA + Style.BRIGHT,
                "gray": Fore.LIGHTBLACK_EX
            }
            return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"
        return str(text)

    @staticmethod
    def info(msg): print(f"  {Display._c('cyan', '[*]')} {msg}")
    @staticmethod
    def success(msg): print(f"  {Display._c('green', '[+]')} {msg}")
    @staticmethod
    def warning(msg): print(f"  {Display._c('yellow', '[!]')} {msg}")
    @staticmethod
    def error(msg): print(f"  {Display._c('red', '[-]')} {msg}")
    @staticmethod
    def critical(msg): print(f"  {Display._c('bright_red', '[!!!]')} {Display._c('bright_red', msg)}")

    @staticmethod
    def header(msg):
        print(f"\n  {Display._c('magenta', '═' * 60)}")
        print(f"  {Display._c('magenta', msg.center(60))}")
        print(f"  {Display._c('magenta', '═' * 60)}\n")

    @staticmethod
    def section(msg): print(f"\n  {Display._c('blue', '─── ' + msg + ' ───')}")

    @staticmethod
    def progress(current, total, msg=""):
        pct = int((current / total) * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        sys.stdout.write(f"\r  {Display._c('cyan', f'[{bar}]')} {pct}% {msg}")
        sys.stdout.flush()
        if current == total: print()

    @staticmethod
    def banner():
        v = "v" + VERSION
        banner_top = f"""
        
                                                                 
          {Display._c('bright_red',        '██████╗  ██╗  ██╗ ██████╗ ███████╗████████╗')}
         {Display._c('bright_red',        '██╔════╝  ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝')} 
         {Display._c('bright_red',        '██║  ███╗ ███████║██║   ██║███████╗   ██║   ')} 
         {Display._c('bright_red',        '██║   ██║ ██╔══██║██║   ██║╚════██║   ██║   ')} 
         {Display._c('bright_red',        '╚██████╔╝ ██║  ██║╚██████╔╝███████║   ██║   ')} 
         {Display._c('bright_red',        ' ╚═════╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ')} 
"""         
        banner_bottom = f"""
       {Display._c('red',     '██╗  ██╗ ██╗   ██╗ ███╗   ██╗████████╗███████╗██████╗ ')}  
       {Display._c('red',    '██║  ██║ ██║   ██║ ████╗  ██║╚══██╔══╝██╔════╝██╔══██╗')}  
       {Display._c('red',     '███████║ ██║   ██║ ██╔██╗ ██║   ██║   █████╗  ██████╔╝')} 
       {Display._c('red',     '██╔══██║ ██║   ██║ ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗')}  
       {Display._c('red',     '██║  ██║ ╚██████╔╝ ██║ ╚████║   ██║   ███████╗██║  ██║')}  
       {Display._c('red',     '╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝')}  
"""
        print(banner_top)
        print(banner_bottom)
        print(f"  {Display._c('red', '╔════════════════════════════════════════════════════════════════════════╗')}")
        print(Display._c('red', f'  ║  {Display._c("bright_blue", f"  {v}  |  Diff-Based AI  |  Payload Limiter")}      ║'))
        print(Display._c('red', f'  ║  {Display._c("bright_green", "  Custom Payload Count  |  Deep-SSL  |  OWASP Top 10  ")}   ║'))
        print(f"  {Display._c('red', '╚════════════════════════════════════════════════════════════════════════╝')}\n")
        print()

# ──────────────────────────────────────
# SECTION 3: PAYLOAD DATABASE (WITH LIMIT SUPPORT)
# ──────────────────────────────────────

class PayloadDatabase:
    BASE_DIR = "payloads"

    @staticmethod
    def _load(file_name):
        path = os.path.join(PayloadDatabase.BASE_DIR, file_name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            Display.error(f"Missing payload file: {path}")
            return []

    @staticmethod
    def _generate_variations(payloads):
        all_payloads = list(payloads)
        for p in payloads:
            encoded = urllib.parse.quote(p)
            if encoded != p:
                all_payloads.append(encoded)
        return all_payloads

    @staticmethod
    def _apply_limit(payloads, limit):
        """Apply payload limit. limit=0 means no limit (return all)"""
        if limit and limit > 0:
            return payloads[:limit]
        return payloads

    @classmethod
    def get_sqli_payloads(cls, limit=0):
        return cls._apply_limit(cls._generate_variations(cls._load("sqli.txt")), limit)
    
    @classmethod
    def get_xss_payloads(cls, limit=0):
        return cls._apply_limit(cls._generate_variations(cls._load("xss.txt")), limit)
    
    @classmethod
    def get_dir_traversal_payloads(cls, limit=0):
        return cls._apply_limit(cls._generate_variations(cls._load("lfi.txt")), limit)
    
    @classmethod
    def get_cmd_injection_payloads(cls, limit=0):
        return cls._apply_limit(cls._generate_variations(cls._load("cmd.txt")), limit)
    
    @classmethod
    def get_xxe_payloads(cls, limit=0):
        return cls._apply_limit(cls._load("xxe.txt"), limit)
    
    @classmethod
    def get_ssrf_payloads(cls, limit=0):
        return cls._apply_limit(cls._load("ssrf.txt"), limit)
    
    @classmethod
    def get_misconfig_payloads(cls, limit=0):
        return cls._apply_limit(cls._load("misconfig.txt"), limit)

    @classmethod
    def get_total_count(cls, limit=0):
        return (
            len(cls.get_sqli_payloads(limit)) + len(cls.get_xss_payloads(limit)) +
            len(cls.get_dir_traversal_payloads(limit)) + len(cls.get_cmd_injection_payloads(limit)) +
            len(cls.get_xxe_payloads(limit)) + len(cls.get_ssrf_payloads(limit)) +
            len(cls.get_misconfig_payloads(limit))
        )

    @classmethod
    def get_all_payloads_info(cls, limit=0):
        """Return detailed info about all payload categories"""
        return {
            "SQL Injection": len(cls.get_sqli_payloads(limit)),
            "XSS": len(cls.get_xss_payloads(limit)),
            "Command Injection": len(cls.get_cmd_injection_payloads(limit)),
            "Directory Traversal": len(cls.get_dir_traversal_payloads(limit)),
            "XXE": len(cls.get_xxe_payloads(limit)),
            "SSRF": len(cls.get_ssrf_payloads(limit)),
            "Security Misconfig": len(cls.get_misconfig_payloads(limit))
        }

# ──────────────────────────────────────
# SECTION 3.5: PAYLOAD LIMIT SELECTOR
# ──────────────────────────────────────

class PayloadLimitSelector:
    """Interactive payload limit selection menu"""
    
    @staticmethod
    def show_menu():
        """Display payload limit selection menu"""
        Display.header("PAYLOAD LIMIT SELECTION")
        print(f"  {Display._c('cyan', 'Select how many payloads to use PER vulnerability category:')}")
        print()
        print(f"  {Display._c('yellow', '╔═══════════════════════════════════════════════════════════════╗')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[1]')}  {Display._c('white', 'Quick Scan      ')} {Display._c('cyan', '(10 payloads)    - ~1 min   ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[2]')}  {Display._c('white', 'Low Intensity   ')} {Display._c('cyan', '(25 payloads)    - ~3 min   ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[3]')}  {Display._c('white', 'Medium Intensity')} {Display._c('cyan', '(50 payloads)    - ~5 min   ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[4]')}  {Display._c('white', 'High Intensity  ')} {Display._c('cyan', '(100 payloads)   - ~10 min  ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[5]')}  {Display._c('white', 'Extreme         ')} {Display._c('cyan', '(250 payloads)   - ~25 min  ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[6]')}  {Display._c('white', 'ALL Payloads    ')} {Display._c('cyan', '(No limit)      - ~60+ min ')}  {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '║')}  {Display._c('bright_green', '[7]')}  {Display._c('white', 'Custom Number   ')} {Display._c('cyan', '(Enter your own)')}             {Display._c('yellow', '║')}")
        print(f"  {Display._c('yellow', '╚═══════════════════════════════════════════════════════════════╝')}")
        print()
        
    @staticmethod
    def get_limit():
        """Get payload limit from user input"""
        PayloadLimitSelector.show_menu()
        
        while True:
            choice = input(f"  {Display._c('bright_green', 'Select payload count option > ')}").strip()
            
            if choice == "1":
                limit = PAYLOAD_PRESETS["quick"]
                preset_name = "Quick (10)"
            elif choice == "2":
                limit = PAYLOAD_PRESETS["low"]
                preset_name = "Low (25)"
            elif choice == "3":
                limit = PAYLOAD_PRESETS["medium"]
                preset_name = "Medium (50)"
            elif choice == "4":
                limit = PAYLOAD_PRESETS["high"]
                preset_name = "High (100)"
            elif choice == "5":
                limit = PAYLOAD_PRESETS["extreme"]
                preset_name = "Extreme (250)"
            elif choice == "6":
                limit = PAYLOAD_PRESETS["all"]
                preset_name = "ALL (No Limit)"
            elif choice == "7":
                while True:
                    custom = input(f"  {Display._c('bright_cyan', 'Enter number of payloads (1-9999, or 0 for all) > ')}").strip()
                    try:
                        custom_num = int(custom)
                        if custom_num >= 0:
                            limit = custom_num
                            preset_name = f"Custom ({custom_num})" if custom_num > 0 else "ALL (No Limit)"
                            break
                        else:
                            Display.error("Please enter a positive number or 0")
                    except ValueError:
                        Display.error("Invalid number")
            else:
                Display.error("Invalid choice, try again")
                continue
            
            # Show summary
            PayloadLimitSelector.show_summary(limit, preset_name)
            
            confirm = input(f"  {Display._c('bright_yellow', 'Use this payload limit? (Y/n) > ')}").strip().lower()
            if confirm in ['', 'y', 'yes']:
                return limit, preset_name
            else:
                Display.info("Let's try again...")
                print()
    
    @staticmethod
    def show_summary(limit, preset_name):
        """Show summary of selected payload limit"""
        info = PayloadDatabase.get_all_payloads_info(limit)
        total = sum(info.values())
        
        Display.section(f"PAYLOAD SUMMARY: {preset_name}")
        print(f"  {Display._c('bright_cyan', f'{'Category':<25} {'Payloads':>10}')}")
        print(f"  {Display._c('gray', '─' * 38)}")
        for category, count in info.items():
            print(f"  {Display._c('white', f'{category:<25} {count:>10}')}")
        print(f"  {Display._c('gray', '─' * 38)}")
        print(f"  {Display._c('bright_green', f'{'TOTAL':<25} {total:>10}')}")
        
        # Estimate time (rough estimate: 0.2s per payload)
        if limit > 0:
            est_time = total * DELAY_BETWEEN_REQUESTS
            if est_time < 60:
                time_str = f"~{est_time:.0f} seconds"
            else:
                time_str = f"~{est_time/60:.1f} minutes"
            print(f"  {Display._c('yellow', f'Estimated scan time: {time_str}')}")
        else:
            print(f"  {Display._c('yellow', 'Estimated scan time: Variable (full scan)')}")
        print()

# ──────────────────────────────────────
# SECTION 4: ADVANCED PORT SCANNER
# ──────────────────────────────────────

class AdvancedPortScanner:
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 10000]

    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.lock = threading.Lock()

    def _scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                with self.lock:
                    self.open_ports.append(port)
                    Display.success(f"Port {port}: OPEN ({service})")
            sock.close()
        except Exception:
            pass

    def start_scan(self):
        Display.info(f"Starting Multi-threaded Port Scan on {self.target}...")
        threads = []
        for port in self.COMMON_PORTS:
            t = threading.Thread(target=self._scan_port, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        return self.open_ports

# ──────────────────────────────────────
# SECTION 5: ZAP SCANNER
# ──────────────────────────────────────

class ZAPScanner:
    def __init__(self, target_url, zap_host='127.0.0.1', zap_port=8080, api_key=''):
        self.target_url = target_url
        self.zap_url = f"http://{zap_host}:{zap_port}"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False

    def _zap_request(self, endpoint):
        try:
            url = f"{self.zap_url}{endpoint}"
            if self.api_key: url += f"&apikey={self.api_key}"
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                try: return resp.json()
                except ValueError: return {"message": resp.text}
        except Exception: pass
        return None

    def check_connection(self):
        data = self._zap_request("/JSON/core/view/version/")
        if data:
            Display.success(f"Connected to ZAP: v{data.get('version', 'Unknown')}")
            return True
        return False

    def run_spider(self):
        Display.info("Starting ZAP Spider...")
        resp = self._zap_request(f"/JSON/spider/action/scan/?url={urllib.parse.quote(self.target_url)}&maxChildren=10&recurse=false")
        if resp and 'scan' in resp:
            scan_id = resp['scan']
            while True:
                status = self._zap_request(f"/JSON/spider/view/status/?scanId={scan_id}")
                if status and 'status' in status:
                    pct = int(status['status'])
                    Display.progress(pct, 100, "ZAP Spider")
                    if pct >= 100:
                        Display.success("Spider Complete")
                        break
                time.sleep(2)
        return []

    def run_active_scan(self):
        Display.info("Starting ZAP Active Scan (This may take time)...")
        resp = self._zap_request(f"/JSON/ascan/action/scan/?url={urllib.parse.quote(self.target_url)}&recurse=true")
        if resp and 'scan' in resp:
            scan_id = resp['scan']
            while True:
                status = self._zap_request(f"/JSON/ascan/view/status/?scanId={scan_id}")
                if status and 'status' in status:
                    pct = int(status['status'])
                    Display.progress(pct, 100, f"ZAP Active Scan")
                    if pct >= 100:
                        Display.success("Active Scan Complete")
                        break
                time.sleep(2)
        return self.fetch_alerts()

    def fetch_alerts(self):
        Display.info("Fetching ZAP Alerts...")
        vulns = []
        resp = self._zap_request(f"/JSON/core/view/alerts/?baseurl={urllib.parse.quote(self.target_url)}")
        if resp and 'alerts' in resp:
            for alert in resp['alerts']:
                risk_map = {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Info"}
                severity = risk_map.get(alert.get('risk'), "Info")
                vulns.append({
                    "id": f"ZAP-{alert.get('pluginId')}", "type": "zap_alert", "name": alert.get('name', "ZAP Alert"),
                    "severity": severity, "cvss_score": 5.0 if severity == "Medium" else 8.5 if severity == "High" else 3.0,
                    "url": alert.get('url', self.target_url), "parameter": alert.get('param', "N/A"),
                    "payload": "", "evidence": alert.get('evidence', ""), "response_snippet": alert.get('attack', ""),
                    "status_code": 200, "timestamp": datetime.now().isoformat(), "confidence": 0.9,
                    "ai_reasoning": "Identified by OWASP ZAP"
                })
                Display.critical(f"[ZAP] {alert.get('name')} ({severity})")
        return vulns

    def run_full_zap_scan(self):
        if not self.check_connection():
            Display.error("Cannot connect to ZAP API.")
            return []
        self.run_spider()
        return self.run_active_scan()

# ──────────────────────────────────────
# SECTION 6: RECONNAISSANCE ENGINE
# ──────────────────────────────────────

class ReconnaissanceEngine:
    FRAMEWORK_SIGNATURES = {"WordPress": ["/wp-content/", "/wp-includes/", "wp-login.php"], "Laravel": ["laravel_session"], "React": ["react", "__NEXT_DATA__"], "Angular": ["ng-version", "angular"], "Vue.js": ["vue", "__vue__"], "Django": ["csrfmiddlewaretoken", "django"], "Express": ["X-Powered-By: Express"], "ASP.NET": ["X-AspNet-Version", "__VIEWSTATE"]}
    WAF_SIGNATURES = {"Cloudflare": ["cf-ray", "cloudflare"], "AWS WAF": ["awselb", "x-amzn-requestid"], "ModSecurity": ["Mod_Security", "mod_security"], "Sucuri": ["Sucuri", "X-Sucuri-ID"], "Akamai": ["AkamaiGHost"]}
    SECURITY_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]

    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.recon_data = {"url": target_url, "timestamp": datetime.now().isoformat(), "ip_address": None, "server": None, "frameworks": [], "waf": [], "open_ports": [], "security_headers": {}, "missing_headers": [], "ssl_info": {}, "cookies": [], "forms": []}

    def run_full_recon(self):
        Display.header("RECONNAISSANCE & FINGERPRINTING")
        Display.info("Resolving target IP..."); self._resolve_ip()
        Display.info("Fetching HTTP response..."); self._fetch_response()
        Display.info("Detecting frameworks..."); self._detect_frameworks()
        Display.info("Detecting WAF..."); self._detect_waf()
        Display.info("Checking security headers..."); self._check_security_headers()
        Display.info("Analyzing Deep SSL/TLS Certificate Strength..."); self._check_ssl()
        Display.info("Extracting forms..."); self._extract_forms()
        self._display_recon_summary()
        return self.recon_data

    def _resolve_ip(self):
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            ip = socket.gethostbyname(parsed.hostname or parsed.path)
            self.recon_data["ip_address"] = ip; Display.success(f"IP Address: {ip}")
        except socket.gaierror: Display.error("Could not resolve hostname")

    def _fetch_response(self):
        try:
            resp = self.session.get(self.target_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
            self.recon_data["status_code"] = resp.status_code
            self.recon_data["server"] = resp.headers.get("Server", "Unknown")
            self.recon_data["response_headers"] = dict(resp.headers)
            self.recon_data["page_content"] = resp.text
            self.recon_data["cookies"] = [{"name": c.name, "value": c.value[:20]+"...", "secure": c.secure, "httponly": c.has_nonstandard_attr('httponly')} for c in resp.cookies]
            Display.success(f"Server: {self.recon_data['server']} | Status: {resp.status_code}")
        except requests.RequestException as e: Display.error(f"Request failed: {e}")

    def _detect_frameworks(self):
        content = self.recon_data.get("page_content", "").lower()
        headers = str(self.recon_data.get("response_headers", {})).lower()
        for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
            if any(s.lower() in content or s.lower() in headers for s in sigs):
                self.recon_data["frameworks"].append(fw); Display.success(f"Framework: {fw}")

    def _detect_waf(self):
        headers = str(self.recon_data.get("response_headers", {})).lower()
        for waf, sigs in self.WAF_SIGNATURES.items():
            if any(s.lower() in headers for s in sigs):
                self.recon_data["waf"].append(waf); Display.warning(f"WAF: {waf}")

    def _check_security_headers(self):
        headers = self.recon_data.get("response_headers", {})
        for h in self.SECURITY_HEADERS:
            if h in headers: self.recon_data["security_headers"][h] = headers[h]
            else: self.recon_data["missing_headers"].append(h)
        Display.warning(f"Missing Headers: {len(self.recon_data['missing_headers'])}")

    def _check_ssl(self):
        if not HAS_CRYPTO:
            Display.warning("Cryptography library not installed. Skipping Deep SSL Check.")
            return
        Display.info("Analyzing Deep SSL/TLS Certificate Strength...")
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            hostname = parsed.hostname or parsed.path
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert)
                    pub_key = cert.public_key().key_size
                    key_strength = "Strong" if pub_key >= 4096 else ("Weak" if pub_key >= 2048 else "Very Weak")
                    sig_alg = getattr(cert.signature_hash_algorithm, '_name', 'Unknown')
                    expiry_date = cert.not_valid_after_utc
                    days_left = (expiry_date - datetime.now()).days
                    expiry_status = "Valid" if days_left > 30 else ("Expiring Soon" if days_left > 0 else "EXPIRED")
                    tls_version = ssock.version()
                    tls_ok = tls_version in ["TLSv1.2", "TLSv1.3"]
                    
                    self.recon_data["ssl_info"] = {"protocol": tls_version, "tls_ok": tls_ok, "cert_key_size": pub_key, "key_strength": key_strength, "valid_until": expiry_date.strftime("%Y-%m-%d"), "days_left": days_left, "expiry_status": expiry_status}
                    Display.success(f"Protocol: {tls_version} ({'Secure' if tls_ok else 'Insecure'})")
        except Exception as e: Display.info(f"SSL deep check skipped: {e}")

    def _extract_forms(self):
        if not HAS_BS4: return
        soup = BeautifulSoup(self.recon_data.get("page_content", ""), "html.parser")
        for form in soup.find_all("form"):
            inputs = [{"name": i.get("name", ""), "type": i.get("type", "text")} for i in form.find_all(["input", "textarea"]) if i.get("name")]
            if inputs:
                self.recon_data["forms"].append({"action": form.get("action", ""), "method": form.get("method", "GET").upper(), "inputs": inputs})
                Display.success(f"Form: {form.get('method')} {form.get('action')} ({len(inputs)} inputs)")

    def _display_recon_summary(self):
        Display.section("RECON SUMMARY")
        print(f"  Target: {self.recon_data['url']} | IP: {self.recon_data.get('ip_address', 'N/A')}")
        print(f"  Server: {self.recon_data.get('server', 'N/A')} | WAF: {', '.join(self.recon_data['waf']) or 'None'}")

# ──────────────────────────────────────
# SECTION 7: VULNERABILITY DETECTION ENGINE (WITH LIMIT SUPPORT)
# ──────────────────────────────────────

class VulnerabilityDetector:
    SQL_ERR = [r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?", r"PostgreSQL.*?ERROR", r"ORA-\d{4,5}", r"Microsoft SQL Server", r"Unclosed quotation mark"]
    XSS_IND = [r"<script[^>]*>.*?alert\(", r"onerror\s*=", r"onload\s*="]
    LFI_IND = [r"root:x:0:0:", r"\[boot loader\]", r"nobody:x:"]
    CMD_IND = [r"uid=\d+", r"gid=\d+", r"drwx[rwx-]+"]

    def __init__(self, target_url, session, recon_data, payload_limit=0):
        self.url = target_url
        self.session = session
        self.recon = recon_data
        self.payload_limit = payload_limit
        self.vulns = []
        self.baseline_len = 0
        self.baseline_text = ""
        self.reqs = 0

    def _get_baseline(self):
        try:
            r = self.session.get(self.url, timeout=REQUEST_TIMEOUT, verify=False)
            self.baseline_len = len(r.text)
            self.baseline_text = r.text
        except: pass

    def _req(self, url, method="GET", params=None, data=None, headers=None):
        self.reqs += 1
        try:
            if method == "GET": return self.session.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            return self.session.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        except: return None

    def _inject(self, point, payload):
        if point["type"] == "param":
            if point["method"] == "POST":
                return self._req(self.url, "POST", data={point["name"]: payload})
            parsed = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed.query)
            params[point["name"]] = [payload]
            new_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(params, doseq=True), parsed.fragment))
            return self._req(new_url, "GET")
        elif point["type"] == "form":
            data = {i["name"]: payload for i in point["data"]["inputs"] if i["type"] not in ["submit"]}
            if not data: return None
            return self._req(self.url, point["data"]["method"], data=data)
        return None

    def _get_points(self):
        pts = []
        parsed = urllib.parse.urlparse(self.url)
        for p in urllib.parse.parse_qs(parsed.query): pts.append({"type": "param", "name": p, "method": "GET"})
        for f in self.recon.get("forms", []): pts.append({"type": "form", "data": f, "method": f["method"]})
        if not pts:
            for p in ["id", "q", "search"]: 
                pts.append({"type": "param", "name": p, "method": "GET"})
                pts.append({"type": "param", "name": p, "method": "POST"})
        return pts

    def _add(self, vtype, name, sev, cvss, point, payload, evidence, snippet="", status_code=200):
        self.vulns.append({
            "id": f"VULN-{len(self.vulns)+1:04d}", "type": vtype, "name": name, "severity": sev, 
            "cvss_score": cvss, "url": self.url, "parameter": point.get("name", "form"), 
            "payload": payload, "method": point.get("method", "N/A"), "evidence": evidence, 
            "response_snippet": snippet, "status_code": status_code, 
            "test_point": point, "timestamp": datetime.now().isoformat(), "confidence": 0.5
        })
        Display.critical(f"[{sev}] {name} | {payload[:40]}")

    def scan_sqli(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"SQL INJECTION SCAN{limit_str}")
        payloads = PayloadDatabase.get_sqli_payloads(self.payload_limit)
        pts = self._get_points()
        c = 0; t = len(payloads)*len(pts)
        Display.info(f"Testing {len(payloads)} payloads across {len(pts)} injection points")
        for pt in pts:
            for p in payloads:
                c += 1
                if c % 50 == 0: Display.progress(c, t, "SQLi")
                r = self._inject(pt, p)
                if not r: continue
                if any(re.search(e, r.text, re.I) for e in self.SQL_ERR): self._add("sql_injection", "SQL Injection", "Critical", 9.8, pt, p, "SQL Error Matched", r.text[:300], status_code=r.status_code)
                elif "SLEEP" in p.upper() and r.elapsed.total_seconds() >= 4.5: self._add("sql_injection", "SQLi (Time)", "Critical", 9.1, pt, p, f"Delay {r.elapsed.total_seconds():.1f}s", status_code=r.status_code)
                elif " OR 1=1" in p and abs(len(r.text) - self.baseline_len) > 100: self._add("sql_injection", "SQLi (Boolean)", "Critical", 9.8, pt, p, "Response Length Changed", status_code=r.status_code)
                time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_xss(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"XSS SCAN{limit_str}")
        payloads = PayloadDatabase.get_xss_payloads(self.payload_limit)
        pts = self._get_points()
        c = 0; t = len(payloads)*len(pts)
        Display.info(f"Testing {len(payloads)} payloads across {len(pts)} injection points")
        for pt in pts:
            for p in payloads:
                c += 1
                if c % 50 == 0: Display.progress(c, t, "XSS")
                r = self._inject(pt, p)
                if r and p in r.text: self._add("xss", "XSS (Reflected)", "High", 6.1, pt, p, "Payload Reflected in Response", r.text[:300], status_code=r.status_code)
                time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_cmd(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"COMMAND INJECTION SCAN{limit_str}")
        payloads = PayloadDatabase.get_cmd_injection_payloads(self.payload_limit)
        pts = self._get_points()
        c = 0; t = len(payloads)*len(pts)
        Display.info(f"Testing {len(payloads)} payloads across {len(pts)} injection points")
        for pt in pts:
            for p in payloads:
                c += 1
                if c % 50 == 0: Display.progress(c, t, "CmdInj")
                r = self._inject(pt, p)
                if not r: continue
                if "sleep" in p.lower() and r.elapsed.total_seconds() >= 4.5: self._add("command_injection", "Cmd Injection (Time)", "Critical", 9.8, pt, p, f"Delay {r.elapsed.total_seconds():.1f}s", status_code=r.status_code)
                elif any(re.search(e, r.text, re.I) for e in self.CMD_IND): self._add("command_injection", "Cmd Injection", "Critical", 9.8, pt, p, "Command Output Matched", r.text[:300], status_code=r.status_code)
                time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_lfi(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"DIRECTORY TRAVERSAL SCAN{limit_str}")
        payloads = PayloadDatabase.get_dir_traversal_payloads(self.payload_limit)
        pts = self._get_points()
        c = 0; t = len(payloads)*len(pts)
        Display.info(f"Testing {len(payloads)} payloads across {len(pts)} injection points")
        for pt in pts:
            for p in payloads:
                c += 1
                if c % 30 == 0: Display.progress(c, t, "LFI")
                r = self._inject(pt, p)
                if r and any(re.search(e, r.text, re.I) for e in self.LFI_IND): self._add("directory_traversal", "Dir Traversal", "High", 7.5, pt, p, "File Content Matched", r.text[:300], status_code=r.status_code)
                time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_xxe(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"XXE INJECTION SCAN{limit_str}")
        payloads = PayloadDatabase.get_xxe_payloads(self.payload_limit)
        c = 0; t = len(payloads)
        Display.info(f"Testing {len(payloads)} payloads")
        for p in payloads:
            c += 1
            if c % 5 == 0: Display.progress(c, t, "XXE")
            r = self._req(self.url, "POST", data=p, headers={"Content-Type": "application/xml"})
            if r and any(re.search(e, r.text, re.I) for e in self.LFI_IND): self._add("xxe", "XML External Entity (XXE)", "High", 8.6, {"type":"xml"}, p[:50]+"...", "XXE File Read Matched", r.text[:300], status_code=r.status_code)
            time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_ssrf(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"SSRF SCAN{limit_str}")
        payloads = PayloadDatabase.get_ssrf_payloads(self.payload_limit)
        pts = self._get_points()
        c = 0; t = len(payloads)*len(pts)
        Display.info(f"Testing {len(payloads)} payloads across {len(pts)} injection points")
        for pt in pts:
            for p in payloads:
                c += 1
                if c % 20 == 0: Display.progress(c, t, "SSRF")
                r = self._inject(pt, p)
                if r and any(ind in r.text.lower() for ind in ["ec2-", "ami-", "instance-id", "metadata"]): self._add("ssrf", "Server-Side Request Forgery (SSRF)", "High", 8.6, pt, p, "Internal Metadata Leaked", r.text[:300], status_code=r.status_code)
                time.sleep(DELAY_BETWEEN_REQUESTS)

    def scan_misconfig(self):
        limit_str = f" (Limit: {self.payload_limit})" if self.payload_limit > 0 else " (All Payloads)"
        Display.section(f"SECURITY MISCONFIGURATION SCAN{limit_str}")
        payloads = PayloadDatabase.get_misconfig_payloads(self.payload_limit)
        c = 0; t = len(payloads)
        Display.info(f"Testing {len(payloads)} paths/files")
        for p in payloads:
            c += 1
            if c % 5 == 0: Display.progress(c, t, "Files")
            parsed = urllib.parse.urlparse(self.url)
            path = parsed.path.rstrip('/') + p
            target = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
            r = self._req(target, "GET")
            if r and r.status_code == 200:
                if len(r.text) > 50 and "404" not in r.text[:100].lower():
                    if "Index of" in r.text or "[TOC]" in r.text or "database" in r.text.lower() or "password" in r.text.lower():
                        self._add("security_misconfig", f"Exposed Sensitive File: {p}", "High", 7.5, {"type": "path", "method": "GET"}, p, "File Accessible", r.text[:200], status_code=r.status_code)
                    elif p == "/admin" or p == "/console":
                        self._add("security_misconfig", f"Exposed Admin Panel: {p}", "Medium", 5.3, {"type": "path", "method": "GET"}, p, "Admin Accessible", "", status_code=r.status_code)
            time.sleep(DELAY_BETWEEN_REQUESTS)

        Display.info("Testing HTTP Methods...")
        try:
            r = self._req(self.url, "OPTIONS")
            if r:
                allow = r.headers.get("Allow", "").upper()
                if "PUT" in allow or "DELETE" in allow or "TRACE" in allow:
                    self._add("security_misconfig", "Dangerous HTTP Methods Enabled", "Medium", 5.3, {"type": "header", "method": "OPTIONS"}, "OPTIONS", f"Allow: {allow}", "", status_code=r.status_code)
        except: pass

# ──────────────────────────────────────
# SECTION 8: AI-POWERED ANALYSIS ENGINE (ADVANCED)
# ──────────────────────────────────────

class AIAnalyzer:
    def __init__(self):
        self.filtered = []
        self.false_positives = []
        self.stats = {"total_input": 0, "confirmed": 0, "false_positives_removed": 0, "reduction_rate": 0.0}
        
        self.keywords = [
            "sql syntax", "mysql", "postgresql", "ora-",
            "root:x:", "uid=", "gid=", "fatal error",
            "warning", "exception", "stack trace"
        ]

    @staticmethod
    def similarity(a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()

    def score_vulnerability(self, vuln, baseline_text):
        score = 0
        response_text = vuln.get("response_snippet", "")
        status_code = vuln.get("status_code", 200)

        if status_code == 200: score += 0.2
        elif status_code in [403, 401, 429]: score -= 0.2

        diff = abs(len(response_text) - len(baseline_text))
        if diff > 150: score += 0.25

        text_lower = response_text.lower()
        hits = sum(1 for k in self.keywords if k in text_lower)
        score += min(hits * 0.1, 0.3)

        payload = vuln.get("payload", "").lower()
        if payload and payload in text_lower: score += 0.15

        sim = self.similarity(baseline_text, response_text)
        if sim < 0.7: score += 0.3
        elif sim > 0.9: score -= 0.2

        return max(0, min(score, 1.0))

    def analyze(self, vulnerabilities, baseline_text=None):
        Display.section("🧠 AI ANALYSIS (Diff-Based Advanced)")
        self.stats["total_input"] = len(vulnerabilities)
        Display.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with Diff-Logic AI...")

        for vuln in vulnerabilities:
            if vuln.get("type") == "zap_alert":
                vuln["confidence"] = 0.9
                vuln["ai_verdict"] = "CONFIRMED"
                vuln["ai_reasoning"] = "Identified by OWASP ZAP"
                self.filtered.append(vuln)
                Display.success(f"  ✅ CONFIRMED: {vuln['name']} (ZAP)")
                continue

            if not baseline_text:
                vuln["confidence"] = 0.5
                self.filtered.append(vuln)
                continue

            score = self.score_vulnerability(vuln, baseline_text)
            vuln["confidence"] = round(score, 2)
            vuln["ai_verdict"] = "CONFIRMED" if score >= 0.75 else "LIKELY" if score >= 0.5 else "POSSIBLE" if score >= 0.3 else "FALSE_POSITIVE"
            
            details = f"Diff-Similarity: {self.similarity(baseline_text, vuln.get('response_snippet', '')):.2f} | Keywords Detected"
            if score >= 0.75:
                vuln["ai_reasoning"] = f"CONFIRMED. {details}"
                self.filtered.append(vuln)
                Display.success(f"  ✅ CONFIRMED: {vuln['name']} ({score})")
            elif score >= 0.3:
                vuln["ai_reasoning"] = f"POSSIBLE. {details}"
                self.filtered.append(vuln)
                Display.warning(f"  ⚠️ POSSIBLE: {vuln['name']} ({score})")
            else:
                vuln["ai_reasoning"] = f"FALSE POSITIVE. {details}"
                self.false_positives.append(vuln)
                Display.info(f"  ❌ FILTERED: {vuln['name']} ({score})")

        self.stats["confirmed"] = len(self.filtered)
        self.stats["false_positives_removed"] = len(self.false_positives)
        self.stats["reduction_rate"] = round((self.stats["false_positives_removed"] / max(self.stats["total_input"], 1)) * 100, 1)
        self._display_summary()
        return self.filtered

    def _display_summary(self):
        Display.section("AI ANALYSIS SUMMARY")
        print(f"  Total Raw Findings: {self.stats['total_input']}")
        print(f"  Confirmed True Positives: {self.stats['confirmed']}")
        print(f"  False Positives Filtered: {self.stats['false_positives_removed']}")
        reduction_rate = self.stats["reduction_rate"]
        print(f"  {Display._c('bright_green', f'Intelligence Gain (FP Reduction): {reduction_rate}%')}")

# ──────────────────────────────────────
# SECTION 9 & 10: CVSS SCORER & REPORT GENERATOR
# ──────────────────────────────────────

class CVSSScorer:
    @staticmethod
    def calculate(vuln):
        return {"base_score": vuln.get("cvss_score", 0), "vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "rating": "Critical" if vuln.get("cvss_score",0)>=9.0 else "High" if vuln.get("cvss_score",0)>=7.0 else "Medium"}

class ReportGenerator:
    def __init__(self, target_url, recon_data, vulnerabilities, scan_stats, ai_analyzer=None):
        self.target_url = target_url
        self.recon_data = recon_data
        self.vulnerabilities = vulnerabilities
        self.scan_stats = scan_stats
        self.ai_analyzer = ai_analyzer
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.sanitized = re.sub(r'[^\w]', '_', urllib.parse.urlparse(target_url).netloc or "target")

    def generate_all_reports(self):
        Display.section("GENERATING REPORTS")
        reports = {}
        for fmt, gen_func in [("html", self.generate_html), ("json", self.generate_ai_json_report), ("txt", self.generate_text)]:
            Display.info(f"Generating {fmt.upper()} report...")
            path = gen_func()
            reports[fmt] = path
            Display.success(f"{fmt.upper()}: {path}")
        return reports

    def generate_ai_json_report(self):
        filename = f"AI_Report_{self.sanitized}_{self.timestamp}.json"
        tps = [{"id": f"TP-{i+1:03d}", "vulnerability": v.get("name"), "url": v.get("url"), "payload": v.get("payload"), "ai_reasoning": v.get("ai_reasoning", "N/A"), "cvss_score": str(v.get("cvss_score", "N/A")), "owasp_category": OWASP_MAPPING.get(v.get("type", ""), "N/A")} for i, v in enumerate(self.vulnerabilities)]
        fps = [{"id": f"FP-{i+1:03d}", "original_finding": v.get("name"), "url": v.get("url"), "payload": v.get("payload"), "ai_reasoning": v.get("ai_reasoning", "Filtered")} for i, v in enumerate(self.ai_analyzer.false_positives)] if self.ai_analyzer else []
        
        report = {
            "Scan_Metadata": {"Target": self.target_url, "Total_Raw_Findings": self.scan_stats.get("total_payloads", 0), "AI_Model_Used": "Advanced Diff-Based Analysis", "Payload_Limit_Used": self.scan_stats.get("payload_limit", "All")},
            "AI_Analysis_Summary": {"True_Positives_Confirmed": len(tps), "False_Positives_Filtered": len(fps), "FP_Reduction_Rate": f"{self.scan_stats.get('fp_reduction', 0.0)}%"},
            "Confirmed_True_Positives": tps,
            "Filtered_False_Positives_Report": fps
        }
        with open(filename, 'w', encoding='utf-8') as f: json.dump(report, f, indent=4, ensure_ascii=False)
        return filename

    def generate_html(self):
        filename = f"vuln_report_{self.sanitized}_{self.timestamp}.html"
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in self.vulnerabilities: counts[v.get("severity", "Info")] += 1
        vuln_cards = ""
        for v in self.vulnerabilities:
            color = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#0d6efd"}.get(v.get("severity"), "#6c757d")
            vuln_cards += f'<div class="vuln-card" style="border-left:4px solid {color};"><h3>{html_escape(v.get("name",""))} <span style="color:{color};">({v.get("severity")})</span></h3><p>URL: {html_escape(v.get("url",""))}</p><p>Payload: <code>{html_escape(str(v.get("payload",""))[:100])}</code></p><p>AI Reasoning: {html_escape(v.get("ai_reasoning",""))}</p></div>'
        payload_info = f"Payload Limit: {self.scan_stats.get('payload_limit_used', 'All')}"
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Report</title><style>body{{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;}}.grid{{display:flex;gap:15px;margin-bottom:20px;}}.card{{background:#161b22;padding:20px;border-radius:8px;text-align:center;flex:1;}}.critical{{color:#dc3545;font-size:2em;}}.vuln-card{{background:#161b22;padding:15px;margin-bottom:10px;border-radius:8px;}}</style></head><body><h1>AI Vulnerability Report</h1><p>{html_escape(payload_info)}</p><div class="grid"><div class="card"><div class="critical">{counts['Critical']}</div>Critical</div><div class="card"><div class="critical">{counts['High']}</div>High</div><div class="card"><div class="critical">{counts['Medium']}</div>Medium</div></div>{vuln_cards}</body></html>"""
        with open(filename, 'w', encoding='utf-8') as f: f.write(html)
        return filename

    def generate_text(self):
        filename = f"vuln_report_{self.sanitized}_{self.timestamp}.txt"
        lines = ["="*60, "TEXT REPORT", "="*60, f"Target: {self.target_url}", f"Payload Limit Used: {self.scan_stats.get('payload_limit_used', 'All')}", f"Total Issues: {len(self.vulnerabilities)}", "-"*60]
        for v in self.vulnerabilities: lines.append(f"[{v.get('severity')}] {v.get('name')} | Payload: {str(v.get('payload',''))[:50]}")
        with open(filename, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
        return filename

# ──────────────────────────────────────
# SECTION 11 & 12: ORCHESTRATOR & CLI
# ──────────────────────────────────────

class WebVulnerabilityScanner:
    def __init__(self, target_url, payload_limit=0, payload_preset="All"):
        self.url = target_url if target_url.startswith("http") else "https://" + target_url
        self.payload_limit = payload_limit
        self.payload_preset = payload_preset
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.scan_stats = {"start_time": None, "end_time": None, "duration": "", "total_payloads": 0, "requests_made": 0, "fp_reduction": 0, "payload_limit": self.payload_limit, "payload_limit_used": self.payload_preset}

    def run_scan(self, modules=None):
        if modules is None: modules = ["sqli", "xss", "cmd", "lfi", "xxe_ssrf", "misconfig"]
        self.scan_stats["start_time"] = datetime.now()
        Display.banner()
        Display.info(f"Target: {self.url}")
        Display.info(f"Payload Limit: {self.payload_preset} ({self.payload_limit if self.payload_limit > 0 else 'All'} payloads per category)")

        recon = ReconnaissanceEngine(self.url, self.session).run_full_recon()
        detector = VulnerabilityDetector(self.url, self.session, recon, self.payload_limit)
        detector._get_baseline()

        module_map = {
            "sqli": (detector.scan_sqli, lambda: PayloadDatabase.get_sqli_payloads(self.payload_limit)),
            "xss": (detector.scan_xss, lambda: PayloadDatabase.get_xss_payloads(self.payload_limit)),
            "cmd": (detector.scan_cmd, lambda: PayloadDatabase.get_cmd_injection_payloads(self.payload_limit)),
            "lfi": (detector.scan_lfi, lambda: PayloadDatabase.get_dir_traversal_payloads(self.payload_limit)),
            "xxe_ssrf": (lambda: (detector.scan_xxe(), detector.scan_ssrf()), lambda: PayloadDatabase.get_xxe_payloads(self.payload_limit) + PayloadDatabase.get_ssrf_payloads(self.payload_limit)),
            "misconfig": (detector.scan_misconfig, lambda: PayloadDatabase.get_misconfig_payloads(self.payload_limit))
        }

        if "zap" in modules:
            Display.header("INITIALIZING ZAP INTEGRATION")
            zap_api_key = input(f"  {Display._c('cyan', '[*] Enter ZAP API Key (Leave empty if none): ')}").strip()
            zap_scanner = ZAPScanner(self.url, api_key=zap_api_key)
            zap_vulns = zap_scanner.run_full_zap_scan()
            detector.vulns.extend(zap_vulns)
            self.scan_stats["total_payloads"] += len(zap_vulns)

        if "port_scan" in modules:
            Display.header("INITIALIZING ADVANCED PORT SCANNER")
            hostname = urllib.parse.urlparse(self.url).hostname
            port_scanner = AdvancedPortScanner(hostname)
            open_ports = port_scanner.start_scan()
            recon["open_ports"] = open_ports
            if open_ports:
                critical_ports = [21, 22, 23, 3306, 3389, 5432]
                found_crit = [p for p in open_ports if p in critical_ports]
                if found_crit:
                    detector.vulns.append({
                        "id": f"PORT-{len(found_crit)}", "type": "security_misconfig", "name": "Critical Ports Exposed",
                        "severity": "Medium", "cvss_score": 5.3, "url": self.url, "parameter": "Network",
                        "payload": "", "evidence": f"Ports: {found_crit}", "response_snippet": "",
                        "timestamp": datetime.now().isoformat(), "confidence": 1.0
                    })

        for mod in modules:
            if mod in module_map:
                scan_func, payload_func = module_map[mod]
                scan_func()
                self.scan_stats["total_payloads"] += len(payload_func())

        self.scan_stats["requests_made"] = detector.reqs
        
        ai = AIAnalyzer()
        final_vulns = ai.analyze(detector.vulns, detector.baseline_text)
        
        self.scan_stats["fp_reduction"] = ai.stats["reduction_rate"]
        self.scan_stats["end_time"] = datetime.now()
        self.scan_stats["duration"] = str(self.scan_stats["end_time"] - self.scan_stats["start_time"]).split('.')[0]

        return ReportGenerator(self.url, recon, final_vulns, self.scan_stats, ai).generate_all_reports()

def main():
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError: pass

    MODULE_MAP = {
        "1": ["sqli", "xss", "cmd", "lfi", "xxe_ssrf", "misconfig"],
        "2": ["sqli"], "3": ["xss"], "4": ["cmd"], "5": ["lfi"],
        "6": ["xxe_ssrf"], "7": ["misconfig"], "8": ["port_scan"], "9": ["zap"]
    }

    while True:
        Display.banner()
        print(f"  {Display._c('red', '╔══════════════════════════════════════════════════════╗')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[1]')}  {Display._c('white', 'Full Web Scan (All Modules)                  ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[2]')}  {Display._c('white', 'SQL Injection Scan                           ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[3]')}  {Display._c('white', 'XSS Scan                                     ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[4]')}  {Display._c('white', 'Command Injection Scan                       ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[5]')}  {Display._c('white', 'Directory Traversal Scan                     ')}  {Display._c('red', '║')}") 
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[6]')}  {Display._c('white', 'SSRF / XXE Scan                              ')}  {Display._c('red', '║')}") 
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[7]')}  {Display._c('white', 'Security Misconfiguration Scan               ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[8]')}  {Display._c('white', 'Advanced Multi-Threaded Port Scan            ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[9]')}  {Display._c('white', 'OWASP ZAP Integration                         ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_yellow', '[10]')}  {Display._c('white', 'Custom Scan (Select Modules)                ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '║')}  {Display._c('bright_red', '[0]')}  {Display._c('gray', 'Exit                                         ')}  {Display._c('red', '║')}")
        print(f"  {Display._c('red', '╚══════════════════════════════════════════════════════╝')}\n")

        choice = input(f"  {Display._c('bright_green', 'Choose scan type > ')}").strip()
        if choice == "0": sys.exit(0)
        
        selected_modules = []
        if choice in MODULE_MAP:
            selected_modules = MODULE_MAP[choice]
        elif choice == "10":
            print(f"\n  {Display._c('cyan', 'Available modules:')}")
            print(f"  {Display._c('yellow', '  [2] SQLi   [3] XSS   [4] CMD   [5] LFI   [6] SSRF/XXE   [7] Misconfig   [8] PortScan   [9] ZAP')}")
            custom = input(f"  {Display._c('bright_green', 'Enter numbers separated by commas (e.g., 2,3,8) > ')}").strip()
            for c in custom.split(','):
                c = c.strip()
                if c in MODULE_MAP: selected_modules.extend(MODULE_MAP[c])
        else:
            Display.error("Invalid choice"); time.sleep(1); continue
            
        if not selected_modules:
            Display.error("No valid modules selected"); time.sleep(1); continue

        # Check if any vulnerability scanning modules are selected (not just port/zap)
        vuln_modules = [m for m in selected_modules if m not in ["port_scan", "zap"]]
        
        # Only show payload limit menu if vulnerability scanning is selected
        payload_limit = 0
        payload_preset = "All"
        if vuln_modules:
            payload_limit, payload_preset = PayloadLimitSelector.get_limit()

        url = input(f"  {Display._c('bright_green', 'Target URL > ')}").strip()
        if not url: continue

        confirm = input(f"  {Display._c('bright_red', 'Confirm scan? (y/N) > ')}").strip().lower()
        if confirm != 'y': continue

        try:
            reports = WebVulnerabilityScanner(url, payload_limit, payload_preset).run_scan(selected_modules)
            Display.header("SCAN COMPLETE")
            for fmt, path in reports.items(): Display.success(f"{fmt.upper()}: {path}")
        except KeyboardInterrupt: Display.warning("Interrupted by user.")
        except Exception as e: Display.error(f"Error: {e}")

        input(f"\n  {Display._c('cyan', 'Press Enter to continue...')}")

if __name__ == "__main__":
    main()
