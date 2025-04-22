# config/settings.py
import os

# Scan Configuration
SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', 300))  # 5 minutes default
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', "scan_results")
DEFAULT_NETWORK_RANGE = os.environ.get('NETWORK_RANGE', "192.168.100.0/24")

# Detection Parameters
DHCP_SNIFF_DURATION = int(os.environ.get('DHCP_SNIFF_DURATION', 60))  # seconds
NMAP_ARGUMENTS = os.environ.get('NMAP_ARGUMENTS', '-sS -O -sV --version-intensity 5')

# Security Settings
ENABLE_DHCP_DETECTION = os.environ.get('ENABLE_DHCP_DETECTION', 'true').lower() == 'true'
ENABLE_VULNERABILITY_SCAN = os.environ.get('ENABLE_VULNERABILITY_SCAN', 'true').lower() == 'true'
VULN_SCAN_NSE_SCRIPTS = os.environ.get('VULN_SCAN_NSE_SCRIPTS', 'vuln')

# Logging Settings
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
MAX_LOG_ENTRIES = int(os.environ.get('MAX_LOG_ENTRIES', 1000))
LOG_FILE = os.environ.get('LOG_FILE', 'network_monitor.log')