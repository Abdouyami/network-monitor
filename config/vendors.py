# config/vendors.py
# Vendor OUI Database (first 6 chars of MAC)
VENDOR_OUI = {
    'C03C59': 'Microsoft',
    '729BA4': 'D-Link',
    'A4C138': 'Samsung',
    '88E9FE': 'Apple',
    'DC4427': 'Huawei',
    '001B63': 'Raspberry Pi',
    'B827EB': 'Raspberry Pi',
    '00005E': 'Huawei',
    '001C14': 'Dell',
    '001D92': 'ASUSTek',
    '0021D1': 'Cisco',
    '0050F2': 'Microsoft',
    'F4F5D8': 'Google',
    'F0F61C': 'Apple',
    'ACBC32': 'Apple',
    '94E6F7': 'Intel Corporate',
    '801F02': 'Edimax Technology Co. Ltd.',
    '00FC8D': 'Hitron Technologies',
    '002248': 'Microsoft',
    'D8A25E': 'Nvidia',
    '7CEBEA': 'Asustek Computer Inc',
    '000D3A': 'Microsoft',
    '5067F0': 'ZyXEL Communications',
    '000E8F': 'Sercomm Corporation',
    'CC2D21': 'Tenda Technology Co.,Ltd.Dongguan branch'
}

# Device-specific Port Mappings
PORT_CATEGORIES = {
    'printer': {515, 631, 9100},
    'iot': {1883, 5683, 8883, 1900, 5000},
    'media': {7000, 32410, 3689, 5000, 8008, 9000, 1900},
    'mobile': {62078, 49152, 5353},  # Includes mDNS port
    'server': {21, 22, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443}
}

# Common OS Signatures
OS_SIGNATURES = {
    'Windows': ['Windows', 'Microsoft', 'Win32', 'Win64', 'MSIE'],
    'macOS': ['Mac OS X', 'macOS', 'OSX', 'Mac OS'],
    'Linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'Fedora', 'Red Hat'],
    'Android': ['Android'],
    'iOS': ['iPhone', 'iPad', 'iOS'],
    'Network': ['Router', 'Switch', 'Firewall', 'NAS', 'Storage']
}

# Common Device IoT Ports
IOT_PORTS = {
    'smart_tv': [8008, 8009, 7000],  # Chromecast, WebOS, etc.
    'camera': [554, 80, 443, 8000, 8080],  # RTSP, HTTP
    'voice_assistant': [3000, 4070, 8008, 8009],  # Alexa, Google Home
    'smart_home': [80, 443, 8080, 1883, 8883, 1900]  # MQTT, HTTP, UPnP
}

# Common Vulnerable Ports and Services
VULNERABLE_SERVICES = {
    'smb': [139, 445],  # EternalBlue, SMB vulnerabilities
    'rdp': [3389],  # BlueKeep, RDP vulnerabilities
    'ssh': [22],  # SSH vulnerabilities
    'telnet': [23],  # Telnet (clear text)
    'ftp': [20, 21],  # FTP (clear text)
    'database': [1433, 3306, 5432],  # MS SQL, MySQL, PostgreSQL
    'webserver': [80, 443, 8080, 8443]  # Web vulnerabilities
}

# Device Type Detection by Common Ports
DEVICE_TYPE_PORT_MAPPING = {
    'router': [53, 80, 443, 8080, 161],  # DNS, Web, SNMP
    'firewall': [80, 443, 8080, 8443, 161],  # Management and SNMP
    'printer': [515, 631, 9100],  # LPD, IPP, Raw Print
    'nas': [80, 443, 139, 445, 111, 2049],  # SMB, NFS
    'ip_camera': [554, 80, 443, 8000, 8080, 8443],  # RTSP, HTTP
    'voip': [5060, 5061],  # SIP
    'iot_hub': [1883, 8883, 5683, 8080],  # MQTT, CoAP
    'media_device': [8008, 8009, 7000, 1900],  # Chromecast, DLNA
    'gaming_console': [3074, 3075, 3659, 27015, 27016],  # Xbox, Playstation, Steam
}