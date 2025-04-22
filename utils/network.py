#!/usr/bin/env python3
"""Network utility functions for the monitoring system"""
import netifaces
import socket
import logging
import subprocess
import platform
import re
from typing import List, Dict, Optional, Any, Set, Tuple

logger = logging.getLogger(__name__)

def get_my_ip_address() -> str:
    """
    Get the IP address of the primary network interface
    
    Returns:
        IP address string
    """
    try:
        # Try socket method first - most reliable across platforms
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable, just to determine interface
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.debug(f"Socket method failed: {e}")
    
    try:
        # Fallback to netifaces
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            interface = gateways['default'][netifaces.AF_INET][1]
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            return ip
    except Exception as e:
        logger.debug(f"Netifaces method failed: {e}")
    
    try:
        # Last resort - hostname resolution
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if not ip.startswith('127.'):
            return ip
    except Exception as e:
        logger.debug(f"Hostname method failed: {e}")
    
    # If everything fails
    return "127.0.0.1"

def get_mac_via_arp(ip: str, timeout: int = 2) -> Optional[str]:
    """
    Get MAC address of an IP using ARP
    
    Args:
        ip: IP address to look up
        timeout: Timeout in seconds
    
    Returns:
        MAC address as string or None if unavailable
    """
    try:
        from scapy.all import ARP, Ether, srp
        
        # Send ARP request and wait for response
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=timeout, verbose=0)
        return ans[0][1].src.upper() if ans else None
    except Exception as e:
        logging.debug(f"Scapy ARP failed for {ip}: {str(e)}")
        
        # Fall back to system ARP command
        try:
            import platform
            system = platform.system()
            
            if system == 'Windows':
                # Windows ARP command
                output = subprocess.check_output(['arp', '-a', ip], universal_newlines=True, timeout=timeout)
                for line in output.splitlines():
                    if ip in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0).upper()
            else:
                # Linux/macOS ARP command
                output = subprocess.check_output(['arp', '-n', ip], universal_newlines=True, timeout=timeout)
                for line in output.splitlines():
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                        if mac_match:
                            return mac_match.group(0).upper()
        except Exception as e2:
            logging.debug(f"System ARP failed for {ip}: {str(e2)}")
            
        return None


def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway (router) IP address
    
    Returns:
        Gateway IP string or None if not found
    """
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            return gateway_ip
    except Exception as e:
        logger.debug(f"Error getting default gateway: {e}")
    
    # Platform-specific fallbacks
    system = platform.system().lower()
    
    if system == 'windows':
        try:
            output = subprocess.check_output("ipconfig", universal_newlines=True)
            for line in output.split('\n'):
                if "Default Gateway" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        except Exception as e:
            logger.debug(f"Windows gateway detection failed: {e}")
    
    elif system in ('linux', 'darwin'):
        try:
            if system == 'darwin':  # macOS
                output = subprocess.check_output(["netstat", "-nr"], universal_newlines=True)
            else:  # Linux
                output = subprocess.check_output(["ip", "route"], universal_newlines=True)
            
            for line in output.split('\n'):
                if system == 'darwin' and 'default' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
                elif system == 'linux' and 'default' in line:
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        except Exception as e:
            logger.debug(f"{system} gateway detection failed: {e}")
    
    return None

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Get a list of network interfaces with their IP and MAC addresses
    
    Returns:
        List of dictionaries with interface details
    """
    interfaces = []
    
    try:
        for iface in netifaces.interfaces():
            interface_details = {'name': iface, 'ip': None, 'mac': None, 'netmask': None}
            
            # Get addresses for this interface
            addrs = netifaces.ifaddresses(iface)
            
            # Get IPv4 address if available
            if netifaces.AF_INET in addrs:
                inet_info = addrs[netifaces.AF_INET][0]
                interface_details['ip'] = inet_info.get('addr')
                interface_details['netmask'] = inet_info.get('netmask')
            
            # Get MAC address if available
            if netifaces.AF_LINK in addrs:
                link_info = addrs[netifaces.AF_LINK][0]
                interface_details['mac'] = link_info.get('addr')
            
            # Only add interfaces with an IP address
            if interface_details['ip']:
                interfaces.append(interface_details)
    
    except Exception as e:
        logger.error(f"Error retrieving network interfaces: {e}")
    
    return interfaces or []  # Return empty list if None

def is_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is in a network specified in CIDR notation
    
    Args:
        ip: IP address to check
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        True if IP is in the network, False otherwise
    """
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except (ValueError, ImportError) as e:
        # Fallback method if ipaddress module not available
        logger.debug(f"Error checking network: {e}, using fallback method")
        
        # Basic fallback using string comparison for /24 networks
        if '/24' in network:
            network_prefix = network.split('/')[0].rsplit('.', 1)[0]
            ip_prefix = ip.rsplit('.', 1)[0]
            return network_prefix == ip_prefix
        
        return False

def get_my_mac_address() -> Optional[str]:
    """
    Get the MAC address of the primary network interface
    
    Returns:
        MAC address string or None if not found
    """
    try:
        # Get my IP first to identify the main interface
        my_ip = get_my_ip_address()
        
        # Find interface with this IP
        for interface in get_network_interfaces():
            if interface.get('ip') == my_ip and interface.get('mac'):
                return interface.get('mac').upper()  # Return normalized MAC
                
        # Second attempt using default gateway interface
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            interface = gateways['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addrs and 'addr' in addrs[netifaces.AF_LINK][0]:
                return addrs[netifaces.AF_LINK][0]['addr'].upper()
    except Exception as e:
        logger.error(f"Error getting MAC address: {e}")
    
    return None

def get_network_cidr() -> str:
    """
    Get the network CIDR for the primary interface
    
    Returns:
        Network CIDR string (e.g., "192.168.1.0/24")
    """
    try:
        # Find the main interface
        my_ip = get_my_ip_address()
        
        for interface in get_network_interfaces():
            if interface.get('ip') == my_ip and interface.get('netmask'):
                ip = interface.get('ip')
                netmask = interface.get('netmask')
                
                # Convert netmask to CIDR notation
                import ipaddress
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
        
        # Fallback to a reasonable guess if we can't calculate it
        parts = my_ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
    except Exception as e:
        logger.error(f"Error determining network CIDR: {e}")
    
    # Default fallback
    return "192.168.1.0/24"