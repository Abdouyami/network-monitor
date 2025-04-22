"""
Advanced device type identification module
Uses signature matching and heuristics to accurately identify device types
"""

import logging
from typing import Dict, Any, List, Set, Optional, Tuple
from config import device_signatures

class DeviceIdentifier:
    """Identifies device types based on various detection methods"""
    
    def __init__(self):
        """Initialize the device identifier"""
        self.logger = logging.getLogger(__name__)
    
    def identify_device_type(self, host_info: Dict[str, Any], fingerprint: Dict[str, Any], 
                           my_ip: Optional[str] = None, my_gateway: Optional[str] = None) -> Dict[str, Any]:
        """
        Enhanced device type detection using multiple methods
        
        Args:
            host_info: Host information dictionary with ports, hostname, etc.
            fingerprint: OS fingerprint information
            my_ip: My own IP address (to identify this device)
            my_gateway: Default gateway IP (to identify router)
            
        Returns:
            Dictionary with device type information
        """
        ip_address = host_info.get('ip_address')
        mac_address = host_info.get('mac_address')
        hostname = host_info.get('hostname')
        vendor = host_info.get('vendor')
        os_info = host_info.get('os') or str(fingerprint.get('data', {}))
        open_ports = [p.get('port') for p in host_info.get('ports', [])]
        
        # Initialize result with low confidence defaults
        result = {
            'device_type': 'unknown',
            'confidence': 'low',
            'methods_used': []
        }
        
        # Check if this is our device or the gateway
        if my_ip and ip_address == my_ip:
            result['device_type'] = 'this_device'
            result['confidence'] = 'high'
            result['methods_used'].append('self_identification')
            return result
            
        if my_gateway and ip_address == my_gateway:
            result['device_type'] = 'router'
            result['confidence'] = 'high'
            result['methods_used'].append('gateway_identification')
            return result
            
        # Method 1: Check special port combinations that are very specific
        port_set = set(open_ports)
        for port_combo, device_type in device_signatures.SPECIAL_PORT_SIGNATURES.items():
            if all(port in port_set for port in port_combo):
                result['device_type'] = device_type
                result['confidence'] = 'high'
                result['methods_used'].append('special_port_signature')
                return result
                
        # Method 2: Check for vendor-specific patterns
        if vendor:
            lower_vendor = vendor.lower()
            for vendor_key, vendor_data in device_signatures.VENDOR_DEVICE_MAPPING.items():
                if any(keyword in lower_vendor for keyword in vendor_data['keywords']):
                    # Check port mappings first (more specific)
                    port_mapped = False
                    for port_combo, device_type in vendor_data['device_types'].get('port_mappings', {}).items():
                        if all(port in port_set for port in port_combo):
                            result['device_type'] = device_type
                            result['confidence'] = 'high'
                            result['methods_used'].append('vendor_port_mapping')
                            port_mapped = True
                            break
                            
                    # If no port mapping found, use default vendor device type
                    if not port_mapped:
                        result['device_type'] = vendor_data['device_types']['default']
                        result['confidence'] = 'medium'
                        result['methods_used'].append('vendor_default')
                        
                    return result
                    
        # Method 3: Try port-based device classification from signatures
        for device_key, device_data in device_signatures.PORT_DEVICE_MAPPING.items():
            # Check if any of the required port combinations are present
            for required_combo in device_data['required_ports']:
                if all(port in port_set for port in required_combo):
                    # Calculate confidence based on how many optional ports are also present
                    optional_matches = sum(1 for port in device_data['optional_ports'] if port in port_set)
                    confidence = 'high' if optional_matches >= 2 else 'medium'
                    
                    result['device_type'] = device_data['device_type']
                    result['confidence'] = confidence
                    result['methods_used'].append('port_signature')
                    return result
        
        # Method 4: Look for OS-specific indicators in fingerprint data
        os_str = str(os_info).lower()
        for os_key, os_data in device_signatures.OS_DEVICE_MAPPING.items():
            if any(keyword in os_str for keyword in os_data['keywords']):
                result['device_type'] = os_data['device_type']
                result['confidence'] = 'medium'
                result['methods_used'].append('os_detection')
                return result
                
        # Method 5: Check for specific ports that strongly indicate a device type
        for port in open_ports:
            if port in device_signatures.SPECIFIC_PORT_INDICATORS:
                result['device_type'] = device_signatures.SPECIFIC_PORT_INDICATORS[port]
                result['confidence'] = 'medium'
                result['methods_used'].append('specific_port')
                return result
                
        # Method 6: Last resort - simple OS-based identification
        if 'windows' in os_str.lower():
            result['device_type'] = 'windows_pc'
            result['confidence'] = 'low'
            result['methods_used'].append('os_keyword')
        elif 'linux' in os_str.lower() or 'unix' in os_str.lower():
            result['device_type'] = 'linux_device'
            result['confidence'] = 'low'
            result['methods_used'].append('os_keyword')
        elif 'mac' in os_str.lower() or 'darwin' in os_str.lower():
            result['device_type'] = 'mac'
            result['confidence'] = 'low'
            result['methods_used'].append('os_keyword')
        elif 'android' in os_str.lower():
            result['device_type'] = 'android_device'
            result['confidence'] = 'low'
            result['methods_used'].append('os_keyword')
        elif 'iphone' in os_str.lower() or 'ipad' in os_str.lower() or 'ios' in os_str.lower():
            result['device_type'] = 'ios_device'
            result['confidence'] = 'low'
            result['methods_used'].append('os_keyword')
            
        # Add additional data we discovered
        result['vendor'] = vendor
        result['os_info'] = os_str
        result['open_ports'] = list(port_set)
            
        return result
            
    def get_readable_device_name(self, device_type: str) -> str:
        """
        Convert internal device type to human-readable name
        
        Args:
            device_type: Internal device type
            
        Returns:
            Human-readable device name
        """
        readable_names = {
            'windows_pc': 'Windows Computer',
            'mac': 'Mac Computer',
            'linux_device': 'Linux Device',
            'android_device': 'Android Device',
            'ios_device': 'iPhone/iPad',
            'router': 'Router/Gateway',
            'network_switch': 'Network Switch',
            'nas': 'Network Storage (NAS)',
            'smart_tv': 'Smart TV',
            'streaming_device': 'Streaming Device',
            'ip_camera': 'IP Camera',
            'printer': 'Printer',
            'game_console': 'Game Console',
            'xbox': 'Xbox Console',
            'playstation': 'PlayStation Console',
            'iot_device': 'IoT Device',
            'this_device': 'This Device',
            'apple_device': 'Apple Device',
            'apple_tv': 'Apple TV',
            'samsung_tv': 'Samsung TV',
            'lg_tv': 'LG TV',
            'sony_tv': 'Sony TV',
            'ip_phone': 'IP Phone/VoIP Device',
            'unknown': 'Unknown Device'
        }
        
        return readable_names.get(device_type, device_type.replace('_', ' ').title())