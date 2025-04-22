"""
Enhanced device type detection signatures
This file contains fingerprints to accurately identify common device types
"""

# Mapping of port combinations that are strongly indicative of specific device types
SPECIAL_PORT_SIGNATURES = {
    # Printer signatures (9100 = printing, 631 = IPP, 515 = LPD)
    (9100, 631): 'printer',
    (9100, 515): 'printer',
    (631, 80): 'printer',
    # NAS signatures
    (139, 445, 111): 'nas',
    (139, 445, 9000): 'nas',
    # VoIP phone signatures
    (5060, 5061): 'ip_phone',
    # IoT device hubs
    (8080, 1900, 5555): 'iot_device',
    # Game consoles
    (3074, 53): 'xbox',
    (3478, 3479, 3658): 'playstation',
    # Streaming devices
    (8008, 8009): 'chromecast',
    (7000, 7100): 'apple_tv',
    (8060, 1900): 'roku',
    # Network devices
    (80, 443, 22, 161): 'network_switch',
    (80, 443, 53, 67): 'router',
}

# Mapping of specific ports that are strong indicators of a device type
SPECIFIC_PORT_INDICATORS = {
    9100: 'printer',  # Raw printing
    515: 'printer',   # LPD
    631: 'printer',   # IPP
    5353: 'apple_device',  # mDNS/Bonjour
    5060: 'ip_phone',  # SIP
    2869: 'smart_tv',  # DLNA
    8008: 'streaming_device',  # Chromecast
    8060: 'streaming_device',  # Roku
    3074: 'game_console',  # Xbox Live
    3478: 'game_console',  # PlayStation Network
    5351: 'apple_device',  # Apple Time Machine
    548: 'apple_device',  # AFP (Apple Filing Protocol)
    8080: 'iot_device',  # Common IoT web interface
    8883: 'iot_device',  # Secure MQTT
    1883: 'iot_device',  # MQTT
    554: 'ip_camera',  # RTSP
    10554: 'ip_camera',  # Alternative RTSP
}

# Mapping of vendor-specific signatures for precise device identification
VENDOR_DEVICE_MAPPING = {
    'apple': {
        'keywords': ['apple', 'macintosh'],
        'device_types': {
            'default': 'mac',
            'port_mappings': {
                (548, 5351): 'mac',
                (5353, 7000): 'apple_tv',
                (62078,): 'ios_device'
            }
        }
    },
    'samsung': {
        'keywords': ['samsung'],
        'device_types': {
            'default': 'samsung_tv',
            'port_mappings': {
                (8001, 8002): 'samsung_tv',
                (8080, 9197): 'android_device'
            }
        }
    },
    'amazon': {
        'keywords': ['amazon'],
        'device_types': {
            'default': 'streaming_device',
            'port_mappings': {
                (8008, 40317): 'firetv',
                (4070,): 'echo'
            }
        }
    },
    'sony': {
        'keywords': ['sony'],
        'device_types': {
            'default': 'sony_tv',
            'port_mappings': {
                (3478, 3479, 3658): 'playstation',
                (50001, 50002): 'sony_tv'
            }
        }
    },
    'microsoft': {
        'keywords': ['microsoft'],
        'device_types': {
            'default': 'windows_pc',
            'port_mappings': {
                (3074, 3075): 'xbox',
                (1434, 1433): 'windows_server'
            }
        }
    },
    'lg': {
        'keywords': ['lg'],
        'device_types': {
            'default': 'lg_tv',
            'port_mappings': {
                (8080, 9741, 9742): 'lg_tv'
            }
        }
    },
    'cisco': {
        'keywords': ['cisco', 'linksys'],
        'device_types': {
            'default': 'router',
            'port_mappings': {
                (22, 23, 161): 'router',
                (80, 443, 5060): 'ip_phone'
            }
        }
    },
    'asus': {
        'keywords': ['asus'],
        'device_types': {
            'default': 'router',
            'port_mappings': {
                (80, 443, 8443): 'router'
            }
        }
    },
    'netgear': {
        'keywords': ['netgear'],
        'device_types': {
            'default': 'router',
            'port_mappings': {
                (80, 443, 8443): 'router'
            }
        }
    },
    'tp-link': {
        'keywords': ['tp-link', 'tplink'],
        'device_types': {
            'default': 'router',
            'port_mappings': {
                (80, 443): 'router'
            }
        }
    },
    'ubiquiti': {
        'keywords': ['ubiquiti', 'ubnt'],
        'device_types': {
            'default': 'router',
            'port_mappings': {
                (80, 443, 8080): 'router',
                (8880, 8843): 'router'
            }
        }
    },
    'hp': {
        'keywords': ['hp', 'hewlett-packard'],
        'device_types': {
            'default': 'printer',
            'port_mappings': {
                (9100, 631): 'printer',
                (9100, 80, 443): 'printer'
            }
        }
    },
    'canon': {
        'keywords': ['canon'],
        'device_types': {
            'default': 'printer',
            'port_mappings': {
                (9100, 631): 'printer',
                (8000, 8080): 'printer'
            }
        }
    },
    'epson': {
        'keywords': ['epson', 'seiko'],
        'device_types': {
            'default': 'printer',
            'port_mappings': {
                (9100, 631): 'printer',
                (80, 631): 'printer'
            }
        }
    },
    'brother': {
        'keywords': ['brother'],
        'device_types': {
            'default': 'printer',
            'port_mappings': {
                (9100, 631): 'printer',
                (515, 631): 'printer'
            }
        }
    },
    'synology': {
        'keywords': ['synology'],
        'device_types': {
            'default': 'nas',
            'port_mappings': {
                (5000, 5001): 'nas',
                (139, 445, 5000): 'nas'
            }
        }
    },
    'qnap': {
        'keywords': ['qnap'],
        'device_types': {
            'default': 'nas',
            'port_mappings': {
                (8080, 443): 'nas',
                (139, 445, 8080): 'nas'
            }
        }
    },
    'western digital': {
        'keywords': ['western digital', 'wd'],
        'device_types': {
            'default': 'nas',
            'port_mappings': {
                (80, 443): 'nas',
                (139, 445, 80): 'nas'
            }
        }
    },
    'hikvision': {
        'keywords': ['hikvision'],
        'device_types': {
            'default': 'ip_camera',
            'port_mappings': {
                (80, 554): 'ip_camera',
                (8000, 554): 'ip_camera'
            }
        }
    },
    'dahua': {
        'keywords': ['dahua'],
        'device_types': {
            'default': 'ip_camera',
            'port_mappings': {
                (80, 554): 'ip_camera',
                (37777, 554): 'ip_camera'
            }
        }
    },
    'axis': {
        'keywords': ['axis'],
        'device_types': {
            'default': 'ip_camera',
            'port_mappings': {
                (80, 554): 'ip_camera',
                (8080, 554): 'ip_camera'
            }
        }
    },
    'polycom': {
        'keywords': ['polycom'],
        'device_types': {
            'default': 'ip_phone',
            'port_mappings': {
                (5060, 80): 'ip_phone',
                (5060, 5061, 80): 'ip_phone'
            }
        }
    },
    'grandstream': {
        'keywords': ['grandstream'],
        'device_types': {
            'default': 'ip_phone',
            'port_mappings': {
                (5060, 80): 'ip_phone',
                (5060, 443): 'ip_phone'
            }
        }
    }
}

# Port combinations that indicate device types
PORT_DEVICE_MAPPING = {
    'router': {
        'device_type': 'router',
        'required_ports': [(80,), (443,), (53,)],
        'optional_ports': [22, 23, 67, 68, 161, 8080, 8443]
    },
    'nas': {
        'device_type': 'nas',
        'required_ports': [(139, 445), (80,)],
        'optional_ports': [21, 22, 111, 2049, 3306, 5000, 8080]
    },
    'printer': {
        'device_type': 'printer',
        'required_ports': [(631,), (9100,), (515,)],
        'optional_ports': [80, 443, 161, 5353, 8080]
    },
    'smart_tv': {
        'device_type': 'smart_tv',
        'required_ports': [(80,), (1900,)],
        'optional_ports': [443, 5353, 8008, 8009, 8080, 9080]
    },
    'streaming_device': {
        'device_type': 'streaming_device',
        'required_ports': [(8008,), (8009,), (8060,)],
        'optional_ports': [80, 443, 1900, 5353, 7000]
    },
    'ip_camera': {
        'device_type': 'ip_camera',
        'required_ports': [(80,), (554,)],
        'optional_ports': [443, 8000, 8080, 10554, 37777]
    },
    'network_switch': {
        'device_type': 'network_switch',
        'required_ports': [(80,), (22,)],
        'optional_ports': [23, 161, 443, 8080, 8443]
    },
    'windows_pc': {
        'device_type': 'windows_pc',
        'required_ports': [(139,), (445,)],
        'optional_ports': [135, 3389, 5357, 5000]
    },
    'linux_device': {
        'device_type': 'linux_device',
        'required_ports': [(22,)],
        'optional_ports': [80, 443, 5353, 8080, 5000]
    },
    'mac': {
        'device_type': 'mac',
        'required_ports': [(548,), (5353,)],
        'optional_ports': [22, 80, 88, 445, 631, 5000]
    },
    'ios_device': {
        'device_type': 'ios_device',
        'required_ports': [(62078,), (5353,)],
        'optional_ports': [80, 443, 137, 138, 139, 445, 548]
    },
    'android_device': {
        'device_type': 'android_device',
        'required_ports': [(5555,)],
        'optional_ports': [8080, 80, 443, 5353]
    },
    'iot_device': {
        'device_type': 'iot_device',
        'required_ports': [(8080,), (80,)],
        'optional_ports': [1883, 8883, 443, 5683, 5684, 5555]
    },
    'ip_phone': {
        'device_type': 'ip_phone',
        'required_ports': [(5060,)],
        'optional_ports': [5061, 80, 443, 4569, 2000]
    },
    'game_console': {
        'device_type': 'game_console',
        'required_ports': [(3074,), (3478,)],
        'optional_ports': [80, 443, 1900, 5223, 53, 3479, 3658]
    }
}

# OS-specific signatures for device identification
OS_DEVICE_MAPPING = {
    'windows': {
        'keywords': ['windows', 'microsoft', 'mswin'],
        'device_type': 'windows_pc'
    },
    'linux': {
        'keywords': ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'redhat'],
        'device_type': 'linux_device'
    },
    'mac': {
        'keywords': ['mac', 'macos', 'darwin', 'osx', 'apple'],
        'device_type': 'mac'
    },
    'ios': {
        'keywords': ['ios', 'iphone', 'ipad', 'ipod'],
        'device_type': 'ios_device'
    },
    'android': {
        'keywords': ['android'],
        'device_type': 'android_device'
    },
    'playstation': {
        'keywords': ['playstation', 'ps4', 'ps5'],
        'device_type': 'playstation'
    },
    'xbox': {
        'keywords': ['xbox'],
        'device_type': 'xbox'
    },
    'router_os': {
        'keywords': ['router', 'routeros', 'dd-wrt', 'openwrt', 'tomato', 'asuswrt'],
        'device_type': 'router'
    },
    'nas_os': {
        'keywords': ['nas', 'freenas', 'truenas', 'unraid', 'dsm', 'qts'],
        'device_type': 'nas'
    },
    'printer_os': {
        'keywords': ['printer', 'jetdirect', 'ricoh', 'konica', 'kyocera'],
        'device_type': 'printer'
    }
}