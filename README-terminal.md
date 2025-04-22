# Terminal-Based Network Monitoring System

A powerful cross-platform network monitoring system with terminal-based output for real-time device detection, fingerprinting, and security analysis.

## Files to Include in Your Project

1. **Core Files**:
   - `network_monitor.py` - The main command-line interface and entry point
   - `run_monitor.py` - Script for running the monitor in terminal mode

2. **Core Modules** (in `/core` directory):
   - `core/scanner.py` - Network scanning functionality using nmap
   - `core/detector.py` - Threat detection algorithms
   - `core/fingerprint.py` - Device fingerprinting and OS detection
   - `core/models.py` - Data structures for devices, ports, and threats

3. **Utility Modules** (in `/utils` directory):
   - `utils/network.py` - Network utility functions
   - `utils/helpers.py` - Helper functions for data handling

4. **Configuration Files** (in `/config` directory):
   - `config/settings.py` - Global settings and constants
   - `config/vendors.json` - Vendor database for MAC address lookups
   - `config/security_config.json` - Security configuration for access control

5. **Data Directories**:
   - `logs/` - Directory for log files
   - `output/` - Directory for scan results

## Installation

### Prerequisites

- Python 3.7 or higher
- Nmap (For full functionality)
- Admin/root privileges for some features

### Required Python Packages

```bash
pip install python-nmap scapy netifaces mac-vendor-lookup zeroconf colorama
```

## Usage

### Basic Scan

```bash
python network_monitor.py
```

### Continuous Monitoring

```bash
python network_monitor.py --monitor --interval 60
```

### Threat-Focused Scan

```bash
python network_monitor.py --threat-scan
```

### Vulnerability Assessment

```bash
python network_monitor.py --vuln-scan
```

### Comprehensive Full Scan

```bash
python network_monitor.py --full-scan
```

This will run a complete scan that combines all 8 detection features:
1. Device discovery
2. DHCP server detection
3. ARP spoofing detection
4. DNS spoofing detection
5. Device fingerprinting
6. Port scanning detection
7. Vulnerability scanning
8. Threat analysis

The full scan is the most thorough option but will take longer to complete.

### Specify Network Range

```bash
python network_monitor.py --network 192.168.1.0/24
```

### DHCP Server Detection

```bash
python network_monitor.py --dhcp-detect
```

### Whitelist Management

```bash
# Add IP address to whitelist
python network_monitor.py --add-to-whitelist 192.168.1.100

# Add MAC address to whitelist
python network_monitor.py --add-to-whitelist 00:11:22:33:44:55

# Show whitelist
python network_monitor.py --show-whitelist
```

### Security Configuration

```bash
# Set up security configuration (restrict access to authorized machines)
python network_monitor.py --config-setup
```

This will prompt you to enter:
- An authorized IP address (defaults to current IP)
- An authorized MAC address (defaults to current MAC)
- Whether to require an access token
- The access token (if required)
- An authorized port (optional)

After configuration, the tool will only run on the authorized machine.

To run the tool on a specific port (when port restriction is enabled):
```bash
python network_monitor.py -p 8080 --quick-scan
```

## File Descriptions

### network_monitor.py

Main entry point that provides a command-line interface with various options for different scanning modes. This file has the `NetworkMonitorCLI` class that handles command-line arguments, executes scans, and displays results in the terminal.

### run_monitor.py

A simplified script focused on running scans and displaying results without the full command-line interface. Useful for integration with other tools.

### core/scanner.py

Handles network scanning using Python-nmap. Discovers hosts, determines open ports, and gathers host information.

### core/detector.py

Implements threat detection algorithms including:
- DHCP spoofing detection
- ARP poisoning detection
- Port scanning detection
- Unauthorized device detection
- Vulnerability assessment

### core/fingerprint.py

Provides device identification and OS detection using various methods:
- MAC address vendor lookup
- TTL-based OS detection
- Service fingerprinting
- mDNS discovery (on macOS)
- NetBIOS (on Windows)

### core/models.py

Data structures for representing devices, ports, threats, and scan results.

### utils/network.py

Utility functions for network operations:
- Getting local IP and MAC addresses
- Determining network range in CIDR notation
- Finding the default gateway
- ARP operations

### utils/helpers.py

Helper functions for data handling:
- Saving and loading scan results
- Managing whitelists
- Analyzing ports for security issues

### config/settings.py

Configuration settings and constants, including:
- Default network range
- Scan intervals
- Detection thresholds
- Platform-specific settings

### config/vendors.json

Database of MAC address prefixes and corresponding manufacturer names.

### config/security_config.json

Security configuration file that restricts tool usage to authorized machines only. Contains:
- Authorized IP address
- Authorized MAC address
- Access token requirement flag
- Access token (if required)
- Authorized port (optional)

## Troubleshooting

- **Permission issues**: Most scanning functions require admin/root privileges. Run with sudo/administrator privileges.
- **Missing nmap**: Ensure nmap is installed on your system.
- **Slow scans**: Adjust scan intensity in settings.py.
- **False positives**: Use the whitelist to exclude authorized devices.
- **Access denied errors**: If you see "ACCESS DENIED" messages, run with `--config-setup` to authorize your machine.

## Platform-Specific Features

- **Linux**: p0f passive fingerprinting (if available)
- **Windows**: NetBIOS name resolution
- **macOS**: mDNS service discovery

## Security Notice

This tool is designed for legitimate network monitoring and security assessment. Please use responsibly and only on networks you own or have permission to scan.

## Meet the Team

<div align="center">
  <table>
    <tr>
      <td align="center">
        <img src="https://github.com/Abdouyami.png" width="100px;" alt="BELHAMICI ABDERRAHMANE" style="border-radius:50%"/><br />
        <b>BELHAMICI ABDERRAHMANE</b><br />
        <div>
          <a href="https://github.com/Abdouyami"><img src="https://img.shields.io/badge/GitHub-%23181717.svg?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>
          <a href="https://www.linkedin.com/in/abderrahmane-belhamici-6a8628288/"><img src="https://img.shields.io/badge/LinkedIn-%230A66C2.svg?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
          <a href="mailto:belhamiciabderrahmane@gmail.com"><img src="https://img.shields.io/badge/Email-%23EA4335.svg?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/></a>
        </div>
        <p><i>Network Security Specialist/AI Engineer</i></p>
      </td>
      <td align="center">
        <img src="https://github.com/Madjid01.png" width="100px;" alt="BOUKHALFA LYES" style="border-radius:50%"/><br />
        <b>BOUKHALFA LYES</b><br />
        <div>
          <a href="https://github.com/Madjid01"><img src="https://img.shields.io/badge/GitHub-%23181717.svg?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>
          <a href="https://www.linkedin.com/in/lyes-boukhalfa-642780340/"><img src="https://img.shields.io/badge/LinkedIn-%230A66C2.svg?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
          <a href="mailto:lyesboukhalfa18@gmail.com"><img src="https://img.shields.io/badge/Email-%23EA4335.svg?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/></a>
        </div>
        <p><i>Network Security Specialist/Software Engineer</i></p>
      </td>
    </tr>
  </table>
</div>

<div align="center">
  <p><b>🔒 Network Monitoring System Creators 🔒</b></p>
  <p><i>Passionate about network security and technology innovation</i></p>
</div>