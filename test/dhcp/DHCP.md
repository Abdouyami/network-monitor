# DHCP Attack Simulation

A powerful tool for simulating DHCP attacks and testing network security defenses.

## Overview

This Python script creates a rogue DHCP server on your network that can be used to test DHCP detection systems, understand DHCP spoofing techniques, and evaluate network security posture. The tool offers both standard and enhanced (aggressive) modes for different testing scenarios.

## Features

- Simulates a rogue DHCP server on the network
- Responds to legitimate DHCP requests from clients
- Proactively broadcasts DHCP offers to establish presence
- Configurable IP range, gateway, and DNS settings
- Aggressive mode for enhanced visibility and detection testing
- Multi-threaded operation for simultaneous attack vectors
- Detailed logging of all DHCP activities

## Requirements

- Python 3.6+
- Scapy library (`pip install scapy`)
- Root/Administrator privileges (required for raw socket operations)
- Compatible network interface (Ethernet or Wi-Fi)

## Installation

1. Clone this repository or download the script
2. Install the required dependencies:
   ```bash
   pip install scapy
   ```

## Usage

### Basic Usage

```bash
sudo python3 dhcp_attack_simulation.py
```

### Advanced Options

```bash
sudo python3 dhcp_attack_simulation.py -i eth0 -rp 192.168.100.99 -p 192.168.10.100 -g 192.168.10.1 -d 8.8.8.8 -t 120
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--interface` | Network interface to use (default: system default) |
| `-p`, `--ip` | Base IP address to offer to clients (default: 192.168.100.100) |
| `-g`, `--gateway` | Gateway IP to offer to clients (default: attacker's IP) |
| `-rp`, `--rogue-ip` | IP address to use for the rogue server (default: 192.168.100.89) |
| `-d`, `--dns` | DNS server to offer to clients (default: 8.8.8.8) |
| `-t`, `--time` | Duration to run the attack in seconds (default: 60) |
| `--normal` | Run in normal mode instead of aggressive mode |

## Enhanced Version

The enhanced version (`enhanced_dhcp_attack.py`) provides more aggressive attack techniques:

```bash
sudo python3 enhanced_dhcp_attack.py -i eth0 -t 120
```

This version:
- Uses multiple threads for different attack vectors
- Continuously broadcasts DHCP offers
- Sends targeted offers to previously seen clients
- Creates a more persistent presence on the network

## How It Works

The script uses Scapy to create and send custom DHCP packets:

1. **Discovery Phase**: The script can send DHCP discovery packets to trigger network responses
2. **Offer Phase**: When a client (real or simulated) sends a DHCP discovery, the rogue server responds with an offer
3. **Request/ACK Phase**: The script can also respond to DHCP requests with acknowledgments
4. **Broadcast Phase**: In aggressive mode, the script periodically sends unsolicited offers

## Security Notice

This tool is designed for educational purposes, testing network defenses, and security research. Usage on networks without proper authorization is illegal and unethical. Always obtain written permission before running this tool on any network.

## Detecting Rogue DHCP Servers

This tool can help network administrators test their DHCP security by:

- Validating that DHCP snooping is properly configured on switches
- Testing rogue DHCP server detection systems
- Training security teams to identify DHCP-based attacks
- Demonstrating the potential impact of DHCP spoofing attacks

## Troubleshooting

### Common Issues

1. **"Operation not permitted" error**: Ensure you're running the script with root/administrator privileges
2. **No packets sent/received**: Check that the specified interface is correct and active
3. **Firewall blocking**: Confirm that your firewall isn't blocking DHCP traffic
4. **No detection**: If your detection system isn't finding the rogue server, try the enhanced aggressive mode

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.