import os
import sys
import subprocess
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define required packages
REQUIRED_PACKAGES = [
    'python-nmap',
    'scapy',
    'netifaces',
    'mac-vendor-lookup',
    'zeroconf',
    'colorama',
    'trafilatura'
]

# Optional packages based on platform
LINUX_PACKAGES = ['python-libnmap']
WINDOWS_PACKAGES = ['pywin32', 'win32-security']
MACOS_PACKAGES = ['pyobjc-framework-SystemConfiguration']

def check_python_version():
    """Check if Python version is sufficient"""
    required_version = (3, 7)
    current_version = sys.version_info
    
    if current_version < required_version:
        logger.error(f"Python {required_version[0]}.{required_version[1]} or higher is required!")
        logger.error(f"Current version: {current_version[0]}.{current_version[1]}")
        return False
    
    logger.info(f"Python version check passed: {current_version[0]}.{current_version[1]}")
    return True

def install_requirements():
    """Install required Python packages"""
    try:
        import pip
        
        # Install core requirements
        logger.info("Installing required packages...")
        for package in REQUIRED_PACKAGES:
            logger.info(f"Installing {package}...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to install {package}: {result.stderr}")
            else:
                logger.info(f"Successfully installed {package}")
        
        # Install platform-specific packages
        if sys.platform.startswith('linux'):
            logger.info("Installing Linux-specific packages...")
            for package in LINUX_PACKAGES:
                subprocess.run([sys.executable, "-m", "pip", "install", package])
        elif sys.platform.startswith('win'):
            logger.info("Installing Windows-specific packages...")
            for package in WINDOWS_PACKAGES:
                subprocess.run([sys.executable, "-m", "pip", "install", package])
        elif sys.platform.startswith('darwin'):
            logger.info("Installing macOS-specific packages...")
            for package in MACOS_PACKAGES:
                subprocess.run([sys.executable, "-m", "pip", "install", package])
        
        logger.info("Package installation completed")
        return True
    except Exception as e:
        logger.error(f"Failed to install requirements: {str(e)}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'scan_results']
    
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                logger.info(f"Created directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {str(e)}")

def check_nmap_installation():
    """Check if nmap is installed"""
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"Nmap is installed: {result.stdout.splitlines()[0]}")
            return True
        else:
            logger.warning("Nmap command failed. Make sure Nmap is installed.")
            return False
    except FileNotFoundError:
        logger.warning("Nmap is not installed. Please install Nmap for full functionality.")
        return False

def print_instructions():
    """Print instructions for using the network monitor"""
    print("\n" + "=" * 70)
    print("NETWORK MONITOR - SETUP COMPLETE")
    print("=" * 70)
    print("\nTo use the network monitor, run the following command:")
    print("  python network_monitor.py")
    print("\nFor more options, run:")
    print("  python network_monitor.py --help")
    print("\nFor continuous monitoring:")
    print("  python network_monitor.py --monitor")
    print("\nFor a focused threat scan:")
    print("  python network_monitor.py --threat-scan")
    print("\nFor vulnerability assessment:")
    print("  python network_monitor.py --vuln-scan")
    print("\nFor comprehensive full scan (combines all 8 detection features):")
    print("  python network_monitor.py --full-scan")
    print("\nNote: Some features may require root/administrator privileges.")
    print("=" * 70)

def main():
    """Main setup function"""
    logger.info("Starting network monitor setup")
    
    # Check python version
    if not check_python_version():
        return 1
    
    # Create necessary directories
    create_directories()
    
    # Install requirements
    if not install_requirements():
        logger.warning("Some packages may not have been installed correctly")
    
    # Check nmap installation
    check_nmap_installation()
    
    # Print instructions
    print_instructions()
    
    logger.info("Setup completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())