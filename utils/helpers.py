#!/usr/bin/env python3
"""Helper functions for the network monitoring system"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)

def save_results(results: Dict[str, Any], output_dir: str, prefix: str = "network_scan") -> str:
    """
    Save scan results to a timestamped JSON file
    
    Args:
        results: Results dictionary to save
        output_dir: Directory to save the file in
        prefix: Prefix for the filename (default: "network_scan")
        
    Returns:
        Path to the saved file
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Save results to file
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Saved scan results to {filepath}")
    return filepath

def load_whitelist(output_dir: str) -> Dict[str, List]:
    """
    Load whitelist from file
    
    Args:
        output_dir: Directory containing the whitelist file
        
    Returns:
        Whitelist dictionary
    """
    whitelist_path = os.path.join(output_dir, 'whitelist.json')
    
    try:
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
    
    # Default empty whitelist
    return {
        'ip': [],
        'mac': []
    }

def save_whitelist(whitelist: Dict[str, List], output_dir: str):
    """
    Save whitelist to file
    
    Args:
        whitelist: Whitelist dictionary
        output_dir: Directory to save the file in
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    whitelist_path = os.path.join(output_dir, 'whitelist.json')
    
    try:
        with open(whitelist_path, 'w') as f:
            json.dump(whitelist, f, indent=2)
        logger.info(f"Saved whitelist to {whitelist_path}")
    except Exception as e:
        logger.error(f"Error saving whitelist: {e}")

def analyze_vulnerability_severity(ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze port scan results to determine vulnerability severity
    
    Args:
        ports: List of open ports with service information
        
    Returns:
        Dictionary with vulnerability assessment
    """
    if not ports:
        return {
            'risk_score': 0,
            'risk_level': 'None',
            'vulnerabilities': []
        }
    
    # Define high, medium, and low risk ports
    high_risk_ports = {21, 22, 23, 1433, 2375, 2376, 2379, 3306, 5000, 5432, 5900, 6379, 8080, 9200, 27017}
    medium_risk_ports = {25, 110, 143, 389, 445, 3389, 3478, 5353, 5672, 5984, 6380, 8443, 9000, 9090, 27018}
    
    # Check for risky ports
    vulnerabilities = []
    risk_score = 0
    
    for port_info in ports:
        port = port_info.get('port')
        service = port_info.get('service', 'unknown')
        
        if port in high_risk_ports:
            risk_score += 10
            vulnerabilities.append({
                'port': port,
                'service': service,
                'severity': 'High',
                'description': f"High-risk port {port} ({service}) is open"
            })
        elif port in medium_risk_ports:
            risk_score += 5
            vulnerabilities.append({
                'port': port,
                'service': service,
                'severity': 'Medium',
                'description': f"Medium-risk port {port} ({service}) is open"
            })
    
    # Add minor risk score for other open ports
    other_ports = [p.get('port') for p in ports 
                  if p.get('port') not in high_risk_ports and p.get('port') not in medium_risk_ports]
    risk_score += len(other_ports)
    
    # Determine overall risk level
    if risk_score >= 20:
        risk_level = 'High'
    elif risk_score >= 10:
        risk_level = 'Medium'
    elif risk_score > 0:
        risk_level = 'Low'
    else:
        risk_level = 'None'
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'vulnerabilities': vulnerabilities
    }

def get_file_list(directory: str, prefix: str = "", suffix: str = "", max_files: int = None) -> List[str]:
    """
    Get a list of files from a directory with optional filtering and sorting
    
    Args:
        directory: Directory to search
        prefix: Filter files starting with this prefix
        suffix: Filter files ending with this suffix
        max_files: Maximum number of files to return (most recent first)
        
    Returns:
        List of filenames (not full paths)
    """
    try:
        # Get a list of all files in the directory
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        
        # Apply filters
        if prefix:
            files = [f for f in files if f.startswith(prefix)]
        if suffix:
            files = [f for f in files if f.endswith(suffix)]
            
        # Sort by modification time (most recent first)
        files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        
        # Limit number of files
        if max_files is not None:
            files = files[:max_files]
            
        return files
    except Exception as e:
        logger.error(f"Error getting file list: {e}")
        return []